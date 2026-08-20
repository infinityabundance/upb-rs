//! mini-table-inspect differential court.
//!
//! Builds a mini table from a mini descriptor string with BOTH the pinned
//! upstream `upb_MiniTable_Build` (oracle op `mini_table_inspect`) and the
//! Rust model (`upb-rs-mini-table`), and compares the normalized rendering
//! (§11): message size, field count, dense_below, ext mode, required count,
//! and every raw field (number, type, mode, offset, presence, submsg_ofs)
//! plus the derived oneof grouping. Error cases compare the upstream error
//! message exactly (pinned-version scope).

use std::fs;
use std::path::{Path, PathBuf};

use upb_rs_casefile::{CaseMetadata, CaseResult, CourtSummary, ResidualRecord};
use upb_rs_mini_table::decode::build_mini_table;
use upb_rs_mini_table::inspect::inspect as inspect_table;
use upb_rs_oracle::client::OracleClient;
use upb_rs_oracle::protocol::ResponseStatus;

const COURT: &str = "mini-table-inspect-v1";
const UPSTREAM_SHA: &str = "2de70d710510ea7c5ad7ec0c72bfed7f411c7b60";

#[derive(Debug, Clone, serde::Deserialize)]
struct CorpusCase {
    op: String,
    hex: String,
    kind: String,
    seed: u64,
}

fn hex_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).expect("hex hi");
        let lo = (bytes[i + 1] as char).to_digit(16).expect("hex lo");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

/// DUT outcome.
#[derive(Debug, Clone)]
enum DutOutcome {
    Ok(serde_json::Value),
    Error { msg: String },
}

fn dut_eval(descriptor: &[u8]) -> DutOutcome {
    match build_mini_table(descriptor) {
        Ok((mt, version)) => DutOutcome::Ok(inspect_table(&mt, version)),
        Err(e) => DutOutcome::Error { msg: e.to_string() },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut corpus_dir = PathBuf::from("corpus/generated/wire-primitives-v1");
    let mut oracle_bin = upb_rs_oracle::client::default_oracle_path();
    let mut receipts_dir = PathBuf::from("receipts");
    let mut fail_on_residuals = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                i += 1;
                corpus_dir = PathBuf::from(&args[i]);
            }
            "--oracle" => {
                i += 1;
                oracle_bin = args[i].clone();
            }
            "--receipts" => {
                i += 1;
                receipts_dir = PathBuf::from(&args[i]);
            }
            "--fail-on-residuals" => fail_on_residuals = true,
            other => panic!("unknown argument: {other}"),
        }
        i += 1;
    }

    let cases_path = corpus_dir.join("cases.jsonl");
    let corpus_raw = fs::read_to_string(&cases_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", cases_path.display()));
    let all_cases: Vec<CorpusCase> = corpus_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("parse corpus line"))
        .collect();
    let cases: Vec<&CorpusCase> = all_cases
        .iter()
        .filter(|c| c.op == "mini_table_inspect")
        .collect();
    println!(
        "loaded {} mini_table_inspect cases from {}",
        cases.len(),
        cases_path.display()
    );

    let mut oracle =
        OracleClient::spawn(&oracle_bin).unwrap_or_else(|e| panic!("cannot spawn oracle: {e}"));
    oracle.ping().expect("oracle ping failed");

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    let mut equal_count: u64 = 0;

    for (index, c) in cases.iter().enumerate() {
        let descriptor = hex_decode(&c.hex);

        // Oracle: pinned upb_MiniTable_Build.
        let resp = oracle
            .mini_table_inspect(&descriptor)
            .unwrap_or_else(|e| panic!("oracle failure at case {index} ({}): {e}", c.kind));

        // DUT.
        let dut = dut_eval(&descriptor);

        let equal = match (&resp.status, &dut) {
            (ResponseStatus::Ok, DutOutcome::Ok(mt)) => resp.mini_table.as_ref() == Some(mt),
            (ResponseStatus::Error, DutOutcome::Error { msg }) => {
                resp.msg.as_deref() == Some(msg.as_str())
            }
            _ => false,
        };

        if equal {
            equal_count += 1;
        } else {
            let oracle_json = serde_json::to_value(&resp).expect("serialize oracle response");
            let dut_json = match &dut {
                DutOutcome::Ok(mt) => serde_json::json!({
                    "status": "ok", "mini_table": mt, "v": 1, "id": index as u64
                }),
                DutOutcome::Error { msg } => serde_json::json!({
                    "status": "error", "code": "build_failed", "msg": msg,
                    "v": 1, "id": index as u64
                }),
            };
            let o_msg = resp.msg.clone().unwrap_or_default();
            let d_msg = match &dut {
                DutOutcome::Ok(_) => String::new(),
                DutOutcome::Error { msg } => msg.clone(),
            };
            residuals.push(ResidualRecord {
                metadata: CaseMetadata {
                    id: format!("mti-{:06}", index),
                    court: COURT.to_string(),
                    oracle: UPSTREAM_SHA.to_string(),
                    op: c.op.clone(),
                    input_hex: c.hex.clone(),
                    tag: None,
                    seed: c.seed,
                    classification: None,
                    date: timestamp(),
                    notes: format!("kind={}", c.kind),
                },
                result: CaseResult {
                    oracle: oracle_json,
                    dut: dut_json,
                    equal: false,
                },
                oracle_status: format!("{:?}", resp.status).to_lowercase(),
                dut_status: match &dut {
                    DutOutcome::Ok(_) => "ok".to_string(),
                    DutOutcome::Error { .. } => "error".to_string(),
                },
                oracle_value: Some(o_msg),
                dut_value: Some(d_msg),
            });
        }
    }

    let run_id = format!("{COURT}-{}", timestamp());
    let out_dir = receipts_dir.join(&run_id);
    fs::create_dir_all(out_dir.join("casefiles")).expect("create receipt dir");

    let summary = CourtSummary {
        court: COURT.to_string(),
        oracle: UPSTREAM_SHA.to_string(),
        total: cases.len() as u64,
        equal: equal_count,
        residuals: residuals.len() as u64,
        corpus_version: "1".to_string(),
        rust_revision: rust_revision(),
        date: timestamp(),
    };
    fs::write(
        out_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .expect("write summary");
    fs::write(
        out_dir.join("residuals.json"),
        serde_json::to_string_pretty(&residuals).unwrap(),
    )
    .expect("write residuals");

    let manifest = serde_json::json!({
        "court": COURT,
        "run_id": run_id,
        "upstream": UPSTREAM_SHA,
        "oracle_binary": oracle_bin,
        "corpus": cases_path.display().to_string(),
        "cases": cases.len(),
        "summary": serde_json::to_value(&summary).unwrap(),
    });
    fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");

    for r in &residuals {
        let dir = out_dir.join("casefiles").join(&r.metadata.id);
        fs::create_dir_all(&dir).expect("create casefile dir");
        fs::write(
            dir.join("metadata.json"),
            serde_json::to_string_pretty(&r.metadata).unwrap(),
        )
        .expect("write casefile metadata");
        fs::write(
            dir.join("oracle.json"),
            serde_json::to_string_pretty(&r.result.oracle).unwrap(),
        )
        .expect("write casefile oracle");
        fs::write(
            dir.join("rust.json"),
            serde_json::to_string_pretty(&r.result.dut).unwrap(),
        )
        .expect("write casefile rust");
        fs::write(
            dir.join("residual.json"),
            serde_json::to_string_pretty(r).unwrap(),
        )
        .expect("write casefile residual");
        fs::write(
            dir.join("reproduce.sh"),
            format!(
                "#!/bin/sh\n# Reproduce residual {id} (kind {kind})\n#\n#   echo '{{\"v\":1,\"id\":1,\"op\":\"mini_table_inspect\",\"hex\":\"{hex}\"}}' | tools/oracle/build/oracle\n",
                id = r.metadata.id,
                kind = r.metadata.notes,
                hex = r.metadata.input_hex,
            ),
        )
        .expect("write casefile reproduce.sh");
    }

    println!(
        "court complete: {}/{} equal, {} residuals -> {}",
        equal_count,
        cases.len(),
        residuals.len(),
        out_dir.display()
    );
    for r in &residuals {
        println!(
            "  residual {} kind={} oracle={} dut={}",
            r.metadata.id, r.metadata.notes, r.oracle_status, r.dut_status
        );
    }

    if !residuals.is_empty() && fail_on_residuals {
        std::process::exit(2);
    }
}

fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();
    let days = secs / 86400;
    let (y, m, d) = civil_from_days(days as i64);
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}{m:02}{d:02}-{h:02}{mi:02}{s:02}")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as i64;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as i64;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn rust_revision() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in [
        "crates",
        "tools/corpus/src",
        "courts/mini-table-inspect/src",
    ] {
        let d = Path::new(dir);
        if let Ok(entries) = fs::read_dir(d) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension()
                    .map(|x| x == "rs" || x == "toml")
                    .unwrap_or(false)
                {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    for f in files {
        if let Ok(content) = fs::read(&f) {
            f.hash(&mut h);
            content.hash(&mut h);
        }
    }
    format!("{:016x}", h.finish())
}
