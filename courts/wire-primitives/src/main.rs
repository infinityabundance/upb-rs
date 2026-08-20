//! wire-primitives differential court.
//!
//! Runs the generated corpus against BOTH the pinned upstream oracle
//! (`tools/oracle/build/oracle`, protocol v1) and the upb-rs DUT
//! (`upb-rs-wire`), compares the full observable outcome
//! (status / value / consumed / bounded), and writes an evidence receipt:
//!
//! ```text
//! receipts/<run-id>/
//!     manifest.json      environment + inputs
//!     summary.json       court summary
//!     residuals.json     all residual records
//!     casefiles/<id>/    permanent casefiles for each residual
//! ```
//!
//! Exit code: 0 = no residuals; 2 = residuals present (with
//! `--fail-on-residuals`); 1 = infrastructure error.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use upb_rs_casefile::{CaseMetadata, CaseResult, CourtSummary, ResidualRecord};
use upb_rs_oracle::client::{OracleClient, OracleError};
use upb_rs_oracle::protocol::PrimitiveOp;
use upb_rs_wire::reader;
use upb_rs_wire::stream::EpsCopyStream;

const COURT: &str = "wire-primitives-v1";
const UPSTREAM_SHA: &str = "2de70d710510ea7c5ad7ec0c72bfed7f411c7b60";
const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, serde::Deserialize)]
struct CorpusCase {
    op: String,
    hex: String,
    tag: Option<u64>,
    kind: String,
    seed: u64,
}

/// DUT outcome, mirroring the oracle response shape exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DutOutcome {
    Eof,
    Error,
    Ok {
        value: Option<u64>,
        consumed: usize,
        bounded: bool,
    },
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

/// Evaluates one op on the DUT, mirroring the oracle's exact sequence:
/// IsDone (eof) -> read op -> IsDone at the final position for boundedness,
/// with `consumed` computed before the boundedness IsDone mutates the stream.
fn dut_eval(op: &str, tag: Option<u64>, input: &[u8]) -> DutOutcome {
    let mut stream = EpsCopyStream::init(input);
    let mut ptr = 0usize;
    if stream.is_done(&mut ptr) {
        return DutOutcome::Eof;
    }
    let result = match op {
        "read_varint" => reader::read_varint(&stream, ptr).map(|o| (Some(o.value), o.consumed)),
        "read_tag" => reader::read_tag(&stream, ptr).map(|o| (Some(o.value), o.consumed)),
        "read_size" => reader::read_size(&stream, ptr).map(|o| (Some(o.value), o.consumed)),
        "read_fixed32" => reader::read_fixed32(&stream, ptr).map(|o| (Some(o.value), o.consumed)),
        "read_fixed64" => reader::read_fixed64(&stream, ptr).map(|o| (Some(o.value), o.consumed)),
        "skip_varint" => reader::skip_varint(&stream, ptr).map(|p| (None, p)),
        "skip_value" => reader::skip_value(
            &mut stream,
            ptr,
            tag.unwrap_or(0) as u32,
            reader::DEFAULT_DEPTH_LIMIT,
        )
        .map(|p| (None, p)),
        "skip_group" => reader::skip_group_inner(
            &mut stream,
            ptr,
            tag.unwrap_or(0) as u32,
            reader::DEFAULT_DEPTH_LIMIT,
        )
        .map(|p| (None, p)),
        other => panic!("unknown op: {other}"),
    };
    match result {
        Err(_) => DutOutcome::Error,
        Ok((value, end)) => {
            // consumed in input coordinates, computed BEFORE the boundedness
            // IsDone (which may relocate the window via the patch fallback).
            let consumed = stream.absolute(end);
            let mut q = end;
            let done = stream.is_done(&mut q);
            let bounded = if done { !stream.is_error() } else { true };
            DutOutcome::Ok {
                value,
                consumed,
                bounded,
            }
        }
    }
}

/// Runs one corpus case against the oracle and the DUT, returning a
/// normalized comparison pair.
fn run_case(
    oracle: &mut OracleClient,
    index: usize,
    c: &CorpusCase,
) -> Result<(serde_json::Value, serde_json::Value, bool), OracleError> {
    let input = hex_decode(&c.hex);

    // Oracle.
    let resp = match c.op.as_str() {
        "read_varint" => oracle.primitive(PrimitiveOp::ReadVarint, &input)?,
        "read_tag" => oracle.primitive(PrimitiveOp::ReadTag, &input)?,
        "read_size" => oracle.primitive(PrimitiveOp::ReadSize, &input)?,
        "read_fixed32" => oracle.primitive(PrimitiveOp::ReadFixed32, &input)?,
        "read_fixed64" => oracle.primitive(PrimitiveOp::ReadFixed64, &input)?,
        "skip_varint" => oracle.primitive(PrimitiveOp::SkipVarint, &input)?,
        "skip_value" => oracle.skip_value(c.tag.unwrap_or(0) as u32, &input)?,
        "skip_group" => oracle.skip_group(c.tag.unwrap_or(0) as u32, &input)?,
        other => panic!("unknown op: {other}"),
    };
    let oracle_json = serde_json::to_value(&resp).expect("serialize oracle response");

    // DUT.
    let dut = dut_eval(&c.op, c.tag, &input);
    let dut_json = match dut {
        DutOutcome::Eof => {
            serde_json::json!({"status": "eof", "v": PROTOCOL_VERSION, "id": index as u64})
        }
        DutOutcome::Error => serde_json::json!({
            "status": "error", "code": "malformed", "consumed": 0,
            "v": PROTOCOL_VERSION, "id": index as u64
        }),
        DutOutcome::Ok {
            value,
            consumed,
            bounded,
        } => serde_json::json!({
            "status": "ok",
            "value": value.map(|v| v.to_string()),
            "consumed": consumed,
            "bounded": bounded,
            "v": PROTOCOL_VERSION,
            "id": index as u64
        }),
    };

    // Normalize the oracle response to the same shape for comparison.
    let o_status = resp.status;
    let o_value = resp.value_u64();
    let o_consumed = resp.consumed.map(|v| v as usize);
    let o_bounded = resp.bounded;

    let equal = match (o_status, &dut) {
        (upb_rs_oracle::protocol::ResponseStatus::Eof, DutOutcome::Eof) => true,
        (upb_rs_oracle::protocol::ResponseStatus::Error, DutOutcome::Error) => true,
        (
            upb_rs_oracle::protocol::ResponseStatus::Ok,
            DutOutcome::Ok {
                value,
                consumed,
                bounded,
            },
        ) => o_value == *value && o_consumed == Some(*consumed) && o_bounded == Some(*bounded),
        _ => false,
    };
    Ok((oracle_json, dut_json, equal))
}

/// Computes a deterministic content hash over the production crates to
/// identify the Rust source state (used when the tree is not committed).
fn rust_revision() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in ["crates", "tools/corpus/src", "courts/wire-primitives/src"] {
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

    // Load corpus.
    let cases_path = corpus_dir.join("cases.jsonl");
    let corpus_raw = fs::read_to_string(&cases_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", cases_path.display()));
    let all_cases: Vec<CorpusCase> = corpus_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("parse corpus line"))
        .collect();
    // This court runs only its own primitive ops.
    let cases: Vec<&CorpusCase> = all_cases
        .iter()
        .filter(|c| {
            matches!(
                c.op.as_str(),
                "read_varint"
                    | "read_tag"
                    | "read_size"
                    | "read_fixed32"
                    | "read_fixed64"
                    | "skip_varint"
                    | "skip_value"
                    | "skip_group"
            )
        })
        .collect();
    println!("loaded {} cases from {}", cases.len(), cases_path.display());

    // Spawn oracle and self-test the protocol.
    let mut oracle =
        OracleClient::spawn(&oracle_bin).unwrap_or_else(|e| panic!("cannot spawn oracle: {e}"));
    oracle.ping().expect("oracle ping failed");

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    let mut equal_count: u64 = 0;

    for (index, c) in cases.iter().enumerate() {
        let (oracle_json, dut_json, equal) = run_case(&mut oracle, index, c)
            .unwrap_or_else(|e| panic!("oracle failure at case {index} ({}): {e}", c.kind));
        if equal {
            equal_count += 1;
        } else {
            let metadata = CaseMetadata {
                id: format!("wp-{:06}", index),
                court: COURT.to_string(),
                oracle: UPSTREAM_SHA.to_string(),
                op: c.op.clone(),
                input_hex: c.hex.clone(),
                tag: c.tag,
                seed: c.seed,
                classification: None,
                date: chrono_like_timestamp(),
                notes: format!("kind={}", c.kind),
            };
            let o_status = oracle_json["status"].as_str().unwrap_or("?").to_string();
            let d_status = dut_json["status"].as_str().unwrap_or("?").to_string();
            let o_value = oracle_json["value"].as_str().map(|s| s.to_string());
            let d_value = dut_json["value"].as_str().map(|s| s.to_string());
            residuals.push(ResidualRecord {
                metadata,
                result: CaseResult {
                    oracle: oracle_json,
                    dut: dut_json,
                    equal: false,
                },
                oracle_status: o_status,
                dut_status: d_status,
                oracle_value: o_value,
                dut_value: d_value,
            });
        }
    }

    // Write the receipt.
    let run_id = format!("{COURT}-{}", chrono_like_timestamp());
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
        date: chrono_like_timestamp(),
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

    // Environment manifest.
    let mut env_map: BTreeMap<String, String> = BTreeMap::new();
    env_map.insert("uname".into(), uname().unwrap_or_default());
    env_map.insert("rustc".into(), rustc_version().unwrap_or_default());
    env_map.insert("upstream".into(), UPSTREAM_SHA.into());
    env_map.insert("protocol_version".into(), PROTOCOL_VERSION.to_string());
    env_map.insert("oracle_binary".into(), oracle_bin.clone());
    env_map.insert("corpus".into(), cases_path.display().to_string());
    env_map.insert("cases".into(), cases.len().to_string());
    env_map.insert("seed".into(), "0x7570627273".into());
    let manifest = serde_json::json!({
        "court": COURT,
        "run_id": run_id,
        "environment": env_map,
        "summary": serde_json::to_value(&summary).unwrap(),
    });
    fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");

    // Permanent casefiles for every residual.
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
                "#!/bin/sh\n# Reproduce residual {id} (kind {kind})\n#\n# Input: {hex}\n# Op: {op}{tag}\n#\n# Run the full court:\n#   cargo run --manifest-path courts/wire-primitives/Cargo.toml -- --fail-on-residuals\n# Or probe the oracle directly:\n#   echo '{{\"v\":1,\"id\":1,\"op\":\"{op}\",\"hex\":\"{hex}\"{tag_field}}}' | tools/oracle/build/oracle\n",
                id = r.metadata.id,
                kind = r.metadata.notes,
                hex = r.metadata.input_hex,
                op = r.metadata.op,
                tag = r.metadata.tag.map(|t| format!(" (tag={t})")).unwrap_or_default(),
                tag_field = r.metadata.tag.map(|t| format!(",\"tag\":{t}")).unwrap_or_default(),
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
            "  residual {} op={} kind={} oracle={} dut={}",
            r.metadata.id, r.metadata.op, r.metadata.notes, r.oracle_status, r.dut_status
        );
    }

    if !residuals.is_empty() && fail_on_residuals {
        std::process::exit(2);
    }
}

/// Minimal timestamp (YYYYMMDD-HHMMSS); avoids a chrono dependency.
fn chrono_like_timestamp() -> String {
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
    // Howard Hinnant's civil_from_days algorithm.
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

fn uname() -> Option<String> {
    let out = std::process::Command::new("uname")
        .arg("-a")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn rustc_version() -> Option<String> {
    let out = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
