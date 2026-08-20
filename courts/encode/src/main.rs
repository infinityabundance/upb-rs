//! encode differential court.
//!
//! Runs decode-then-re-encode against BOTH the pinned upstream oracle (op
//! `encode`: real `upb_Decode` + `upb_Encode` under the given options and max
//! depth) and the upb-rs DUT (`upb-rs-wire` `message_known::encode_submsg`).
//!
//! Two case sources:
//! 1. Explicit `encode`-op corpus cases (options carried in the case).
//! 2. Every `decode_submsg` / `decode_known` corpus case, derived with the
//!    four option combinations (0, Deterministic, SkipUnknown, both).
//!
//! Comparison: encode status and, on success, the exact output bytes. For
//! NON-deterministic cases whose bytes differ, a semantic fallback parses
//! both outputs with the sealed DUT decoder and compares the normalized
//! dumps: an equal-dump difference is the permitted map-table iteration
//! order (forensics/NONDETERMINISM.md §map-order), not a residual. The
//! residual record preserves the exact oracle bytes for audit.
//!
//! Build/link failures (oracle codes `minitable_build_failed`,
//! `enum_build_failed`, `link_failed`, `oom`) are classified together with
//! the DUT's `unsupported` refusal, as in the decode-submsg court.

use std::fs;
use std::path::{Path, PathBuf};

use upb_rs_casefile::{CaseMetadata, CaseResult, CourtSummary, ResidualRecord};
use upb_rs_oracle::client::OracleClient;
use upb_rs_oracle::protocol::ResponseStatus;
use upb_rs_wire::message_known::{decode_submsg, encode_submsg, KnownDecodeError};

const COURT: &str = "encode-v1";
const UPSTREAM_SHA: &str = "2de70d710510ea7c5ad7ec0c72bfed7f411c7b60";

const OPT_DETERMINISTIC: u32 = 1;
const OPT_SKIP_UNKNOWN: u32 = 2;

#[derive(Debug, Clone, serde::Deserialize)]
struct CorpusCase {
    op: String,
    hex: String,
    md: Option<String>,
    mds: Option<Vec<String>>,
    links: Option<Vec<Vec<u64>>>,
    depth: Option<u64>,
    options: Option<u64>,
    #[allow(dead_code)] // retained for casefile provenance
    kind: String,
    #[allow(dead_code)] // retained for casefile provenance
    seed: u64,
}

/// A concrete encode request: pool + links + payload + depth + options.
struct EncCase {
    mds: Vec<Vec<u8>>,
    links: Vec<Vec<usize>>,
    input: Vec<u8>,
    depth: u32,
    options: u32,
    kind: String,
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

/// All encode requests: explicit `encode` cases plus every decode case under
/// the four option combinations.
fn collect(cases: &[CorpusCase]) -> Vec<EncCase> {
    let mut out = Vec::new();
    for c in cases {
        match c.op.as_str() {
            "encode" => {
                let mds = c
                    .mds
                    .as_ref()
                    .expect("encode case without mds")
                    .iter()
                    .map(|m| hex_decode(m))
                    .collect();
                let links = c
                    .links
                    .as_ref()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|l| l.iter().map(|&x| x as usize).collect())
                    .collect();
                out.push(EncCase {
                    mds,
                    links,
                    input: hex_decode(&c.hex),
                    depth: c.depth.unwrap_or(0) as u32,
                    options: c.options.unwrap_or(0) as u32,
                    kind: c.kind.clone(),
                });
            }
            "decode_submsg" | "decode_known" => {
                let mds: Vec<Vec<u8>> = match &c.mds {
                    Some(m) => m.iter().map(|m| hex_decode(m)).collect(),
                    // decode_known: a single-table pool, no links.
                    None => vec![hex_decode(c.md.as_ref().expect("decode_known md"))],
                };
                let links: Vec<Vec<usize>> = match &c.links {
                    Some(l) => l
                        .iter()
                        .map(|row| row.iter().map(|&x| x as usize).collect())
                        .collect(),
                    None => vec![vec![]],
                };
                for options in [0u32, OPT_DETERMINISTIC, OPT_SKIP_UNKNOWN, 3] {
                    out.push(EncCase {
                        mds: mds.clone(),
                        links: links.clone(),
                        input: hex_decode(&c.hex),
                        depth: c.depth.unwrap_or(0) as u32,
                        options,
                        kind: format!("{}-opt{options}", c.kind),
                    });
                }
            }
            _ => {}
        }
    }
    out
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
    let cases = collect(&all_cases);
    println!("loaded {} encode requests", cases.len());

    let mut oracle =
        OracleClient::spawn(&oracle_bin).unwrap_or_else(|e| panic!("cannot spawn oracle: {e}"));
    oracle.ping().expect("oracle ping failed");

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    let mut classified_equal: Vec<String> = Vec::new();
    let mut equal_count: u64 = 0;

    for (index, c) in cases.iter().enumerate() {
        let links_u64: Vec<Vec<u64>> = c
            .links
            .iter()
            .map(|l| l.iter().map(|&x| x as u64).collect())
            .collect();
        let resp = oracle
            .encode(&c.mds, &links_u64, &c.input, c.depth, c.options)
            .unwrap_or_else(|e| panic!("oracle failure at case {index} ({}): {e}", c.kind));

        let mds_refs: Vec<&[u8]> = c.mds.iter().map(|m| m.as_slice()).collect();
        let links_refs: Vec<&[usize]> = c.links.iter().map(|l| l.as_slice()).collect();
        let dut = encode_submsg(&mds_refs, &links_refs, &c.input, c.depth, c.options);

        let mut equal = match (&resp.status, &dut) {
            (ResponseStatus::Ok, Ok(bytes)) => resp.hex_out.as_deref() == Some(&hex(bytes)),
            (ResponseStatus::Error, Err(e)) => {
                let oracle_code = resp.code.as_deref().unwrap_or("");
                let dut_code = match e {
                    KnownDecodeError::Malformed => "malformed",
                    KnownDecodeError::BadUtf8 => "bad_utf8",
                    KnownDecodeError::MaxDepthExceeded => "max_depth_exceeded",
                    KnownDecodeError::Unsupported(_) => "unsupported",
                };
                if dut_code == "unsupported" {
                    matches!(
                        oracle_code,
                        "minitable_build_failed" | "enum_build_failed" | "link_failed" | "oom"
                    )
                } else {
                    oracle_code == dut_code
                }
            }
            _ => false,
        };

        // Semantic fallback for permitted non-determinism: non-deterministic
        // encodes whose bytes differ are equal iff both outputs parse to the
        // same normalized message (the difference is the map table iteration
        // order — NONDETERMINISM.md §map-order).
        let mut fallback_used = false;
        if !equal && c.options & OPT_DETERMINISTIC == 0 {
            if let (ResponseStatus::Ok, Ok(ours)) = (&resp.status, &dut) {
                if let Some(oracle_hex) = &resp.hex_out {
                    let oracle_bytes = hex_decode(oracle_hex);
                    if let (Ok(a), Ok(b)) = (
                        decode_submsg(&mds_refs, &links_refs, &oracle_bytes, c.depth),
                        decode_submsg(&mds_refs, &links_refs, ours, c.depth),
                    ) {
                        let ts =
                            upb_rs_wire::message_known::TableSet::from_pool(&mds_refs, &links_refs)
                                .ok();
                        if let Some(ts) = ts {
                            if a.dump(&ts, 0) == b.dump(&ts, 0) {
                                equal = true;
                                fallback_used = true;
                            }
                        }
                    }
                }
            }
        }

        if equal {
            equal_count += 1;
            if fallback_used {
                classified_equal.push(format!(
                    "{index}:{} oracle={} dut={}",
                    c.kind,
                    resp.hex_out.as_deref().unwrap_or(""),
                    hex(&dut.clone().unwrap_or_default()),
                ));
            }
        } else {
            let oracle_json = serde_json::to_value(&resp).expect("serialize oracle response");
            let dut_json = match &dut {
                Ok(bytes) => serde_json::json!({
                    "status": "ok", "hex_out": hex(bytes), "v": 1, "id": index as u64
                }),
                Err(e) => serde_json::json!({
                    "status": "error", "code": e.to_string(), "v": 1, "id": index as u64
                }),
            };
            let o_status = format!("{:?}", resp.status).to_lowercase();
            residuals.push(ResidualRecord {
                metadata: CaseMetadata {
                    id: format!("enc-{:06}", index),
                    court: COURT.to_string(),
                    oracle: UPSTREAM_SHA.to_string(),
                    op: "encode".to_string(),
                    input_hex: hex(&c.input),
                    tag: None,
                    seed: 0,
                    classification: None,
                    date: timestamp(),
                    notes: format!(
                        "kind={}, options={}, depth={}, mds={:?}",
                        c.kind, c.options, c.depth, c.mds
                    ),
                },
                result: CaseResult {
                    oracle: oracle_json,
                    dut: dut_json,
                    equal: false,
                },
                oracle_status: o_status,
                dut_status: match &dut {
                    Ok(_) => "ok".to_string(),
                    Err(e) => e.to_string(),
                },
                oracle_value: resp.hex_out.clone(),
                dut_value: match &dut {
                    Ok(b) => Some(hex(b)),
                    Err(e) => Some(e.to_string()),
                },
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
    fs::write(
        out_dir.join("classified.json"),
        serde_json::to_string_pretty(&classified_equal).unwrap(),
    )
    .expect("write classified");

    let manifest = serde_json::json!({
        "court": COURT,
        "run_id": run_id,
        "upstream": UPSTREAM_SHA,
        "oracle_binary": oracle_bin,
        "corpus": cases_path.display().to_string(),
        "cases": cases.len(),
        "classified_non_deterministic": classified_equal.len(),
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
    }

    println!(
        "court complete: {}/{} equal, {} residuals ({}/{} byte-exact, {} classified map-order) -> {}",
        equal_count,
        cases.len(),
        residuals.len(),
        equal_count - classified_equal.len() as u64,
        cases.len(),
        classified_equal.len(),
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

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
    for dir in ["crates", "tools/corpus/src", "courts/encode/src"] {
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
