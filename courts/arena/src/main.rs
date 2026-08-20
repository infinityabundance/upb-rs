//! arena-v1 differential court.
//!
//! Runs deterministic arena scripts against BOTH the pinned upstream oracle
//! (`tools/oracle/build/oracle`, ops `arena_info` / `arena_trace` /
//! `arena_fuse` — the real `upb_Arena`) and the upb-rs DUT
//! (`upb-rs-core` `arena::ArenaPool`).
//!
//! Each script is a sequence of arena operations (malloc, realloc, shrink,
//! try-extend, message allocation, strdup, cleanup registration) over an
//! arena configuration (initial block, allocator presence, max block size,
//! injected OOM threshold). The observable compared per op: success, the
//! `SpaceAllocated` total, realloc pointer identity, try-extend result,
//! message zeroing, plus the final arena state (space, fused count) and the
//! alloc-cleanup execution order at free.
//!
//! Fused-group cleanup ORDER depends on upstream's lower-address root
//! selection, which is representation-level; the court compares fused
//! cleanup sets (sorted), not order (forensics/NONDETERMINISM.md).
//!
//! The scripts are generated deterministically from a seed; a failure is
//! replayable from one seed. The oracle's `arena_info` constants are read at
//! startup and drive the DUT, so the comparison tracks the oracle build.

use std::fs;
use std::path::{Path, PathBuf};

use upb_rs_casefile::{CaseMetadata, CaseResult, CourtSummary, ResidualRecord};
use upb_rs_core::arena::{ArenaConfig, ArenaPool, ControlledAllocator, RELEASE_CONFIG};
use upb_rs_oracle::client::OracleClient;
use upb_rs_oracle::protocol::{ArenaCfg, ArenaOp};

const COURT: &str = "arena-v1";
const UPSTREAM_SHA: &str = "2de70d710510ea7c5ad7ec0c72bfed7f411c7b60";
const SEED: u64 = 0x0075_7062_6172; // "upbar"

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A deterministic arena case: a trace (one arena) or a fuse (two arenas).
enum ArenaCase {
    Trace {
        name: String,
        cfg: ArenaCfg,
        ops: Vec<ArenaOp>,
        free_at_end: bool,
    },
    Fuse {
        name: String,
        cfg_a: ArenaCfg,
        cfg_b: ArenaCfg,
        ops_a: Vec<ArenaOp>,
        ops_b: Vec<ArenaOp>,
        ops_post: Vec<ArenaOp>,
    },
}

impl ArenaCase {
    fn name(&self) -> &str {
        match self {
            ArenaCase::Trace { name, .. } | ArenaCase::Fuse { name, .. } => name,
        }
    }
}

fn cfg(initial_block: u64, alloc: bool) -> ArenaCfg {
    let mut c = ArenaCfg::new();
    c.initial_block = initial_block;
    c.alloc = alloc;
    c
}

/// Hand-crafted scripts targeting specific behaviors, plus deterministic
/// randomized growth scripts.
fn generate_cases() -> Vec<ArenaCase> {
    let mut cases = Vec::new();

    // Basic growth within and across the first block (336 data + 16 reserve).
    cases.push(ArenaCase::Trace {
        name: "basic".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::malloc(8),
            ArenaOp::malloc(16),
            ArenaOp::malloc(100),
            ArenaOp::malloc(256),
        ],
        free_at_end: false,
    });
    // Exhaust the first block (32 allocs of 8 from offset 80) and grow.
    let mut ops: Vec<ArenaOp> = (0..44).map(|_| ArenaOp::malloc(8)).collect();
    cases.push(ArenaCase::Trace {
        name: "exhaust-first-block".into(),
        cfg: cfg(0, true),
        ops,
        free_at_end: false,
    });
    // One-off block for an allocation larger than any growth size.
    cases.push(ArenaCase::Trace {
        name: "one-off".into(),
        cfg: cfg(0, true),
        ops: vec![ArenaOp::malloc(70000)],
        free_at_end: false,
    });
    // One-off followed by small allocs from the untouched bump region.
    cases.push(ArenaCase::Trace {
        name: "one-off-then-small".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::malloc(70000),
            ArenaOp::malloc(8),
            ArenaOp::malloc(64),
        ],
        free_at_end: false,
    });
    // Realloc/shrink/try-extend: in-place when last, move when not.
    cases.push(ArenaCase::Trace {
        name: "realloc-inplace".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::malloc(16),
            ArenaOp::realloc(0, 32),
            ArenaOp::shrink(1, 8),
            ArenaOp::tryextend(1, 16),
        ],
        free_at_end: false,
    });
    cases.push(ArenaCase::Trace {
        name: "realloc-move".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::malloc(16),
            ArenaOp::malloc(8),
            ArenaOp::realloc(0, 32),
        ],
        free_at_end: false,
    });
    cases.push(ArenaCase::Trace {
        name: "tryextend-nonlast".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::malloc(16),
            ArenaOp::malloc(8),
            ArenaOp::tryextend(0, 32),
            ArenaOp::tryextend(1, 24),
        ],
        free_at_end: false,
    });
    // Message allocations (mini-table sizes) and string copies.
    cases.push(ArenaCase::Trace {
        name: "messages".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::message(16),
            ArenaOp::message(24),
            ArenaOp::message(32),
        ],
        free_at_end: false,
    });
    cases.push(ArenaCase::Trace {
        name: "strdups".into(),
        cfg: cfg(0, true),
        ops: vec![
            ArenaOp::strdup(5, "68656c6c6f"),
            ArenaOp::strdup(6, "776f726c6421"),
        ],
        free_at_end: false,
    });
    // Fixed-size arena: no allocator; the initial block [80, 160) holds 10
    // allocs of 8; the 11th fails.
    ops = (0..11).map(|_| ArenaOp::malloc(8)).collect();
    cases.push(ArenaCase::Trace {
        name: "fixed-size".into(),
        cfg: cfg(160, false),
        ops,
        free_at_end: false,
    });
    // Initial block with an allocator: grows after the block is exhausted.
    ops = (0..20).map(|_| ArenaOp::malloc(8)).collect();
    cases.push(ArenaCase::Trace {
        name: "initial-with-alloc".into(),
        cfg: cfg(160, true),
        ops,
        free_at_end: false,
    });
    // OOM injection: the first block (352 accounting) fits; the second block
    // request fails once the cumulative requested bytes exceed the threshold.
    let mut c = cfg(0, true);
    c.fail_after_bytes = 352;
    ops = (0..40).map(|_| ArenaOp::malloc(8)).collect();
    cases.push(ArenaCase::Trace {
        name: "oom-after-first-block".into(),
        cfg: c,
        ops,
        free_at_end: false,
    });
    // OOM at init: even the first block cannot be allocated.
    let mut c = cfg(0, true);
    c.fail_after_bytes = 100;
    cases.push(ArenaCase::Trace {
        name: "oom-at-init".into(),
        cfg: c,
        ops: vec![ArenaOp::malloc(8)],
        free_at_end: false,
    });
    // No allocator and no initial block: arena creation fails.
    cases.push(ArenaCase::Trace {
        name: "init-fail-no-alloc".into(),
        cfg: cfg(0, false),
        ops: vec![],
        free_at_end: false,
    });
    // Cleanup runs at free; setting it twice keeps only the last.
    cases.push(ArenaCase::Trace {
        name: "cleanup".into(),
        cfg: cfg(0, true),
        ops: vec![ArenaOp::malloc(16), ArenaOp::cleanup(7)],
        free_at_end: true,
    });
    cases.push(ArenaCase::Trace {
        name: "cleanup-overwrite".into(),
        cfg: cfg(0, true),
        ops: vec![ArenaOp::cleanup(7), ArenaOp::cleanup(8)],
        free_at_end: true,
    });
    // Reduced max block size caps the growth doubling.
    let mut c = cfg(0, true);
    c.max_block_size = 1024;
    ops = (0..50).map(|_| ArenaOp::malloc(64)).collect();
    cases.push(ArenaCase::Trace {
        name: "max-block-1024".into(),
        cfg: c,
        ops,
        free_at_end: false,
    });
    // Charter boundary sizes as allocations.
    let boundary = [
        0usize, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    ];
    cases.push(ArenaCase::Trace {
        name: "boundary-sizes".into(),
        cfg: cfg(0, true),
        ops: boundary
            .iter()
            .map(|&s| ArenaOp::malloc(s as u64))
            .collect(),
        free_at_end: false,
    });

    // Fuse cases.
    cases.push(ArenaCase::Fuse {
        name: "fuse-basic".into(),
        cfg_a: cfg(0, true),
        cfg_b: cfg(0, true),
        ops_a: vec![ArenaOp::malloc(8), ArenaOp::cleanup(5)],
        ops_b: vec![ArenaOp::malloc(8), ArenaOp::cleanup(6)],
        ops_post: vec![ArenaOp::malloc(8)],
    });
    cases.push(ArenaCase::Fuse {
        name: "fuse-refused-initial".into(),
        cfg_a: cfg(200, true),
        cfg_b: cfg(0, true),
        ops_a: vec![],
        ops_b: vec![ArenaOp::malloc(8)],
        ops_post: vec![ArenaOp::malloc(8)],
    });
    cases.push(ArenaCase::Fuse {
        name: "fuse-post-oom".into(),
        cfg_a: cfg(0, true),
        cfg_b: cfg(0, true),
        ops_a: vec![ArenaOp::malloc(8)],
        ops_b: vec![ArenaOp::malloc(8)],
        ops_post: vec![ArenaOp::malloc(8), ArenaOp::malloc(70000)],
    });

    // Deterministic randomized growth scripts (SplitMix64 from the seed).
    let mut rng = SplitMix64::new(SEED.wrapping_add(1));
    for i in 0..40 {
        let n = 1 + (rng.next_u64() % 30) as usize;
        let mut ops = Vec::with_capacity(n);
        for _ in 0..n {
            let size = rng.next_u64() % 70001;
            let kind = rng.next_u64() % 8;
            let op = match kind {
                0..=5 => ArenaOp::malloc(size),
                6 => ArenaOp::message(8 + (size % 400)),
                _ => {
                    let len = (size % 64) as usize;
                    ArenaOp::strdup(len as u64, &hex(&vec![0x61; len]))
                }
            };
            ops.push(op);
        }
        cases.push(ArenaCase::Trace {
            name: format!("rand-{i}"),
            cfg: cfg(0, true),
            ops,
            free_at_end: false,
        });
    }
    cases
}

/// SplitMix64 (deterministic PRNG; same as tools/corpus/src/rng.rs).
struct SplitMix64(u64);
impl SplitMix64 {
    fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

/// The DUT interpreter: runs an op script against the ArenaPool and produces
/// the same response shape as the oracle.
fn run_dut_trace(
    cfg: &ArenaConfig,
    arena_cfg: &ArenaCfg,
    ops: &[ArenaOp],
    free_at_end: bool,
) -> serde_json::Value {
    let mut pool = ArenaPool::new(*cfg, ControlledAllocator::new(arena_cfg.fail_after_bytes));
    if arena_cfg.max_block_size != 0 {
        pool.set_max_block_size(arena_cfg.max_block_size as usize);
    }
    let initial = if arena_cfg.initial_block != 0 {
        Some(arena_cfg.initial_block as usize)
    } else {
        None
    };
    let arena = match pool.new_arena(initial, arena_cfg.alloc, 0) {
        Some(a) => a,
        None => return serde_json::json!({"status": "error", "code": "init_failed"}),
    };
    let (ops_out, _) = run_ops(&mut pool, arena, ops);
    let (space, fused) = pool.space_allocated(arena);
    let mut out = serde_json::json!({
        "status": "ok",
        "ops": ops_out,
        "arena": {"space": space, "fused_count": fused},
    });
    if free_at_end {
        let cleanups: Vec<serde_json::Value> = pool
            .free(arena)
            .into_iter()
            .map(|c| serde_json::json!(c))
            .collect();
        out["cleanup"] = serde_json::Value::Array(cleanups);
    }
    out
}

fn run_dut_fuse(
    cfg: &ArenaConfig,
    cfg_a: &ArenaCfg,
    cfg_b: &ArenaCfg,
    ops_a: &[ArenaOp],
    ops_b: &[ArenaOp],
    ops_post: &[ArenaOp],
) -> serde_json::Value {
    let fail_after = if cfg_a.fail_after_bytes != 0 {
        cfg_a.fail_after_bytes
    } else {
        cfg_b.fail_after_bytes
    };
    let mut pool = ArenaPool::new(*cfg, ControlledAllocator::new(fail_after));
    let max = if cfg_a.max_block_size != 0 {
        cfg_a.max_block_size
    } else {
        cfg_b.max_block_size
    };
    if max != 0 {
        pool.set_max_block_size(max as usize);
    }
    let ia = if cfg_a.initial_block != 0 {
        Some(cfg_a.initial_block as usize)
    } else {
        None
    };
    let ib = if cfg_b.initial_block != 0 {
        Some(cfg_b.initial_block as usize)
    } else {
        None
    };
    let a = match pool.new_arena(ia, cfg_a.alloc, 0) {
        Some(a) => a,
        None => return serde_json::json!({"status": "error", "code": "init_failed"}),
    };
    let b = match pool.new_arena(ib, cfg_b.alloc, 0) {
        Some(b) => b,
        None => return serde_json::json!({"status": "error", "code": "init_failed"}),
    };
    let (a_res, _) = run_ops(&mut pool, a, ops_a);
    let (b_res, _) = run_ops(&mut pool, b, ops_b);
    let fused = pool.fuse(a, b);
    let (post_res, _) = run_ops(&mut pool, b, ops_post);
    let (space, count) = pool.space_allocated(b);
    let free_a: Vec<serde_json::Value> = pool
        .free(a)
        .into_iter()
        .map(|c| serde_json::json!(c))
        .collect();
    let mut free_b: Vec<serde_json::Value> = pool
        .free(b)
        .into_iter()
        .map(|c| serde_json::json!(c))
        .collect();
    // Fused cleanup order depends on upstream's address-based root selection
    // (representation); compare sets.
    sort_values(&mut free_b);
    serde_json::json!({
        "status": "ok",
        "a_ops": a_res,
        "b_ops": b_res,
        "is_fused": fused,
        "post_ops": post_res,
        "arena": {"space": space, "fused_count": count},
        "free_a": free_a,
        "free_b": free_b,
    })
}

fn sort_values(v: &mut [serde_json::Value]) {
    v.sort_by(|a, b| {
        let an = a.as_i64().unwrap_or(i64::MAX);
        let bn = b.as_i64().unwrap_or(i64::MAX);
        an.cmp(&bn)
    });
}

/// Runs an op script against one arena, returning the per-op results and the
/// alloc handles by op index (mirrors the oracle's ArenaCtx).
fn run_ops(
    pool: &mut ArenaPool,
    arena: usize,
    ops: &[ArenaOp],
) -> (
    Vec<serde_json::Value>,
    Vec<Option<upb_rs_core::arena::Alloc>>,
) {
    let mut allocs = vec![None; ops.len()];
    let mut out = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let mut result = serde_json::Map::new();
        let mut ref_index: Option<u64> = None;
        match op.k.as_str() {
            "malloc" | "strdup" => {
                let a = pool.malloc(arena, op.size as usize);
                allocs[i] = a;
                result.insert("ok".into(), serde_json::json!(a.is_some()));
                if a.is_some() {
                    ref_index = Some(i as u64);
                }
            }
            "realloc" => {
                let old = op
                    .r#ref
                    .and_then(|r| allocs.get(r as usize).copied().flatten());
                let a = match old {
                    Some(o) => pool.realloc(arena, o, op.size as usize),
                    None => pool.malloc(arena, op.size as usize),
                };
                let same = match old {
                    Some(o) => a.map(|n| n.same_address(&o)).unwrap_or(false),
                    None => false,
                };
                allocs[i] = a;
                result.insert("ok".into(), serde_json::json!(a.is_some()));
                result.insert("same_ptr".into(), serde_json::json!(same));
                if a.is_some() {
                    ref_index = Some(i as u64);
                }
            }
            "shrink" => {
                if let Some(mut o) = op
                    .r#ref
                    .and_then(|r| allocs.get(r as usize).copied().flatten())
                {
                    pool.shrink_last(arena, &mut o, op.size as usize);
                    if let Some(r) = op.r#ref {
                        allocs[r as usize] = Some(o);
                    }
                }
                result.insert("ok".into(), serde_json::json!(true));
            }
            "tryextend" => {
                let extended = match op
                    .r#ref
                    .and_then(|r| allocs.get(r as usize).copied().flatten())
                {
                    Some(mut o) => {
                        let ok = pool.try_extend(arena, &mut o, op.size as usize);
                        if ok {
                            if let Some(r) = op.r#ref {
                                allocs[r as usize] = Some(o);
                            }
                        }
                        ok
                    }
                    None => false,
                };
                result.insert("ok".into(), serde_json::json!(true));
                result.insert("extended".into(), serde_json::json!(extended));
            }
            "message" => {
                let a = pool.message_new(arena, op.size as usize);
                allocs[i] = a;
                result.insert("ok".into(), serde_json::json!(a.is_some()));
                result.insert("zeroed".into(), serde_json::json!(a.is_some()));
                if a.is_some() {
                    ref_index = Some(i as u64);
                }
            }
            "cleanup" => {
                pool.set_cleanup(arena, op.r#ref.unwrap_or(0));
                result.insert("ok".into(), serde_json::json!(true));
            }
            other => panic!("unknown arena op kind: {other}"),
        }
        let (space, _) = pool.space_allocated(arena);
        result.insert("space".into(), serde_json::json!(space));
        if let Some(r) = ref_index {
            result.insert("ref".into(), serde_json::json!(r));
        }
        out.push(serde_json::Value::Object(result));
    }
    (out, allocs)
}

/// Normalizes the oracle response for comparison: strips the envelope and
/// sorts the fused cleanup lists (address-dependent order upstream).
fn normalize(value: serde_json::Value) -> serde_json::Value {
    let mut v = value;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("v");
        obj.remove("id");
        obj.remove("status");
        for key in ["free_b", "free_a", "cleanup"] {
            if let Some(arr) = obj.get_mut(key).and_then(|x| x.as_array_mut()) {
                sort_values(arr);
            }
        }
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut oracle_bin = upb_rs_oracle::client::default_oracle_path();
    let mut receipts_dir = PathBuf::from("receipts");
    let mut fail_on_residuals = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
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

    let mut oracle =
        OracleClient::spawn(&oracle_bin).unwrap_or_else(|e| panic!("cannot spawn oracle: {e}"));
    oracle.ping().expect("oracle ping failed");
    let info = oracle.arena_info().expect("arena_info failed");
    let arena_cfg = ArenaConfig {
        malloc_align: info["arena"]["malloc_align"].as_u64().unwrap() as usize,
        guard_size: info["arena"]["guard_size"].as_u64().unwrap() as usize,
        memblock_reserve: info["arena"]["memblock_reserve"].as_u64().unwrap() as usize,
        state_reserve: info["arena"]["state_reserve"].as_u64().unwrap() as usize,
        default_max_block_size: info["arena"]["default_max_block_size"].as_u64().unwrap() as usize,
    };
    assert_eq!(arena_cfg, RELEASE_CONFIG, "oracle build constants mismatch");
    println!("oracle arena config: {arena_cfg:?}");

    let cases = generate_cases();
    println!("generated {} arena cases (seed {SEED:#x})", cases.len());

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    let mut equal_count: u64 = 0;

    for (index, case) in cases.iter().enumerate() {
        let (oracle_val, dut_val) = match case {
            ArenaCase::Trace {
                cfg,
                ops,
                free_at_end,
                ..
            } => {
                let o = oracle
                    .arena_trace(cfg, ops, *free_at_end)
                    .unwrap_or_else(|e| panic!("oracle failure at {index}: {e}"));
                let d = run_dut_trace(&arena_cfg, cfg, ops, *free_at_end);
                (o, d)
            }
            ArenaCase::Fuse {
                cfg_a,
                cfg_b,
                ops_a,
                ops_b,
                ops_post,
                ..
            } => {
                let o = oracle
                    .arena_fuse(cfg_a, cfg_b, ops_a, ops_b, ops_post)
                    .unwrap_or_else(|e| panic!("oracle failure at {index}: {e}"));
                let d = run_dut_fuse(&arena_cfg, cfg_a, cfg_b, ops_a, ops_b, ops_post);
                (o, d)
            }
        };

        let equal = normalize(oracle_val.clone()) == normalize(dut_val.clone());
        if equal {
            equal_count += 1;
        } else {
            residuals.push(ResidualRecord {
                metadata: CaseMetadata {
                    id: format!("ar-{:06}", index),
                    court: COURT.to_string(),
                    oracle: UPSTREAM_SHA.to_string(),
                    op: "arena".to_string(),
                    input_hex: String::new(),
                    tag: None,
                    seed: SEED,
                    classification: None,
                    date: timestamp(),
                    notes: format!("kind={}", case.name()),
                },
                result: CaseResult {
                    oracle: oracle_val,
                    dut: dut_val,
                    equal: false,
                },
                oracle_status: "n/a".to_string(),
                dut_status: "n/a".to_string(),
                oracle_value: None,
                dut_value: None,
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
        "seed": format!("{SEED:#x}"),
        "oracle_binary": oracle_bin,
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
    }

    println!(
        "court complete: {}/{} equal, {} residuals -> {}",
        equal_count,
        cases.len(),
        residuals.len(),
        out_dir.display()
    );
    for r in &residuals {
        println!("  residual {} kind={}", r.metadata.id, r.metadata.notes);
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
    for dir in ["crates", "courts/arena/src"] {
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
