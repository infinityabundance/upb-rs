//! collections-v1 differential court.
//!
//! Runs deterministic array/map scripts against BOTH the pinned upstream
//! oracle (`tools/oracle/build/oracle`, ops `array_trace` / `map_trace` —
//! the real `upb_Array` / `upb_Map`) and the upb-rs DUT
//! (`upb-rs-core` `array::Array` / `map::Map` over `arena::ArenaPool`).
//!
//! Array observables compared per op: success, element count, data bytes,
//! and the arena `SpaceAllocated` total (the array's data region is a single
//! arena allocation; growth via arena realloc is observable in the
//! accounting). Map observables: size, insert status (inserted/replaced),
//! lookup, delete, and iteration as a sorted set — the map's internal table
//! layout and arena footprint are representation (the DUT keeps entries in
//! owned storage; the court does not compare map arena space).
//!
//! The scripts are generated deterministically from a seed; a failure is
//! replayable from one seed.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use upb_rs_casefile::{CaseMetadata, CaseResult, CourtSummary, ResidualRecord};
use upb_rs_core::arena::{ArenaConfig, ArenaPool, ControlledAllocator, RELEASE_CONFIG};
use upb_rs_core::array::{ctype_lg2, Array};
use upb_rs_core::map::Map;
use upb_rs_oracle::client::OracleClient;
use upb_rs_oracle::protocol::{ArenaCfg, GenOp};

const COURT: &str = "collections-v1";
const UPSTREAM_SHA: &str = "2de70d710510ea7c5ad7ec0c72bfed7f411c7b60";
const SEED: u64 = 0x0075_7062_636f; // "upbco"

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn cfg() -> ArenaCfg {
    ArenaCfg::new()
}

/// A deterministic collection case.
enum ColCase {
    Array { name: String, ops: Vec<GenOp> },
    Map { name: String, ops: Vec<GenOp> },
}

impl ColCase {
    fn name(&self) -> &str {
        match self {
            ColCase::Array { name, .. } | ColCase::Map { name, .. } => name,
        }
    }
}

fn gop(k: &str, op: GenOp) -> GenOp {
    let mut o = op;
    o.k = k.to_string();
    o
}

fn generate_cases() -> Vec<ColCase> {
    let mut cases = Vec::new();

    // uint32 arrays: appends across capacity doublings, set/get/resize.
    let mut ops: Vec<GenOp> = vec![
        gop("new", GenOp::new_type(4)),
        gop("append", GenOp::new_ref_hex(0, "01000000")),
        gop("append", GenOp::new_ref_hex(0, "02000000")),
        gop("append", GenOp::new_ref_hex(0, "03000000")),
        gop("append", GenOp::new_ref_hex(0, "04000000")),
        gop("append", GenOp::new_ref_hex(0, "05000000")),
        gop("get", GenOp::new_ref_index(0, 2)),
        gop("set", GenOp::new_ref_index_hex(0, 0, "0a000000")),
        gop("resize", GenOp::new_ref_size(0, 2)),
    ];
    cases.push(ColCase::Array {
        name: "uint32-basic".into(),
        ops,
    });

    // Growth: 100 appends exercise doublings 4->8->16->32->64->128.
    ops = vec![gop("new", GenOp::new_type(4))];
    for i in 0..100u32 {
        ops.push(gop("append", GenOp::new_ref_hex(0, &hex(&i.to_le_bytes()))));
    }
    cases.push(ColCase::Array {
        name: "uint32-growth".into(),
        ops,
    });

    // Bool arrays (1-byte elements).
    ops = vec![gop("new", GenOp::new_type(1))];
    for i in 0..20 {
        ops.push(gop(
            "append",
            GenOp::new_ref_hex(0, if i % 2 == 0 { "01" } else { "00" }),
        ));
    }
    cases.push(ColCase::Array {
        name: "bool-basic".into(),
        ops,
    });

    // Double arrays (8-byte elements) with hostile bit patterns.
    ops = vec![gop("new", GenOp::new_type(7))];
    for v in [
        0u64,
        1,
        0x3FF0000000000000,
        0x8000000000000000,
        0x7FF0000000000000,
        u64::MAX,
    ] {
        ops.push(gop("append", GenOp::new_ref_hex(0, &hex(&v.to_le_bytes()))));
    }
    cases.push(ColCase::Array {
        name: "double-hostile".into(),
        ops,
    });

    // Boundary element counts.
    ops = vec![gop("new", GenOp::new_type(4))];
    for i in 0..17u32 {
        ops.push(gop("append", GenOp::new_ref_hex(0, &hex(&i.to_le_bytes()))));
    }
    ops.push(gop("resize", GenOp::new_ref_size(0, 3)));
    ops.push(gop("get", GenOp::new_ref_index(0, 2)));
    ops.push(gop("get", GenOp::new_ref_index(0, 100))); // out of bounds
    ops.push(gop("set", GenOp::new_ref_index_hex(0, 2, "ff000000")));
    cases.push(ColCase::Array {
        name: "boundary-sizes".into(),
        ops,
    });

    // Map: uint32 -> uint32.
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(4, 4))];
    for (k, v) in [(1u32, 10u32), (2, 20), (3, 30)] {
        ops.push(gop(
            "insert",
            GenOp::new_ref_hex(
                0,
                &format!("{}|{}", hex(&k.to_le_bytes()), hex(&v.to_le_bytes())),
            ),
        ));
    }
    ops.push(gop("insert", GenOp::new_ref_hex(0, "01000000|1e000000"))); // replace
    ops.push(gop("get", GenOp::new_ref_hex(0, "01000000")));
    ops.push(gop("get", GenOp::new_ref_hex(0, "09000000"))); // absent
    ops.push(gop("delete", GenOp::new_ref_hex(0, "02000000")));
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "u32-u32".into(),
        ops,
    });

    // Map: string -> string.
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(10, 10))];
    for (k, v) in [("hello", "world"), ("upb", "rust"), ("proto", "buf")] {
        ops.push(gop(
            "insert",
            GenOp::new_ref_hex(0, &format!("{}|{}", hex(k.as_bytes()), hex(v.as_bytes()))),
        ));
    }
    ops.push(gop(
        "insert",
        GenOp::new_ref_hex(0, "68656c6c6f|7570627273"),
    )); // replace
    ops.push(gop("get", GenOp::new_ref_hex(0, "68656c6c6f")));
    ops.push(gop("delete", GenOp::new_ref_hex(0, "757062")));
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "str-str".into(),
        ops,
    });

    // Map: uint32 -> string and string -> uint32.
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(4, 10))];
    ops.push(gop("insert", GenOp::new_ref_hex(0, "01000000|776f726c64")));
    ops.push(gop("insert", GenOp::new_ref_hex(0, "02000000|757062")));
    ops.push(gop("get", GenOp::new_ref_hex(0, "02000000")));
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "u32-str".into(),
        ops,
    });
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(10, 4))];
    ops.push(gop("insert", GenOp::new_ref_hex(0, "68656c6c6f|0a000000")));
    ops.push(gop("get", GenOp::new_ref_hex(0, "68656c6c6f")));
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "str-u32".into(),
        ops,
    });

    // Map: bool keys and double keys (hostile bit patterns).
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(1, 4))];
    ops.push(gop("insert", GenOp::new_ref_hex(0, "01|0a000000")));
    ops.push(gop("insert", GenOp::new_ref_hex(0, "00|14000000")));
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "bool-u32".into(),
        ops,
    });
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(7, 7))];
    for (i, v) in [
        0u64,
        0x8000000000000000,
        0x3FF0000000000000,
        0x7FF0000000000000,
    ]
    .iter()
    .enumerate()
    {
        ops.push(gop(
            "insert",
            GenOp::new_ref_hex(
                0,
                &format!(
                    "{}|{}",
                    hex(&v.to_le_bytes()),
                    hex(&(i as u64).to_le_bytes())
                ),
            ),
        ));
    }
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "double-double".into(),
        ops,
    });

    // Map: delete then re-insert the same key.
    let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(4, 4))];
    ops.push(gop("insert", GenOp::new_ref_hex(0, "01000000|0a000000")));
    ops.push(gop("delete", GenOp::new_ref_hex(0, "01000000")));
    ops.push(gop("insert", GenOp::new_ref_hex(0, "01000000|14000000")));
    ops.push(gop("get", GenOp::new_ref_hex(0, "01000000")));
    ops.push(gop("iterate", GenOp::new_ref(0)));
    cases.push(ColCase::Map {
        name: "delete-reinsert".into(),
        ops,
    });

    // Deterministic randomized scripts.
    let mut rng = SplitMix64::new(SEED.wrapping_add(2));
    for i in 0..20 {
        let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_type(4))];
        let n = 1 + (rng.next_u64() % 25) as usize;
        for _ in 0..n {
            let v = rng.next_u64();
            ops.push(gop("append", GenOp::new_ref_hex(0, &hex(&v.to_le_bytes()))));
        }
        if rng.next_u64().is_multiple_of(2) {
            ops.push(gop("resize", GenOp::new_ref_size(0, rng.next_u64() % 20)));
        }
        cases.push(ColCase::Array {
            name: format!("rand-arr-{i}"),
            ops,
        });
    }
    for i in 0..20 {
        let mut ops: Vec<GenOp> = vec![gop("new", GenOp::new_keyval(4, 4))];
        let n = 1 + (rng.next_u64() % 15) as usize;
        for _ in 0..n {
            let k = rng.next_u64() % 7;
            let v = rng.next_u64();
            // The oracle's value_from_hex requires EXACTLY key_size/val_size
            // bytes for numeric map keys/values (else it zero-fills); a
            // uint32 key/value is 4 bytes.
            ops.push(gop(
                "insert",
                GenOp::new_ref_hex(
                    0,
                    &format!(
                        "{}|{}",
                        hex(&(k as u32).to_le_bytes()),
                        hex(&(v as u32).to_le_bytes())
                    ),
                ),
            ));
        }
        ops.push(gop("iterate", GenOp::new_ref(0)));
        cases.push(ColCase::Map {
            name: format!("rand-map-{i}"),
            ops,
        });
    }
    cases
}

/// SplitMix64 (deterministic PRNG).
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

/// The DUT array interpreter (mirrors the oracle's array_trace).
fn run_dut_array(cfg: &ArenaConfig, arena_cfg: &ArenaCfg, ops: &[GenOp]) -> serde_json::Value {
    let mut pool = ArenaPool::new(*cfg, ControlledAllocator::new(arena_cfg.fail_after_bytes));
    if arena_cfg.max_block_size != 0 {
        pool.set_max_block_size(arena_cfg.max_block_size as usize);
    }
    let initial = (arena_cfg.initial_block != 0).then_some(arena_cfg.initial_block as usize);
    let arena = match pool.new_arena(initial, arena_cfg.alloc, 0) {
        Some(a) => a,
        None => return json!({"status": "error", "code": "init_failed"}),
    };
    let mut arrays: Vec<Option<Array>> = vec![None; ops.len()];
    let mut lgs: Vec<i32> = vec![-1; ops.len()];
    let mut out = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let mut r = serde_json::Map::new();
        match op.k.as_str() {
            "new" => {
                let lg2 = op.r#type.and_then(|t| ctype_lg2(t as u8));
                let arr = match lg2 {
                    Some(l) => pool.array_new(arena, l),
                    None => None,
                };
                lgs[i] = lg2.map(|l| l as i32).unwrap_or(-1);
                let ok = arr.is_some();
                arrays[i] = arr;
                r.insert("ok".into(), json!(ok));
                r.insert("size".into(), json!(0u64));
                r.insert("data".into(), json!(""));
                let (space, _) = pool.space_allocated(arena);
                r.insert("space".into(), json!(space));
                if ok {
                    r.insert("ref".into(), json!(i as u64));
                }
            }
            "append" | "set" => {
                let ok = match (
                    &arrays[op.r#ref.expect("missing ref") as usize],
                    lgs[op.r#ref.expect("missing ref") as usize],
                ) {
                    (Some(arr), lg2) if lg2 >= 0 => {
                        let bytes = hex_decode(op.hex.as_deref().unwrap_or(""));
                        if bytes.len() == 1 << lg2 {
                            if op.k == "append" {
                                pool.array_append(
                                    arena,
                                    arrays[op.r#ref.expect("missing ref") as usize]
                                        .as_mut()
                                        .unwrap(),
                                    &bytes,
                                )
                            } else {
                                pool.array_set(
                                    arrays[op.r#ref.expect("missing ref") as usize]
                                        .as_mut()
                                        .unwrap(),
                                    op.index.unwrap_or(0) as usize,
                                    &bytes,
                                )
                            }
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                emit_array_op(&mut r, &mut pool, arena, &arrays, &lgs, ok, op, i);
            }
            "resize" => {
                let ok = match arrays.get(op.r#ref.expect("missing ref") as usize) {
                    Some(Some(_)) => {
                        let arr = arrays[op.r#ref.expect("missing ref") as usize]
                            .as_mut()
                            .unwrap();
                        pool.array_resize(arena, arr, op.size.unwrap_or(0) as usize)
                    }
                    _ => false,
                };
                emit_array_op(&mut r, &mut pool, arena, &arrays, &lgs, ok, op, i);
            }
            "get" => {
                let arr = arrays
                    .get(op.r#ref.expect("missing ref") as usize)
                    .and_then(|a| a.as_ref());
                let v = match arr {
                    Some(a) => a.get(op.index.unwrap_or(0) as usize),
                    None => None,
                };
                match v {
                    Some(bytes) => {
                        r.insert("ok".into(), json!(true));
                        r.insert("val".into(), json!(hex(bytes)));
                    }
                    None => {
                        r.insert("ok".into(), json!(false));
                    }
                }
                let (space, _) = pool.space_allocated(arena);
                r.insert("space".into(), json!(space));
            }
            other => panic!("unknown array op: {other}"),
        }
        out.push(serde_json::Value::Object(r));
    }
    let (space, fused) = pool.space_allocated(arena);
    json!({
        "status": "ok",
        "ops": out,
        "arena": {"space": space, "fused_count": fused},
    })
}

// Mirrors the oracle's emit_collections_op printf shape; the parameter set is
// the op interpreter's state, so the count is inherent.
#[allow(clippy::too_many_arguments)]
fn emit_array_op(
    r: &mut serde_json::Map<String, serde_json::Value>,
    pool: &mut ArenaPool,
    arena: usize,
    arrays: &[Option<Array>],
    lgs: &[i32],
    ok: bool,
    op: &GenOp,
    i: usize,
) {
    let arr = arrays
        .get(op.r#ref.expect("missing ref") as usize)
        .and_then(|a| a.as_ref());
    r.insert("ok".into(), json!(ok));
    r.insert("size".into(), json!(arr.map(|a| a.size()).unwrap_or(0)));
    let data = match arr {
        Some(a) => hex(a.data()),
        None => String::new(),
    };
    r.insert("data".into(), json!(data));
    let (space, _) = pool.space_allocated(arena);
    r.insert("space".into(), json!(space));
    if ok && arr.is_some() {
        r.insert("ref".into(), json!(i as u64));
    }
    let _ = lgs;
}

/// The DUT map interpreter (mirrors the oracle's map_trace).
fn run_dut_map(_cfg: &ArenaConfig, ops: &[GenOp]) -> serde_json::Value {
    let mut maps: Vec<Option<Map>> = vec![None; ops.len()];
    let mut out = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let mut r = serde_json::Map::new();
        match op.k.as_str() {
            "new" => {
                let map = Map::new(
                    op.key_type.unwrap_or(0) as u8,
                    op.val_type.unwrap_or(0) as u8,
                );
                maps[i] = map;
                r.insert("ok".into(), json!(maps[i].is_some()));
                r.insert("size".into(), json!(0u64));
                if maps[i].is_some() {
                    r.insert("ref".into(), json!(i as u64));
                }
            }
            "insert" => {
                let (key, val) = split_kv(op.hex.as_deref().unwrap_or(""));
                let status = match maps.get_mut(op.r#ref.expect("missing ref") as usize) {
                    Some(Some(m)) => {
                        assert_kv_width(op, &key, &val, m.key_size, m.val_size);
                        m.insert(&key, &val)
                    }
                    _ => {
                        r.insert("ok".into(), json!(false));
                        out.push(serde_json::Value::Object(r));
                        continue;
                    }
                };
                let st = match status {
                    upb_rs_core::map::MapInsertStatus::Inserted => "inserted",
                    upb_rs_core::map::MapInsertStatus::Replaced => "replaced",
                    upb_rs_core::map::MapInsertStatus::OutOfMemory => "oom",
                };
                r.insert("ok".into(), json!(true));
                r.insert("status".into(), json!(st));
                let sz = maps[op.r#ref.expect("missing ref") as usize]
                    .as_ref()
                    .unwrap()
                    .size();
                r.insert("size".into(), json!(sz));
            }
            "get" => {
                let (key, _) = split_kv(op.hex.as_deref().unwrap_or(""));
                let found = match maps.get(op.r#ref.expect("missing ref") as usize) {
                    Some(Some(m)) => {
                        assert_kv_width(op, &key, &[], m.key_size, 0);
                        m.get(&key)
                    }
                    _ => None,
                };
                r.insert("ok".into(), json!(true));
                match found {
                    Some(v) => {
                        r.insert("found".into(), json!(true));
                        r.insert("val".into(), json!(hex(v)));
                    }
                    None => {
                        r.insert("found".into(), json!(false));
                    }
                }
            }
            "delete" => {
                let (key, _) = split_kv(op.hex.as_deref().unwrap_or(""));
                match maps.get_mut(op.r#ref.expect("missing ref") as usize) {
                    Some(Some(m)) => {
                        assert_kv_width(op, &key, &[], m.key_size, 0);
                        let removed = m.delete(&key);
                        r.insert("ok".into(), json!(true));
                        r.insert("removed".into(), json!(removed.is_some()));
                        r.insert("size".into(), json!(m.size()));
                    }
                    // The oracle prints a bare {"ok":false} when the map is
                    // missing (map_trace.c, delete branch).
                    _ => {
                        r.insert("ok".into(), json!(false));
                    }
                }
            }
            "iterate" => {
                let entries = match maps.get(op.r#ref.expect("missing ref") as usize) {
                    Some(Some(m)) => {
                        let mut pairs: Vec<(String, String)> =
                            m.iter().map(|e| (hex(&e.key), hex(&e.value))).collect();
                        // Sort by the concatenated pair string, matching the
                        // oracle's iteration normalization.
                        pairs.sort_by(|a, b| {
                            format!("{}|{}", a.0, a.1).cmp(&format!("{}|{}", b.0, b.1))
                        });
                        pairs
                    }
                    _ => Vec::new(),
                };
                r.insert("ok".into(), json!(true));
                let arr: Vec<serde_json::Value> =
                    entries.into_iter().map(|(k, v)| json!([k, v])).collect();
                r.insert("entries".into(), json!(arr));
            }
            other => panic!("unknown map op: {other}"),
        }
        out.push(serde_json::Value::Object(r));
    }
    // The map's arena footprint is representation (documented); the court
    // drops the arena totals before comparing.
    json!({"status": "ok", "ops": out})
}

fn split_kv(s: &str) -> (Vec<u8>, Vec<u8>) {
    match s.split_once('|') {
        Some((k, v)) => (hex_decode(k), hex_decode(v)),
        None => (hex_decode(s), hex_decode(s)),
    }
}

/// The oracle's value_from_hex requires EXACTLY key_size/val_size bytes for
/// numeric (non-string) map keys/values; a width mismatch silently zero-fills
/// upstream. The DUT enforces the same contract loudly so a generator bug
/// cannot hide as a semantic residual.
fn assert_kv_width(op: &GenOp, key: &[u8], val: &[u8], key_size: u8, val_size: u8) {
    assert!(
        key_size == 0 || key.len() == key_size as usize,
        "{}: key width {} != key_size {} (protocol contract)",
        op.k,
        key.len(),
        key_size
    );
    assert!(
        val_size == 0 || val.len() == val_size as usize,
        "{}: value width {} != val_size {} (protocol contract)",
        op.k,
        val.len(),
        val_size
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).expect("hex hi");
        let lo = (bytes[i + 1] as char).to_digit(16).expect("hex lo");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

/// Normalizes the oracle response: strips the envelope; for map traces drops
/// the arena totals (representation).
fn normalize(value: serde_json::Value, is_map: bool) -> serde_json::Value {
    let mut v = value;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("v");
        obj.remove("id");
        obj.remove("status");
        if is_map {
            obj.remove("arena");
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

    let cases = generate_cases();
    println!(
        "generated {} collection cases (seed {SEED:#x})",
        cases.len()
    );

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    let mut equal_count: u64 = 0;

    for (index, case) in cases.iter().enumerate() {
        let (oracle_val, dut_val, is_map) = match case {
            ColCase::Array { ops, .. } => {
                let acfg = cfg();
                let o = oracle
                    .arena_trace_request("array_trace", &acfg, ops)
                    .unwrap_or_else(|e| panic!("oracle failure at {index}: {e}"));
                let d = run_dut_array(&arena_cfg, &acfg, ops);
                (o, d, false)
            }
            ColCase::Map { ops, .. } => {
                let acfg = cfg();
                let o = oracle
                    .arena_trace_request("map_trace", &acfg, ops)
                    .unwrap_or_else(|e| panic!("oracle failure at {index}: {e}"));
                let d = run_dut_map(&arena_cfg, ops);
                (o, d, true)
            }
        };

        let equal = normalize(oracle_val.clone(), is_map) == normalize(dut_val.clone(), is_map);
        if equal {
            equal_count += 1;
        } else {
            residuals.push(ResidualRecord {
                metadata: CaseMetadata {
                    id: format!("col-{:06}", index),
                    court: COURT.to_string(),
                    oracle: UPSTREAM_SHA.to_string(),
                    op: if is_map { "map_trace" } else { "array_trace" }.to_string(),
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
    for dir in ["crates", "courts/collections/src"] {
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
