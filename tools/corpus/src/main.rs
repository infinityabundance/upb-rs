//! Deterministic corpus generator for the wire-primitives court.
//!
//! Generates boundary-length and malformed inputs (§9 of the charter):
//! boundary lengths 0,1,2,7,8,15,16,31,32,63,64,127,128,255,256; all
//! meaningful varint-width transitions; truncation at every byte offset of
//! valid messages; overlong encodings; the zero-padding corner cases that
//! the eps-copy stream exposes.
//!
//! The output is fully determined by the seed; a failure is replayable from
//! one seed. Usage:
//!
//!   cargo run --manifest-path tools/corpus/Cargo.toml -- \
//!     --seed 0x7570627273 --out corpus/generated/wire-primitives-v1

mod rng;

use rng::SplitMix64;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

/// The canonical default seed ("upbrs").
const DEFAULT_SEED: u64 = 0x0075_7062_7273;

/// Boundary lengths mandated by §9 of the charter.
const BOUNDARY_LENGTHS: &[usize] = &[
    0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256,
];

#[derive(Debug, Clone, Serialize)]
struct Case {
    op: String,
    hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<u64>,
    kind: String,
    seed: u64,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Minimal LEB128 encoder used only for *generating* valid test inputs. This
/// is court tooling, not the DUT.
fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Encodes a value in `n` bytes with continuation bits set on all but the
/// last byte (an overlong encoding when the value fits in fewer bytes).
fn encode_varint_overlong(mut v: u64, n: usize, out: &mut Vec<u8>) {
    for i in 0..n {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if i + 1 < n {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

struct CaseSet {
    cases: Vec<Case>,
    seed: u64,
    rng: SplitMix64,
}

impl CaseSet {
    fn new(seed: u64) -> CaseSet {
        CaseSet {
            cases: Vec::new(),
            seed,
            rng: SplitMix64::new(seed),
        }
    }

    fn push(&mut self, op: &str, tag: Option<u64>, bytes: &[u8], kind: &str) {
        self.cases.push(Case {
            op: op.to_string(),
            hex: hex(bytes),
            tag,
            kind: kind.to_string(),
            seed: self.seed,
        });
    }

    /// Truncation at every byte offset: for a valid payload of length N, all
    /// prefixes [0..i] for 0 <= i < N, plus the boundary-length wrappings.
    fn push_truncations(&mut self, op: &str, tag: Option<u64>, full: &[u8], kind: &str) {
        for i in 0..full.len() {
            self.push(op, tag, &full[..i], &format!("{kind}-trunc{i}"));
        }
        // The full payload, wrapped to every charter boundary length by
        // padding with a seed-derived byte (boundedness semantics depend on
        // total length; for group bodies the padding is genuinely parsed, so
        // the filler value matters and must stay deterministic).
        for &len in BOUNDARY_LENGTHS {
            if len >= full.len() {
                let mut padded = full.to_vec();
                let filler = (self.rng.next_u64() & 0xFF) as u8;
                padded.resize(len, filler);
                self.push(op, tag, &padded, &format!("{kind}-len{len}"));
            }
        }
    }
}

fn gen_varint_corpus(set: &mut CaseSet) {
    // Single-byte fast path: 0x00..=0x7F.
    for v in 0u64..=0x7F {
        set.push("read_varint", None, &[v as u8], "varint-single");
    }
    // Two-byte: every first byte 0x80..=0xFF with representative seconds.
    for b0 in 0x80u8..=0xFF {
        for &b1 in &[0x00u8, 0x01, 0x7F] {
            set.push("read_varint", None, &[b0, b1], "varint-two");
        }
    }
    // Width transitions: values around each 7-bit boundary.
    for shift in [7u32, 14, 21, 28, 35, 42, 49, 56, 63] {
        let base = 1u64.wrapping_shl(shift);
        for &delta in &[-3i64, -2, -1, 0, 1, 2, 3] {
            let v = if delta < 0 {
                base.wrapping_sub((-delta) as u64)
            } else {
                base.wrapping_add(delta as u64)
            };
            let mut enc = Vec::new();
            encode_varint(v, &mut enc);
            set.push(
                "read_varint",
                None,
                &enc,
                &format!("varint-boundary-s{shift}"),
            );
        }
    }
    // Extremes.
    let mut enc = Vec::new();
    encode_varint(u64::MAX, &mut enc);
    set.push("read_varint", None, &enc, "varint-max");
    set.push("read_varint", None, &[0x00], "varint-zero");

    // Overlong encodings of small values, 2..10 bytes.
    for v in [0u64, 1, 0x7F, 0x80, 0x3FFF, 0x4000] {
        for n in 2..=10 {
            let mut enc = Vec::new();
            encode_varint_overlong(v, n, &mut enc);
            set.push(
                "read_varint",
                None,
                &enc,
                &format!("varint-overlong-v{v}-n{n}"),
            );
        }
    }
    // Ten continuation bytes and eleven.
    set.push("read_varint", None, &[0xFF; 10], "varint-10-cont");
    set.push("read_varint", None, &[0xFF; 11], "varint-11-cont");
    // Truncations of interesting encodings.
    for v in [1u64, 0x7F, 0x80, 0x4000, u64::MAX] {
        let mut enc = Vec::new();
        encode_varint(v, &mut enc);
        set.push_truncations("read_varint", None, &enc, &format!("varint-trunc-v{v}"));
    }
    // Truncations of the maximum-length encoding.
    let mut max_enc = Vec::new();
    encode_varint(u64::MAX, &mut max_enc);
    set.push_truncations("read_varint", None, &max_enc, "varint-trunc-max");
}

fn gen_tag_corpus(set: &mut CaseSet) {
    // All one-byte tags (fast path).
    for v in 0u32..=0x7F {
        set.push("read_tag", None, &[v as u8], "tag-single");
    }
    // Two-byte tags: field numbers with every wire type.
    for field in [1u32, 2, 15, 16, 127, 128, 0x3FF, 0x400, 0x7FFF, 0x8000] {
        for wt in 0u32..=7 {
            let mut enc = Vec::new();
            encode_varint(((field << 3) | wt) as u64, &mut enc);
            set.push("read_tag", None, &enc, &format!("tag-f{field}-wt{wt}"));
        }
    }
    // Values around the 32-bit boundary.
    for v in [
        0x0FFF_FFFFu64,
        0x1000_0000,
        0x1FFF_FFFF,
        0x3FFF_FFFF,
        0x7FFF_FFFF,
        0xFFFF_FFFF,
        0x1_0000_0000,
    ] {
        let mut enc = Vec::new();
        encode_varint(v, &mut enc);
        set.push("read_tag", None, &enc, "tag-u32-boundary");
    }
    // Explicit 5-byte boundary encodings.
    set.push(
        "read_tag",
        None,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F],
        "tag-max-u32",
    );
    set.push(
        "read_tag",
        None,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0x10],
        "tag-over-u32",
    );
    // Overlong tags.
    for n in 2..=5 {
        let mut enc = Vec::new();
        encode_varint_overlong(1, n, &mut enc);
        set.push("read_tag", None, &enc, &format!("tag-overlong-n{n}"));
    }
    set.push("read_tag", None, &[0xFF; 5], "tag-5-cont");
    set.push("read_tag", None, &[0xFF; 6], "tag-6-cont");
    let mut full = Vec::new();
    encode_varint(0xFFFF_FFFF, &mut full);
    set.push_truncations("read_tag", None, &full, "tag-trunc-max");
}

fn gen_size_corpus(set: &mut CaseSet) {
    for v in [0u64, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0x7FFF_FFFF] {
        let mut enc = Vec::new();
        encode_varint(v, &mut enc);
        set.push("read_size", None, &enc, "size-value");
    }
    // INT32_MAX boundary: 5th byte 0x07 is valid (0x7FFFFFFF), 0x08 errors.
    set.push(
        "read_size",
        None,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0x07],
        "size-max-i32",
    );
    set.push(
        "read_size",
        None,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0x08],
        "size-over-i32",
    );
    set.push("read_size", None, &[0xFF; 5], "size-5-cont");
    let mut full = Vec::new();
    encode_varint(0x7FFF_FFFF, &mut full);
    set.push_truncations("read_size", None, &full, "size-trunc-max");
    set.push("read_size", None, &[], "size-empty");
}

fn gen_fixed_corpus(set: &mut CaseSet) {
    for &len in BOUNDARY_LENGTHS {
        // All-zero and all-FF at every boundary length.
        let zeros = vec![0u8; len];
        let ff = vec![0xFFu8; len];
        set.push("read_fixed32", None, &zeros, "fixed32-zero");
        set.push("read_fixed32", None, &ff, "fixed32-ff");
        set.push("read_fixed64", None, &zeros, "fixed64-zero");
        set.push("read_fixed64", None, &ff, "fixed64-ff");
    }
    // Distinct byte patterns.
    let pattern: Vec<u8> = (0..32u8).collect();
    for &len in BOUNDARY_LENGTHS {
        let p: Vec<u8> = pattern.iter().copied().take(len).collect();
        set.push("read_fixed32", None, &p, "fixed32-pattern");
        set.push("read_fixed64", None, &p, "fixed64-pattern");
    }
    // Truncation at every offset of a 32-byte pattern.
    set.push_truncations("read_fixed32", None, &pattern, "fixed32-trunc");
    set.push_truncations("read_fixed64", None, &pattern, "fixed64-trunc");
}

fn gen_skip_varint_corpus(set: &mut CaseSet) {
    // Representative varint shapes: the skip op has the same
    // acceptance/consumption surface as read_varint but no value.
    for v in [0u64, 1, 0x7F, 0x80, 0x4000, u64::MAX] {
        let mut enc = Vec::new();
        encode_varint(v, &mut enc);
        set.push_truncations("skip_varint", None, &enc, "skipvarint");
    }
    set.push("skip_varint", None, &[0xFF; 10], "skipvarint-10-cont");
    set.push("skip_varint", None, &[0xFF], "skipvarint-ff");
}

fn gen_skip_value_corpus(set: &mut CaseSet) {
    // varint (tag 0x08): payload truncations.
    for v in [0u64, 1, 0x7F, 0x80, u64::MAX] {
        let mut enc = Vec::new();
        encode_varint(v, &mut enc);
        set.push_truncations("skip_value", Some(0x08), &enc, "skipval-varint");
    }
    // 32-bit (tag 0x0D) and 64-bit (tag 0x09): truncation at every offset.
    let pattern: Vec<u8> = (0..32u8).collect();
    set.push_truncations("skip_value", Some(0x0D), &pattern, "skipval-32bit");
    set.push_truncations("skip_value", Some(0x09), &pattern, "skipval-64bit");
    // Delimited (tag 0x0A): sizes with exact payloads.
    for size in [0u64, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256] {
        let payload: Vec<u8> = (0..size as usize).map(|i| (i % 251) as u8).collect();
        let mut enc = Vec::new();
        encode_varint(size, &mut enc);
        enc.extend_from_slice(&payload);
        set.push("skip_value", Some(0x0A), &enc, "skipval-delimited-fit");
    }
    // Declared size exceeding the available payload (CheckSize failure).
    for size in [1u64, 2, 7, 8, 16, 128, 0x3FFF, 0x7FFF_FFFF] {
        let mut enc = Vec::new();
        encode_varint(size, &mut enc);
        enc.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        set.push("skip_value", Some(0x0A), &enc, "skipval-delimited-overrun");
    }
    // Truncated size varints (zero-padded termination then CheckSize fail).
    set.push(
        "skip_value",
        Some(0x0A),
        &[0xFF],
        "skipval-delimited-sizetrunc1",
    );
    set.push(
        "skip_value",
        Some(0x0A),
        &[0xFF, 0xFF],
        "skipval-delimited-sizetrunc2",
    );
    set.push(
        "skip_value",
        Some(0x0A),
        &[0xFF; 4],
        "skipval-delimited-sizetrunc4",
    );
    // Empty payload -> eof for every wire type.
    for tag in [0x08u64, 0x0D, 0x09, 0x0A, 0x0B, 0x0C] {
        set.push("skip_value", Some(tag), &[], "skipval-empty");
    }
    // Field number 0: tags 0x00..0x07.
    for tag in 0u64..=7 {
        set.push("skip_value", Some(tag), &[0x00], "skipval-field0");
    }
    // Invalid wire types 6 and 7.
    set.push("skip_value", Some(0x0E), &[0x00], "skipval-wt6");
    set.push("skip_value", Some(0x0F), &[0x00], "skipval-wt7");
    // EndGroup as a skipped value is an error.
    set.push("skip_value", Some(0x0C), &[0x00], "skipval-endgroup");
}

fn gen_skip_group_corpus(set: &mut CaseSet) {
    // Valid groups with empty bodies: a body of depth d (counting the outer
    // group opened by the op's tag) is 0x0B^(d-1) 0x0C^d: each 0x0B opens a
    // nested group, each 0x0C closes one, and the last 0x0C closes the outer.
    // The depth limit is 100 group entries (upb/wire/reader.c:63-80), so
    // d = 100 is valid and d = 101 fails.
    for d in [1usize, 2, 7, 8, 16, 32, 63, 64, 99, 100, 101] {
        let mut body = Vec::new();
        body.extend(std::iter::repeat_n(0x0Bu8, d - 1));
        body.extend(std::iter::repeat_n(0x0Cu8, d));
        set.push(
            "skip_group",
            Some(0x0B),
            &body,
            &format!("skipgroup-depth{d}"),
        );
    }
    // A group with a varint field, fixed fields, and a delimited field.
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x10, 0x01, 0x0C],
        "skipgroup-varint",
    );
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x15, 0x78, 0x56, 0x34, 0x12, 0x0C],
        "skipgroup-fixed32",
    );
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x1A, 0x03, 0xAA, 0xBB, 0xCC, 0x0C],
        "skipgroup-delimited",
    );
    // Nested groups of mixed shape: field-2 group containing a field-1 group.
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x13, 0x0B, 0x0C, 0x14, 0x0C],
        "skipgroup-nested",
    );
    // Unterminated groups.
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x10, 0x01],
        "skipgroup-unterminated",
    );
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x0B, 0x0C],
        "skipgroup-inner-unterminated",
    );
    set.push("skip_group", Some(0x0B), &[], "skipgroup-empty");
    // Wrong field number in the end tag.
    set.push(
        "skip_group",
        Some(0x0B),
        &[0x10, 0x01, 0x14],
        "skipgroup-wrong-end-field",
    );
    // Truncations of a moderately complex group.
    let complex = [
        0x10u8, 0x80, 0x01, 0x1A, 0x03, 0xAA, 0xBB, 0xCC, 0x25, 0x01, 0x02, 0x03, 0x04, 0x0C,
    ];
    set.push_truncations("skip_group", Some(0x0B), &complex, "skipgroup-trunc");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut seed = DEFAULT_SEED;
    let mut out = PathBuf::from("corpus/generated/wire-primitives-v1");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                seed = u64::from_str_radix(args[i].trim_start_matches("0x"), 16)
                    .expect("--seed must be a u64 hex literal");
            }
            "--out" => {
                i += 1;
                out = PathBuf::from(&args[i]);
            }
            other => panic!("unknown argument: {other}"),
        }
        i += 1;
    }

    // The PRNG lives inside CaseSet and drives filler bytes deterministically.

    let mut set = CaseSet::new(seed);
    gen_varint_corpus(&mut set);
    gen_tag_corpus(&mut set);
    gen_size_corpus(&mut set);
    gen_fixed_corpus(&mut set);
    gen_skip_varint_corpus(&mut set);
    gen_skip_value_corpus(&mut set);
    gen_skip_group_corpus(&mut set);

    fs::create_dir_all(&out).expect("create corpus dir");
    let cases_path = out.join("cases.jsonl");
    let mut w = String::new();
    for c in &set.cases {
        w.push_str(&serde_json::to_string(c).unwrap());
        w.push('\n');
    }
    fs::write(&cases_path, w).expect("write cases.jsonl");

    let manifest = serde_json::json!({
        "court": "wire-primitives-v1",
        "seed": format!("{seed:#x}"),
        "upstream": "2de70d710510ea7c5ad7ec0c72bfed7f411c7b60",
        "case_count": set.cases.len(),
        "generated_by": "tools/corpus",
    });
    fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest.json");

    println!(
        "generated {} cases -> {}",
        set.cases.len(),
        cases_path.display()
    );
}
