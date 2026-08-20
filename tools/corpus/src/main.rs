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

mod mdgen;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    depth: Option<u64>,
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
            depth: None,
            kind: kind.to_string(),
            seed: self.seed,
        });
    }

    fn push_depth(&mut self, op: &str, depth: u64, bytes: &[u8], kind: &str) {
        self.cases.push(Case {
            op: op.to_string(),
            hex: hex(bytes),
            tag: None,
            depth: Some(depth),
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

fn gen_decode_empty_corpus(set: &mut CaseSet) {
    // Message-shaped inputs for the empty-mini-table decode surface.

    // Single fields of every wire type, valid and truncated at every offset.
    // varint field 1: tag 0x08
    for v in [0u64, 1, 0x7F, 0x80, 0x3FFF, u64::MAX] {
        let mut m = vec![0x08u8];
        encode_varint(v, &mut m);
        set.push_truncations("decode_empty", None, &m, "msg-varint");
    }
    // 32-bit field 1: tag 0x0D; 64-bit field 1: tag 0x09.
    let pattern: Vec<u8> = (0..32u8).collect();
    for (tag, kind) in [(0x0Du8, "msg-fixed32"), (0x09u8, "msg-fixed64")] {
        for len in [1usize, 2, 4, 5, 8, 9, 16, 17, 32] {
            let mut m = vec![tag];
            m.extend_from_slice(&pattern[..len]);
            set.push("decode_empty", None, &m, kind);
        }
        // Valid at exact lengths, truncated at every offset.
        let mut m = vec![tag];
        m.extend_from_slice(&pattern[..8]);
        set.push_truncations("decode_empty", None, &m, kind);
    }
    // Delimited field 1: tag 0x0A, payloads of many sizes.
    for size in [
        0usize, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    ] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut m = vec![0x0Au8];
        encode_varint(size as u64, &mut m);
        m.extend_from_slice(&payload);
        set.push("decode_empty", None, &m, "msg-delimited");
    }
    // Delimited declared sizes exceeding the payload.
    for size in [1u64, 2, 7, 16, 128, 0x3FFF] {
        let mut m = vec![0x0Au8];
        encode_varint(size, &mut m);
        m.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        set.push("decode_empty", None, &m, "msg-delimited-overrun");
    }
    // Truncated size varints.
    for trunc in [1usize, 2, 4] {
        let mut m = vec![0x0Au8];
        m.extend(std::iter::repeat_n(0xFFu8, trunc));
        set.push("decode_empty", None, &m, "msg-delimited-sizetrunc");
    }

    // Multi-field messages: mixed wire types, out-of-order field numbers,
    // duplicates.
    let multi = [
        0x08u8, 0x01, // field 1 varint = 1
        0x15, 0x78, 0x56, 0x34, 0x12, // field 2 fixed32
        0x18, 0x96, 0x01, // field 3 varint = 150
        0x22, 0x03, 0xAA, 0xBB, 0xCC, // field 4 delimited
        0x08, 0x02, // field 1 varint again (duplicate)
        0x35, 0x01, 0x02, 0x03, 0x04, // field 6 fixed32
    ];
    set.push_truncations("decode_empty", None, &multi, "msg-multi");

    // Out-of-order field numbers (descending).
    let desc = [0x40u8, 0x01, 0x30, 0x02, 0x20, 0x03, 0x10, 0x04];
    set.push_truncations("decode_empty", None, &desc, "msg-descending");

    // Groups: nested at increasing depth (0x0B^d 0x0C^d pattern needs ends).
    for d in [1usize, 2, 7, 8, 16, 32, 63, 64, 99, 100, 101] {
        let mut m = Vec::new();
        m.extend(std::iter::repeat_n(0x0Bu8, d - 1));
        m.extend(std::iter::repeat_n(0x0Cu8, d));
        set.push("decode_empty", None, &m, &format!("msg-group-depth{d}"));
    }
    // Group containing scalar fields.
    let g = [0x0Bu8, 0x10, 0x01, 0x1A, 0x03, 0xAA, 0xBB, 0xCC, 0x0C];
    set.push_truncations("decode_empty", None, &g, "msg-group-fields");
    // Unterminated groups.
    set.push(
        "decode_empty",
        None,
        &[0x0Bu8, 0x10, 0x01],
        "msg-group-unterminated",
    );
    set.push("decode_empty", None, &[0x0Bu8], "msg-group-bare");
    // Group with wrong end-field number.
    set.push(
        "decode_empty",
        None,
        &[0x0Bu8, 0x10, 0x01, 0x14],
        "msg-group-wrong-end",
    );

    // Hostile tags.
    for tag in 0u8..=7 {
        set.push("decode_empty", None, &[tag, 0x00], "msg-field0");
    }
    set.push("decode_empty", None, &[0x0Eu8, 0x00], "msg-wt6");
    set.push("decode_empty", None, &[0x0Fu8, 0x00], "msg-wt7");
    set.push("decode_empty", None, &[0x0Cu8], "msg-endgroup-top");
    set.push("decode_empty", None, &[0x1Cu8], "msg-endgroup-top-f3");
    // A 5-byte tag over UINT32_MAX.
    set.push(
        "decode_empty",
        None,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0x10],
        "msg-tag-over",
    );
    // Large field number, valid wire type.
    let mut big = Vec::new();
    encode_varint(((1u64 << 29) - 1) << 3, &mut big);
    big.push(0x01);
    set.push("decode_empty", None, &big, "msg-fieldnum-max");

    // Depth parameter variants over group-nesting messages.
    for d in [1usize, 2, 3, 4, 100, 101] {
        let mut m = Vec::new();
        m.extend(std::iter::repeat_n(0x0Bu8, d));
        m.extend(std::iter::repeat_n(0x0Cu8, d + 1));
        for depth in [1u64, 2, 3, 99, 100, 101] {
            set.push_depth(
                "decode_empty",
                depth,
                &m,
                &format!("msg-depthopt-n{d}-d{depth}"),
            );
        }
    }

    // Boundary-length wrappings of a representative valid message.
    let rep = [0x08u8, 0x01, 0x22, 0x03, 0xAA, 0xBB, 0xCC];
    set.push_truncations("decode_empty", None, &rep, "msg-rep");
}

fn gen_mini_table_corpus(set: &mut CaseSet) {
    use mdgen::*;

    // --- Valid messages ---------------------------------------------------
    // Empty.
    set.push("mini_table_inspect", None, b"", "mt-empty");
    set.push("mini_table_inspect", None, b"$", "mt-empty-msg");

    // Every scalar encoded type (0..=18).
    for t in 0..=18usize {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, t, 0);
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            &format!("mt-scalar-t{t}"),
        );
    }
    // Every repeated encoded type (20..=38).
    for t in 0..=18usize {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, t + REPEATED_BASE, 0);
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            &format!("mt-repeated-t{t}"),
        );
    }

    // Message modifiers: all 8 combinations.
    for msg_mod in 0..8u32 {
        let mut enc = MessageEncoder::new(msg_mod);
        enc.field(1, 15, 0); // String (UTF-8 flip interplay)
        enc.field(2, 7 + REPEATED_BASE, 0); // repeated UInt32 (packing)
        enc.field(3, 13, 0); // Bool
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            &format!("mt-msgmod-{msg_mod}"),
        );
    }

    // Field modifiers: FlipPacked, required, proto3 singular, FlipValidateUtf8.
    for &(t, modifiers, msg_mod, kind) in &[
        (
            7usize + REPEATED_BASE,
            MOD_FLIP_PACKED,
            0u32,
            "mt-flippacked",
        ),
        (
            7usize + REPEATED_BASE,
            MOD_FLIP_PACKED,
            MSG_MOD_DEFAULT_IS_PACKED,
            "mt-flippacked2",
        ),
        (15usize, MOD_FLIP_VALIDATE_UTF8, 0, "mt-fliputf8"),
        (13usize, MOD_IS_REQUIRED, 0, "mt-required"),
        (13usize, MOD_IS_PROTO3_SINGULAR, 0, "mt-proto3sing"),
        (
            15usize,
            MOD_FLIP_VALIDATE_UTF8,
            MSG_MOD_VALIDATE_UTF8,
            "mt-fliputf8-off",
        ),
    ] {
        let mut enc = MessageEncoder::new(msg_mod);
        enc.field(1, t, modifiers);
        set.push("mini_table_inspect", None, &enc.finish(), kind);
    }
    // Invalid: flip packed on a string, flip utf8 on non-string, singular
    // submessage, singular+required, required repeated.
    set.push(
        "mini_table_inspect",
        None,
        &{
            let mut e = MessageEncoder::new(0);
            e.field(1, 15, MOD_FLIP_PACKED); // String cannot be packed
            e.finish()
        },
        "mt-inval-flippacked-string",
    );
    set.push(
        "mini_table_inspect",
        None,
        &{
            let mut e = MessageEncoder::new(0);
            e.field(1, 7, MOD_FLIP_VALIDATE_UTF8); // UInt32 is not alternate bytes
            e.finish()
        },
        "mt-inval-fliputf8",
    );
    set.push(
        "mini_table_inspect",
        None,
        &{
            let mut e = MessageEncoder::new(0);
            e.field(1, 17, MOD_IS_PROTO3_SINGULAR); // singular message
            e.finish()
        },
        "mt-inval-singular-msg",
    );
    set.push(
        "mini_table_inspect",
        None,
        &{
            let mut e = MessageEncoder::new(0);
            e.field(1, 13, MOD_IS_PROTO3_SINGULAR | MOD_IS_REQUIRED);
            e.finish()
        },
        "mt-inval-singreq",
    );
    set.push(
        "mini_table_inspect",
        None,
        &{
            let mut e = MessageEncoder::new(0);
            e.field(1, 7 + REPEATED_BASE, MOD_IS_REQUIRED); // required repeated
            e.finish()
        },
        "mt-inval-req-repeated",
    );

    // Skips / sparse field numbers.
    for &num in &[2u32, 3, 15, 16, 100, 0x3FFF, 0x4000, (1u32 << 29) - 1] {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 13, 0);
        enc.field(num, 13, 0);
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            &format!("mt-skip-{num}"),
        );
    }
    // Skip value 0 (invalid): a bare '_' encodes skip 0.
    set.push("mini_table_inspect", None, b"$_", "mt-skip0");

    // Oneofs.
    for &(n_fields, oneof_members) in &[
        (2usize, 2usize), // both in one oneof
        (3, 2),           // two of three in a oneof
        (5, 3),
        (3, 3),
    ] {
        let mut enc = MessageEncoder::new(0);
        for i in 1..=n_fields {
            enc.field(i as u32, 7, 0); // UInt32
        }
        enc.start_oneofs();
        for i in 1..=oneof_members {
            enc.oneof_field(i as u32, i == 1);
        }
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            &format!("mt-oneof-{n_fields}-{oneof_members}"),
        );
    }
    // Mixed-rep oneof: int32 + string + submessage.
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 6, 0); // Int32
        enc.field(2, 15, 0); // String
        enc.field(3, 17, 0); // Message
        enc.start_oneofs();
        enc.oneof_field(1, true);
        enc.oneof_field(2, false);
        enc.oneof_field(3, false);
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            "mt-oneof-mixedrep",
        );
    }
    // Multiple oneofs.
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7, 0);
        enc.field(2, 6, 0);
        enc.field(3, 13, 0);
        enc.field(4, 9, 0); // Int64
        enc.start_oneofs();
        enc.oneof_field(1, true);
        enc.oneof_field(2, false);
        enc.oneof_field(3, true);
        enc.oneof_field(4, false);
        set.push("mini_table_inspect", None, &enc.finish(), "mt-two-oneofs");
    }
    // Oneof referencing a repeated field (invalid).
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7 + REPEATED_BASE, 0);
        enc.start_oneofs();
        enc.oneof_field(1, true);
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            "mt-inval-oneof-repeated",
        );
    }
    // Oneof referencing a missing field (invalid).
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7, 0);
        enc.start_oneofs();
        enc.oneof_field(9, true);
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            "mt-inval-oneof-missing",
        );
    }
    // Empty oneof (invalid).
    set.push("mini_table_inspect", None, b"$^", "mt-inval-oneof-empty");

    // --- Maps -------------------------------------------------------------
    for &(k, v) in &[
        (7usize, 6usize),        // UInt32 -> Int32
        (13, 6),                 // Bool -> Int32
        (0, 9),                  // Double -> Int64
        (6, 17),                 // Int32 -> Message
        (14, 15),                // Bytes -> String (invalid key)
        (2, 7),                  // Fixed32 -> UInt32
        (9, 0),                  // Int64 -> Double
        (15, 15),                // String -> String (invalid key)
        (14 + REPEATED_BASE, 6), // repeated key (invalid)
        (7, 10),                 // UInt32 -> Group (invalid val)
    ] {
        set.push(
            "mini_table_inspect",
            None,
            &map_descriptor(k, v),
            &format!("mt-map-k{k}-v{v}"),
        );
    }
    // Map with 1 or 3 fields (invalid).
    set.push("mini_table_inspect", None, b"%)", "mt-map-1field");
    set.push("mini_table_inspect", None, b"%)()", "mt-map-3field");

    // --- MessageSet -------------------------------------------------------
    set.push(
        "mini_table_inspect",
        None,
        &messageset_descriptor(),
        "mt-messageset",
    );
    set.push("mini_table_inspect", None, b"&A", "mt-messageset-data");

    // --- Invalid descriptors ---------------------------------------------
    set.push("mini_table_inspect", None, b"X", "mt-inval-version");
    set.push("mini_table_inspect", None, b"$", "mt-just-dollar");
    set.push("mini_table_inspect", None, b"$J", "mt-inval-char-J");
    set.push("mini_table_inspect", None, b"$K", "mt-inval-char-K");
    set.push(
        "mini_table_inspect",
        None,
        &[b'$', 0x7F],
        "mt-inval-char-7f",
    );
    set.push("mini_table_inspect", None, &[b'$', 0x01], "mt-inval-ctrl");
    set.push("mini_table_inspect", None, &[b'$', 0xFF], "mt-inval-ff");
    set.push("mini_table_inspect", None, &[b'$', 0x80], "mt-inval-80");
    set.push("mini_table_inspect", None, b"$^", "mt-inval-empty-oneof");

    // Overlong modifier varint: 'L' followed by many '[' chars.
    {
        let mut raw = vec![b'$', b'L'];
        raw.extend(std::iter::repeat_n(b'[', 12));
        set.push("mini_table_inspect", None, &raw, "mt-inval-overlong-varint");
    }

    // --- Seeded random descriptors ----------------------------------------
    let mut rng = SplitMix64::new(0x5EED_2026);
    for i in 0..400 {
        let n_fields = 1 + (rng.next_u64() % 8) as usize;
        let mut enc = MessageEncoder::new((rng.next_u64() % 8) as u32);
        let mut num = 1u32;
        for _ in 0..n_fields {
            num += 1 + (rng.next_u64() % 4) as u32; // sometimes sparse, always ascending
            let t = (rng.next_u64() % 39) as usize; // 0..38 incl repeated
            let mods = (rng.next_u64() % 16) as u32;
            enc.field(num, t, mods);
        }
        if rng.next_u64().is_multiple_of(2) {
            enc.start_oneofs();
            let members = 1 + (rng.next_u64() % n_fields as u64) as u32;
            for m in 1..=members {
                enc.oneof_field(m, m == 1);
            }
        }
        set.push(
            "mini_table_inspect",
            None,
            &enc.finish(),
            &format!("mt-random-{i}"),
        );
    }
    // Raw random byte soup.
    for i in 0..200 {
        let len = 1 + (rng.next_u64() % 24) as usize;
        let mut raw = Vec::with_capacity(len);
        for _ in 0..len {
            raw.push((rng.next_u64() & 0xFF) as u8);
        }
        set.push("mini_table_inspect", None, &raw, &format!("mt-soup-{i}"));
    }
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
    gen_decode_empty_corpus(&mut set);
    gen_mini_table_corpus(&mut set);

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
