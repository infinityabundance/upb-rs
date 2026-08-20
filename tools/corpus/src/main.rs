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
    #[serde(skip_serializing_if = "Option::is_none")]
    md: Option<String>,
    /// decode_submsg: pool descriptors (hex), main first.
    #[serde(skip_serializing_if = "Option::is_none")]
    mds: Option<Vec<String>>,
    /// decode_submsg: per-table sub-slot -> table index.
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<Vec<u64>>>,
    /// encode: the upb_Encode options word (Deterministic = 1, SkipUnknown = 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<u64>,
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
            md: None,
            mds: None,
            links: None,
            options: None,
            kind: kind.to_string(),
            seed: self.seed,
        });
    }

    fn push_md(&mut self, op: &str, md: &[u8], bytes: &[u8], kind: &str) {
        self.cases.push(Case {
            op: op.to_string(),
            hex: hex(bytes),
            tag: None,
            depth: None,
            md: Some(hex(md)),
            mds: None,
            links: None,
            options: None,
            kind: kind.to_string(),
            seed: self.seed,
        });
    }

    /// decode_submsg case: a pool of linked mini tables plus a payload.
    fn push_submsg(&mut self, mds: &[Vec<u8>], links: &[Vec<u64>], bytes: &[u8], kind: &str) {
        self.cases.push(Case {
            op: "decode_submsg".to_string(),
            hex: hex(bytes),
            tag: None,
            depth: None,
            md: None,
            mds: Some(mds.iter().map(|m| hex(m)).collect()),
            links: Some(links.to_vec()),
            options: None,
            kind: kind.to_string(),
            seed: self.seed,
        });
    }

    /// decode_submsg case with an explicit depth option.
    fn push_submsg_depth(
        &mut self,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        bytes: &[u8],
        depth: u64,
        kind: &str,
    ) {
        self.cases.push(Case {
            op: "decode_submsg".to_string(),
            hex: hex(bytes),
            tag: None,
            depth: Some(depth),
            md: None,
            mds: Some(mds.iter().map(|m| hex(m)).collect()),
            links: Some(links.to_vec()),
            options: None,
            kind: kind.to_string(),
            seed: self.seed,
        });
    }

    /// encode case: decode the pool payload and re-encode under `options` and
    /// `depth` (the oracle op `encode`).
    fn push_encode(
        &mut self,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        bytes: &[u8],
        depth: u64,
        options: u64,
        kind: &str,
    ) {
        self.cases.push(Case {
            op: "encode".to_string(),
            hex: hex(bytes),
            tag: None,
            depth: Some(depth),
            md: None,
            mds: Some(mds.iter().map(|m| hex(m)).collect()),
            links: Some(links.to_vec()),
            options: Some(options),
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
            md: None,
            mds: None,
            links: None,
            options: None,
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
    for len in [
        1usize, 2, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256,
    ] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut enc = Vec::new();
        encode_varint(len as u64, &mut enc);
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

fn gen_decode_known_corpus(set: &mut CaseSet) {
    use mdgen::*;

    // Descriptor helpers. Supported encoded types for this court: Bool(13),
    // Int32(6), UInt32(7), SInt32(8), Int64(9), UInt64(10), SInt64(11),
    // Fixed32(2), Fixed64(3), SFixed32(4), SFixed64(5), Float(1), Double(0),
    // String(15), Bytes(14). No submessages/maps/groups/closed enums.
    let scalar_types: &[(usize, &str)] = &[
        (13, "bool"),
        (6, "int32"),
        (7, "uint32"),
        (8, "sint32"),
        (9, "int64"),
        (10, "uint64"),
        (11, "sint64"),
        (2, "fixed32"),
        (3, "fixed64"),
        (4, "sfixed32"),
        (5, "sfixed64"),
        (1, "float"),
        (0, "double"),
        (15, "string"),
        (14, "bytes"),
    ];

    // Single scalar/string fields with a representative set of wire values.
    for &(t, name) in scalar_types {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, t, 0);
        let md = enc.finish();
        // Values: zero, one, extremes, negative, overlong varints.
        let mut values: Vec<Vec<u8>> = vec![];
        for v in [0u64, 1, 2, 0x7F, 0x80, 0x3FFF, u32::MAX as u64, u64::MAX] {
            let mut m = vec![0x08u8];
            encode_varint(v, &mut m);
            values.push(m);
        }
        // Zigzag-munge boundaries (the dk-sint32-*/dk-sint64-* residual set
        // came from odd wire values with the high bit clear; these cover the
        // odd/even/high-bit corners of _upb_Decoder_Munge).
        for v in [
            0x3FFF_FFFFu64,
            0x4000_0000,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
        ] {
            let mut m = vec![0x08u8];
            encode_varint(v, &mut m);
            values.push(m);
        }
        // Overlong encodings of 1.
        for n in 2..=10usize {
            let mut m = vec![0x08u8];
            encode_varint_overlong(1, n, &mut m);
            values.push(m);
        }
        for (i, v) in values.iter().enumerate() {
            set.push_md("decode_known", &md, v, &format!("dk-{name}-varint-{i}"));
        }
        // Truncation: a bare tag with no value bytes, and the empty input.
        set.push_md("decode_known", &md, &[0x08], &format!("dk-{name}-bare-tag"));
        set.push_md("decode_known", &md, &[], &format!("dk-{name}-empty"));
        // Fixed-width values for fixed types.
        if matches!(t, 0..=5) {
            let (tag, n) = if matches!(t, 2 | 4 | 1) {
                (0x0Du8, 4usize)
            } else {
                (0x09u8, 8usize)
            };
            for pat in [0u8, 0xFF, 0x01, 0x80] {
                let mut m = vec![tag];
                m.extend(std::iter::repeat_n(pat, n));
                set.push_md("decode_known", &md, &m, &format!("dk-{name}-fixed"));
            }
        }
        // Strings/bytes payloads.
        if matches!(t, 15 | 14) {
            for (payload, kind) in [
                (vec![], "empty"),
                (b"hello".to_vec(), "ascii"),
                (vec![0xFFu8, 0xFE], "bad-utf8"),
                (vec![0xE2, 0x82, 0xAC], "euro"),
                (vec![0xC3, 0x28], "trunc-utf8"),
                (vec![0xED, 0xA0, 0x80], "surrogate"),
            ] {
                let mut m = vec![0x0Au8];
                encode_varint(payload.len() as u64, &mut m);
                m.extend_from_slice(&payload);
                set.push_md("decode_known", &md, &m, &format!("dk-{name}-{kind}"));
            }
            // Declared size extending past the input.
            let mut m = vec![0x0Au8, 0x05];
            m.extend_from_slice(b"hi");
            set.push_md("decode_known", &md, &m, &format!("dk-{name}-overrun"));
        }
    }

    // Truncations of a valid multi-field message.
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 13, 0); // bool
        enc.field(2, 7, 0); // uint32
        enc.field(3, 15, 0); // string
        let md = enc.finish();
        let mut m = vec![0x08u8, 0x01, 0x10, 0x96, 0x01, 0x1A, 0x03, b'a', b'b', b'c'];
        m.extend_from_slice(&[0x20, 0x01]); // unknown field 4
        set.push_md("decode_known", &md, &m, "dk-multi");
        for i in 0..m.len() {
            set.push_md("decode_known", &md, &m[..i], &format!("dk-multi-trunc{i}"));
        }
        // Wrong wire types for each field.
        set.push_md(
            "decode_known",
            &md,
            &[0x0Du8, 0x01, 0x02, 0x03, 0x04],
            "dk-wt-fixed-for-bool",
        );
        set.push_md(
            "decode_known",
            &md,
            &[0x09u8, 0, 0, 0, 0, 0, 0, 0, 0],
            "dk-wt-64-for-uint32",
        );
        set.push_md(
            "decode_known",
            &md,
            &[0x0Au8, 0x01, 0x00],
            "dk-wt-delim-for-bool",
        );
        set.push_md(
            "decode_known",
            &md,
            &[0x08u8, 0x01],
            "dk-wt-varint-for-string",
        );
        set.push_md(
            "decode_known",
            &md,
            &[0x0Bu8, 0x00],
            "dk-wt-group-for-uint32",
        );
    }

    // Packed repeated fields.
    for (t, name, lg2, tag) in [
        (7usize, "puint32", 2usize, 0x0Au8),
        (9, "pint64", 3, 0x0A),
        (13, "pbool", 0, 0x0A),
        (8, "psint32", 2, 0x0A),
        (2, "pfixed32", 2, 0x0A),
        (3, "pfixed64", 3, 0x0A),
        (1, "pfloat", 2, 0x0A),
    ] {
        let mut enc = MessageEncoder::new(MSG_MOD_DEFAULT_IS_PACKED);
        enc.field(1, t + REPEATED_BASE, 0);
        let md = enc.finish();
        let esz = 1usize << lg2;
        // A valid packed payload of 3 elements.
        let mut payload: Vec<u8> = vec![];
        for _ in 0..3 {
            payload.push(0x01);
            payload.resize(payload.len() + esz - 1, 0x00);
        }
        let mut m = vec![tag];
        encode_varint(payload.len() as u64, &mut m);
        m.extend_from_slice(&payload);
        set.push_md("decode_known", &md, &m, &format!("dk-{name}-valid"));
        // Payload size not a multiple of the element size.
        let mut m2 = vec![tag, (esz + 1) as u8];
        m2.extend(std::iter::repeat_n(0x00u8, esz + 1));
        set.push_md("decode_known", &md, &m2, &format!("dk-{name}-misaligned"));
        // Payload extending past the input.
        let mut m3 = vec![tag, 0x10];
        m3.extend_from_slice(b"hi");
        set.push_md("decode_known", &md, &m3, &format!("dk-{name}-overrun"));
        // Unpacked elements (same wire as scalar varints for varint types).
        if matches!(t, 7 | 9 | 13 | 8) {
            let m4 = vec![0x08u8, 0x01, 0x08, 0x02, 0x08, 0x03];
            set.push_md("decode_known", &md, &m4, &format!("dk-{name}-unpacked"));
        }
        // Truncated varint inside the packed payload (malformed).
        if matches!(t, 7 | 9 | 13 | 8) {
            let m5 = vec![tag, 0x02, 0xFF, 0xFF];
            set.push_md("decode_known", &md, &m5, &format!("dk-{name}-trunc-varint"));
        }
    }

    // Oneof messages.
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7, 0); // uint32
        enc.field(2, 15, 0); // string
        enc.field(3, 13, 0); // bool
        enc.start_oneofs();
        enc.oneof_field(1, true);
        enc.oneof_field(2, false);
        enc.oneof_field(3, false);
        let md = enc.finish();
        // Set each member in turn; switch between members.
        set.push_md("decode_known", &md, &[0x08u8, 0x2A], "dk-oneof-1");
        set.push_md(
            "decode_known",
            &md,
            &[0x12u8, 0x02, b'h', b'i'],
            "dk-oneof-2",
        );
        set.push_md("decode_known", &md, &[0x18u8, 0x01], "dk-oneof-3");
        set.push_md(
            "decode_known",
            &md,
            &[0x08, 0x2A, 0x12, 0x01, b'x', 0x18, 0x00],
            "dk-oneof-switch",
        );
        // Unknown field within the oneof message.
        set.push_md(
            "decode_known",
            &md,
            &[0x20u8, 0x01, 0x08, 0x2A],
            "dk-oneof-unknown",
        );
        // Empty message: the case word is 0 and every oneof offset is still
        // reported (oracle-verified; the DUT dump regression this caught is
        // preserved in casefile dsm-000074).
        set.push_md("decode_known", &md, &[], "dk-oneof-empty");
    }

    // Repeated strings and bytes.
    for (t, name) in [(15usize, "rstring"), (14, "rbytes")] {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, t + REPEATED_BASE, 0);
        let md = enc.finish();
        for (payloads, kind) in [
            (vec![b"ab".to_vec(), b"c".to_vec()], "two"),
            (vec![vec![]], "one-empty"),
            (vec![vec![0xFFu8], vec![0x00]], "non-ascii"),
        ] {
            let mut m = vec![];
            for p in &payloads {
                m.push(0x0A);
                encode_varint(p.len() as u64, &mut m);
                m.extend_from_slice(p);
            }
            set.push_md("decode_known", &md, &m, &format!("dk-{name}-{kind}"));
        }
    }

    // Boundary lengths: wrap a valid message at the charter lengths.
    {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7, 0);
        let md = enc.finish();
        for len in [
            1usize, 2, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256,
        ] {
            let mut m = vec![0x08u8, 0x01];
            m.resize(len, 0x00);
            set.push_md("decode_known", &md, &m, &format!("dk-len{len}"));
        }
    }
}

/// A payload nesting `depth` sub-messages of the recursive schema
/// R { R r = 1; } (each level: tag 0x0A + size varint; innermost: 0x0A 0x00).
fn recursive_payload(depth: usize) -> Vec<u8> {
    let mut p = vec![0x0Au8, 0x00];
    for _ in 1..depth {
        let mut head = vec![0x0Au8];
        encode_varint(p.len() as u64, &mut head);
        let mut n = head;
        n.extend_from_slice(&p);
        p = n;
    }
    p
}

/// Mini descriptor builders shared by the sub-message and encode corpus
/// generators (tooling only; mirrors mini_descriptor/internal/encode.c). The
/// encoded types are the kUpb_EncodedType values (wire_constants.h:16-38).
fn md_fields(fields: &[(u32, usize)]) -> Vec<u8> {
    let mut e = mdgen::MessageEncoder::new(0);
    for &(n, t) in fields {
        e.field(n, t, 0);
    }
    e.finish()
}
fn md_oneof(fields: &[(u32, usize)]) -> Vec<u8> {
    let mut e = mdgen::MessageEncoder::new(0);
    for &(n, t) in fields {
        e.field(n, t, 0);
    }
    e.start_oneofs();
    for (i, &(n, _)) in fields.iter().enumerate() {
        e.oneof_field(n, i == 0);
    }
    e.finish()
}
/// A `!`-versioned closed-enum descriptor for an ascending value list.
fn enum_descriptor(values: &[u32]) -> Vec<u8> {
    let mut e = mdgen::EnumEncoder::new();
    for &v in values {
        e.value(v);
    }
    e.finish()
}

fn gen_decode_submsg_corpus(set: &mut CaseSet) {
    use mdgen::*;

    fn push_truncations(
        set: &mut CaseSet,
        mds: &[Vec<u8>],
        links: &[Vec<u64>],
        full: &[u8],
        kind: &str,
    ) {
        for i in 0..full.len() {
            set.push_submsg(mds, links, &full[..i], &format!("{kind}-trunc{i}"));
        }
    }

    let sub_b = md_fields(&[(1, 7)]); // B { uint32 x = 1; }
    let sub_bi = md_fields(&[(1, 7), (2, 6)]); // B { uint32 x; int32 y; }
    let sub_bb = md_fields(&[(1, 13)]); // B { bool f = 1; }
    let sub_c64 = md_fields(&[(1, 11)]); // C { sint64 z = 1; }
    let sub_s = md_fields(&[(1, 15)]); // S { string s = 1; }
    let a_b = md_fields(&[(1, 17)]); // A { B b = 1; }
    let a_bb = md_fields(&[(1, 17), (2, 17)]); // A { B b = 1; B c = 2; }
    let a_rb = md_fields(&[(1, 17 + REPEATED_BASE)]); // A { repeated B b = 1; }
    let a_bn = md_fields(&[(1, 17), (2, 7)]); // A { B b = 1; uint32 n = 2; }
    let a_oneof = md_oneof(&[(1, 17), (2, 7)]); // A { oneof { B b; uint32 x; } }

    // Singular sub-message with content/merge/unknown/hostile payloads.
    {
        let mds = vec![a_b.clone(), sub_b.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "sm-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x00], "sm-sub-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08, 0x01], "sm-sub-scalar");
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x08], "sm-sub-trunc");
        set.push_submsg(&mds, &links, &[0x0A, 0x05, 0x08], "sm-sub-size-overrun");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x03, 0x98, 0x06, 0x05],
            "sm-sub-unknown",
        );
        set.push_submsg(&mds, &links, &[0x08, 0x01], "sm-wrong-wire");
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x00], "sm-sub-field0");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x10, 0x02],
            "sm-sub-other-field",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x0A, 0x00],
            "sm-sub-wire-mismatch",
        );
        set.push_submsg(&mds, &links, &[0x0A, 0x00, 0x0A, 0x00], "sm-sub-two-empty");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x08, 0x02],
            "sm-sub-scalar-merge",
        );
        // Unlinked sub slot -> unknown field (upstream link.h semantics).
        let unlinked = vec![vec![], vec![]];
        set.push_submsg(
            &mds,
            &unlinked,
            &[0x0A, 0x02, 0x08, 0x01],
            "sm-unlinked-unknown",
        );
    }
    // Merge into a two-field sub-message, with truncations.
    {
        let mds = vec![a_b.clone(), sub_bi.clone()];
        let links = vec![vec![1], vec![]];
        let full = [0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x10, 0x02];
        set.push_submsg(&mds, &links, &full, "sm-merge");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x10, 0x01, 0x0A, 0x02, 0x10, 0x02],
            "sm-merge-overwrite",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x0A, 0x00],
            "sm-merge-empty-second",
        );
        push_truncations(set, &mds, &links, &full, "sm-merge");
    }
    // Repeated sub-messages.
    {
        let mds = vec![a_rb.clone(), sub_bb.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "sm-rep-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08, 0x00], "sm-rep-1");
        let full = [0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x08, 0x00];
        set.push_submsg(&mds, &links, &full, "sm-rep-2");
        set.push_submsg(&mds, &links, &[0x0A, 0x00, 0x0A, 0x00], "sm-rep-two-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08], "sm-rep-trunc");
        push_truncations(set, &mds, &links, &full, "sm-rep-2");
    }
    // Nested A { B { C { sint64 } } }.
    {
        let mds = vec![a_b.clone(), a_b.clone(), sub_c64.clone()];
        let links = vec![vec![1], vec![2], vec![]];
        set.push_submsg(&mds, &links, &[], "sm-nest-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x00], "sm-nest-1");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x0A, 0x00], "sm-nest-2");
        let full = [0x0A, 0x04, 0x0A, 0x02, 0x08, 0x01];
        set.push_submsg(&mds, &links, &full, "sm-nest-z");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x0A, 0x05], "sm-nest-budget");
        push_truncations(set, &mds, &links, &full, "sm-nest-z");
    }
    // Recursive (self-link) and depth boundaries.
    {
        let mds = vec![a_b.clone()];
        let links = vec![vec![0]];
        set.push_submsg(&mds, &links, &[], "sm-rec-0");
        set.push_submsg(&mds, &links, &[0x0A, 0x00], "sm-rec-1");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x0A, 0x00], "sm-rec-2");
        let rec3 = [0x0A, 0x04, 0x0A, 0x02, 0x0A, 0x00];
        set.push_submsg(&mds, &links, &rec3, "sm-rec-3");
        push_truncations(set, &mds, &links, &rec3, "sm-rec-3");
        for d in [1usize, 2, 50, 99, 100, 101] {
            set.push_submsg(
                &mds,
                &links,
                &recursive_payload(d),
                &format!("sm-depth-{d}"),
            );
        }
        // Explicit depth options at the boundary.
        for &(opt, d) in &[
            (50u64, 50usize),
            (50, 51),
            (100, 100),
            (100, 101),
            (101, 101),
            (101, 102),
        ] {
            set.push_submsg_depth(
                &mds,
                &links,
                &recursive_payload(d),
                opt,
                &format!("sm-depth-opt{opt}-{d}"),
            );
        }
    }
    // Mutual recursion: A { B b = 1; } B { A a = 1; }.
    {
        let mds = vec![a_b.clone(), a_b.clone()];
        let links = vec![vec![1], vec![0]];
        set.push_submsg(&mds, &links, &[], "sm-mut-0");
        set.push_submsg(&mds, &links, &[0x0A, 0x00], "sm-mut-1");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x0A, 0x00], "sm-mut-2");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x0A, 0x02, 0x0A, 0x00],
            "sm-mut-3",
        );
    }
    // Oneof with a sub-message member: switch clears, re-set merges.
    {
        let mds = vec![a_oneof.clone(), sub_b.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "sm-oneof-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08, 0x01], "sm-oneof-b");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x10, 0x07],
            "sm-oneof-switch",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x10, 0x07, 0x0A, 0x02, 0x08, 0x01],
            "sm-oneof-scalar-then-b",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x08, 0x02],
            "sm-oneof-b-merge",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x00, 0x10, 0x01],
            "sm-oneof-empty-b-then-x",
        );
        set.push_submsg(&mds, &links, &[0x28, 0x05], "sm-oneof-unknown");
    }
    // Two sub-message fields sharing one sub table (slot order matters).
    {
        let mds = vec![a_bb.clone(), sub_b.clone()];
        let links = vec![vec![1, 1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x12, 0x02, 0x08, 0x02],
            "sm-multi-bc",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x08, 0x03],
            "sm-multi-bb",
        );
    }
    // Sub-message with a scalar sibling.
    {
        let mds = vec![a_bn.clone(), sub_b.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x01, 0x10, 0x05],
            "sm-bn-both",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x10, 0x05, 0x0A, 0x02, 0x08, 0x01],
            "sm-bn-scalar-first",
        );
    }
    // String inside a sub-message (no UTF-8 validation at this pin).
    {
        let mds = vec![a_b.clone(), sub_s.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x03, 0x0A, 0x01, 0xFF],
            "sm-sub-bad-utf8",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x0A, 0x00],
            "sm-sub-empty-string",
        );
    }
    // Packed repeated inside a sub-message.
    {
        let sub_packed = md_fields(&[(1, 7 + REPEATED_BASE)]); // B { repeated uint32 xs = 1; }
        let mds = vec![a_b.clone(), sub_packed.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x05, 0x0A, 0x03, 0x01, 0x02, 0x03],
            "sm-packed-in-sub",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x0A, 0x01],
            "sm-packed-in-sub-trunc",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x0A, 0x00],
            "sm-packed-in-sub-empty",
        );
    }
    // Hostile sizes: huge declared sub-message size, and overlong size
    // varints, must all be malformed (PushLimit delta < 0 / size bounds).
    {
        let mds = vec![a_b.clone(), sub_b.clone()];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0xFE, 0xFF, 0xFF, 0xFF, 0x07],
            "sm-huge-size",
        );
        set.push_submsg(&mds, &links, &[0x0A, 0x81, 0x80, 0x00], "sm-overlong-size");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x80, 0x80, 0x80, 0x80, 0x00],
            "sm-5byte-size-zero",
        );
    }
    // Map fields (`_upb_Decoder_DecodeToMap`): a parent with one Message
    // field linked to a map-entry table (mode flips to kUpb_FieldMode_Map at
    // link time). Entry wire bytes: key field 1, value field 2.
    {
        // A { map<uint32,int32> m = 1; } = $3 + map entry %)( (UInt32 key,
        // Int32 val). Entry payloads use tag 0x0A (field 1, delimited).
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(7, 6)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "mp-empty");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x07],
            "mp-one",
        );
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x05, 0x10, 0x07, 0x0A, 0x04, 0x08, 0x02, 0x10, 0x02,
            ],
            "mp-two",
        );
        // Duplicate keys: last-wins (one entry).
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x05, 0x10, 0x07, 0x0A, 0x04, 0x08, 0x05, 0x10, 0x02,
            ],
            "mp-dup-last-wins",
        );
        // Empty entry inserts the zero key/value; empty then populated.
        set.push_submsg(&mds, &links, &[0x0A, 0x00], "mp-empty-entry");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x00, 0x0A, 0x04, 0x08, 0x05, 0x10, 0x07],
            "mp-empty-then-one",
        );
        // Val-only (zero key) and key-only (zero val).
        set.push_submsg(&mds, &links, &[0x0A, 0x03, 0x10, 0x80, 0x07], "mp-val-only");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08, 0x05], "mp-key-only");
        // Negative int32 key/value: 10-byte sign-extended varints on the
        // wire; the map stores the munged low-32 bits.
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x0C, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x10,
                0x01,
            ],
            "mp-negative-key",
        );
        // Entries with unknown fields are NOT inserted; the whole entry is
        // re-encoded under the map field's tag (AddMapEntryUnknown).
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00],
            "mp-unknown-entry",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x07, 0x08, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00],
            "mp-unknown-with-key",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x03, 0x18, 0x03],
            "mp-unknown-varint-entry",
        );
        // Key field on the wire with a mismatched wire type (delimited key):
        // the entry gains an unknown, so the whole entry is re-encoded.
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x0A, 0x02, 0x05, 0x00],
            "mp-key-wire-mismatch",
        );
        // Field number 0 inside an entry is malformed.
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x00], "mp-entry-field0");
        // Malformed entries.
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x03, 0x08, 0x05, 0x10],
            "mp-trunc-varint",
        );
        set.push_submsg(&mds, &links, &[0x0A, 0x05, 0x08, 0x05], "mp-size-overrun");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0xFE, 0xFF, 0xFF, 0xFF, 0x07],
            "mp-huge-size",
        );
        // Wrong wire types for the map field itself -> unknown fields.
        set.push_submsg(&mds, &links, &[0x08, 0x01], "mp-wrong-wire-varint");
        set.push_submsg(&mds, &links, &[0x0B, 0x0C], "mp-wrong-wire-group");
        // Truncations at every offset of a two-entry payload.
        let full = [
            0x0A, 0x04, 0x08, 0x05, 0x10, 0x07, 0x0A, 0x04, 0x08, 0x02, 0x10, 0x02,
        ];
        push_truncations(set, &mds, &links, &full, "mp-two");
    }
    // String keys and values (%1) = String key + UInt32 val; %)1 = UInt32
    // key + String val; %11 = String/String).
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(15, 7)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x09, 0x0A, 0x05, b'h', b'e', b'l', b'l', b'o', 0x10, 0x01,
            ],
            "mp-str-key",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x0A, 0x00, 0x10, 0x01],
            "mp-str-key-empty",
        );
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x09, 0x0A, 0x02, b'h', b'i', 0x1D, 0x00, 0x00, 0x00, 0x00,
            ],
            "mp-str-key-unknown",
        );
    }
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(7, 15)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x05, 0x08, 0x05, 0x12, 0x01, b'x'],
            "mp-str-val",
        );
    }
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(15, 15)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x06, 0x0A, 0x01, b'x', 0x12, 0x01, b'y'],
            "mp-str-both",
        );
    }
    // Other scalar key types: Bool (/), SInt32 (*), SInt64 (-), Int64 (+),
    // UInt64 (,). Negative keys exercise sign extension / zigzag munge.
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(13, 7)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x01, 0x10, 0x05],
            "mp-bool-key",
        );
    }
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(8, 7)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x01, 0x10, 0x02],
            "mp-sint32-key",
        );
    }
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(11, 7)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x01, 0x10, 0x02],
            "mp-sint64-key",
        );
    }
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(9, 7)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x0C, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x10,
                0x01,
            ],
            "mp-int64-negative-key",
        );
    }
    {
        let mds = vec![md_fields(&[(1, 17)]), map_descriptor(10, 7)];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x07, 0x08, 0x80, 0x80, 0x80, 0x80, 0x10, 0x10, 0x01],
            "mp-uint64-key",
        );
    }
    // Message values: entry val field linked to a scalar message table
    // (A { map<uint32, B> m = 1; } where B { uint32 x = 1; }).
    {
        let mds = vec![
            md_fields(&[(1, 17)]),
            map_descriptor(7, 17),
            md_fields(&[(1, 7)]),
        ];
        let links = vec![vec![1], vec![2], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x06, 0x08, 0x05, 0x12, 0x02, 0x08, 0x01],
            "mp-msg-val",
        );
        // Absent value field: the entry inserts an empty message value.
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08, 0x05], "mp-msg-val-absent");
        // Value sub-message with its own unknown: the ENTRY has no unknowns,
        // so it inserts; the value keeps its unknown.
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x09, 0x08, 0x05, 0x12, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00,
            ],
            "mp-msg-val-unknown-inside",
        );
        // Nested map: the value message itself contains a map (its own entry
        // table). A { map<uint32, B> m = 1; } B { map<uint32,int32> n = 1; }.
        let mds = vec![
            md_fields(&[(1, 17)]),
            map_descriptor(7, 17),
            md_fields(&[(1, 17)]),
            map_descriptor(7, 6),
        ];
        let links = vec![vec![1], vec![2], vec![3], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x0A, 0x08, 0x05, 0x12, 0x06, 0x0A, 0x04, 0x08, 0x01, 0x10, 0x02,
            ],
            "mp-nested-map",
        );
        // Depth boundary: depth 1 lets a map entry decode (its own depth 0),
        // but a message VALUE inside the entry needs depth -1.
        set.push_submsg_depth(
            &[md_fields(&[(1, 17)]), map_descriptor(7, 6)],
            &[vec![1], vec![]],
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x07],
            1,
            "mp-depth1-entry",
        );
        set.push_submsg_depth(
            &mds,
            &links,
            &[0x0A, 0x06, 0x08, 0x05, 0x12, 0x02, 0x08, 0x01],
            1,
            "mp-depth1-msgval",
        );
        set.push_submsg_depth(
            &mds,
            &links,
            &[
                0x0A, 0x0A, 0x08, 0x05, 0x12, 0x06, 0x0A, 0x04, 0x08, 0x01, 0x10, 0x02,
            ],
            2,
            "mp-depth2-nested",
        );
        // The same nested payload with a WRONG entry size (9 vs the actual
        // 10 bytes) is malformed — the trailing byte escapes the entry limit.
        set.push_submsg_depth(
            &mds,
            &links,
            &[
                0x0A, 0x09, 0x08, 0x05, 0x12, 0x06, 0x0A, 0x04, 0x08, 0x01, 0x10, 0x02,
            ],
            100,
            "mp-nested-size-underrun",
        );
    }
    // Group fields (wire types 3/4; descriptor encoded type 16 = Group,
    // 36 = repeated group). The body is bounded by the matching EndGroup
    // tag, not a length prefix.
    {
        // A { group G g = 1; } G { uint32 x = 1; }.
        let mds = vec![md_fields(&[(1, 16)]), md_fields(&[(1, 7)])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "gp-empty");
        set.push_submsg(&mds, &links, &[0x0B, 0x08, 0x05, 0x0C], "gp-one");
        set.push_submsg(&mds, &links, &[0x0B, 0x0C], "gp-empty-body");
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x08, 0x01, 0x0C, 0x0B, 0x08, 0x02, 0x0C],
            "gp-merge",
        );
        // Group with an unknown field inside; group with a wire-mismatched
        // known field inside.
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x0C],
            "gp-inner-unknown",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x0A, 0x03, 0x61, 0x62, 0x63, 0x0C],
            "gp-inner-wire-mismatch",
        );
        // Malformed: EOF after the start tag; EOF mid-body; mismatched
        // EndGroup field number; EndGroup at the top level; truncated.
        set.push_submsg(&mds, &links, &[0x0B], "gp-eof-after-start");
        set.push_submsg(&mds, &links, &[0x0B, 0x08, 0x05], "gp-eof-mid-body");
        set.push_submsg(&mds, &links, &[0x0B, 0x14], "gp-wrong-end-group");
        set.push_submsg(&mds, &links, &[0x0B, 0x0C, 0x0C], "gp-endgroup-at-top");
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x08, 0x05, 0x0C, 0x08, 0x01],
            "gp-with-trailing-scalar",
        );
        // Unlinked group slot -> the whole group decodes as unknown.
        let unlinked = vec![vec![], vec![]];
        set.push_submsg(&mds, &unlinked, &[0x0B, 0x08, 0x05, 0x0C], "gp-unlinked");
        let full = [0x0B, 0x08, 0x05, 0x0C];
        push_truncations(set, &mds, &links, &full, "gp-one");
        // Depth: the group body consumes one level.
        set.push_submsg_depth(&mds, &links, &[0x0B, 0x08, 0x05, 0x0C], 1, "gp-depth1");
        set.push_submsg_depth(&mds, &links, &[0x0B, 0x08, 0x05, 0x0C], 2, "gp-depth2");
    }
    // Repeated groups: A { repeated group G g = 1; } (encoded type 36).
    {
        let mds = vec![md_fields(&[(1, 16 + REPEATED_BASE)]), md_fields(&[(1, 7)])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "gpr-empty");
        set.push_submsg(&mds, &links, &[0x0B, 0x0C], "gpr-one-empty");
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x08, 0x01, 0x0C, 0x0B, 0x08, 0x02, 0x0C],
            "gpr-two",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x08, 0x01, 0x0C, 0x0B, 0x08],
            "gpr-trunc-second",
        );
        let full = [0x0B, 0x08, 0x01, 0x0C, 0x0B, 0x08, 0x02, 0x0C];
        push_truncations(set, &mds, &links, &full, "gpr-two");
    }
    // Nested groups: A { group G g = 1; } G { group H h = 1; } H { uint32 x = 1; }.
    {
        let mds = vec![
            md_fields(&[(1, 16)]),
            md_fields(&[(1, 16)]),
            md_fields(&[(1, 7)]),
        ];
        let links = vec![vec![1], vec![2], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x0B, 0x08, 0x05, 0x0C, 0x0C],
            "gpn-nested",
        );
        set.push_submsg(&mds, &links, &[0x0B, 0x0B, 0x0C, 0x0C], "gpn-two-empty");
        // The inner EndGroup ends only the inner body; the outer must follow.
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x0B, 0x08, 0x05, 0x0C],
            "gpn-missing-outer-end",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x0B, 0x08, 0x05, 0x0C, 0x08, 0x01, 0x0C],
            "gpn-trailing-in-outer",
        );
        set.push_submsg_depth(
            &mds,
            &links,
            &[0x0B, 0x0B, 0x08, 0x05, 0x0C, 0x0C],
            2,
            "gpn-depth2",
        );
        set.push_submsg_depth(
            &mds,
            &links,
            &[0x0B, 0x0B, 0x08, 0x05, 0x0C, 0x0C],
            1,
            "gpn-depth1",
        );
    }
    // Group in a oneof: A { oneof { group G g = 1; uint32 x = 2; } }.
    {
        let mds = vec![md_oneof(&[(1, 16), (2, 7)]), md_fields(&[(1, 7)])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[0x0B, 0x08, 0x05, 0x0C], "gpo-group-only");
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x08, 0x05, 0x0C, 0x10, 0x07],
            "gpo-group-then-scalar",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x10, 0x07, 0x0B, 0x08, 0x05, 0x0C],
            "gpo-scalar-then-group",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0B, 0x08, 0x05, 0x0C, 0x0B, 0x08, 0x06, 0x0C],
            "gpo-group-merge",
        );
        set.push_submsg(&mds, &links, &[0x0B, 0x14], "gpo-wrong-end-group");
        set.push_submsg(&mds, &links, &[0x0C], "gpo-endgroup-top");
    }
    // Closed enums (`!`-versioned enum tables; encoded field type 18 =
    // ClosedEnum, 38 = repeated closed enum). Valid values are stored like
    // Int32 (low 32 bits of the varint); invalid values become unknown fields
    // — the raw wire span is preserved for scalar/unpacked occurrences
    // (`_upb_Decoder_DecodeWireValue`, decode.c:889-901), while packed
    // invalid elements are re-encoded as [varint tag][minimal varint]
    // (`_upb_Decoder_DecodeEnumPacked`, decode.c:315-347, via
    // AddEnumValueToUnknown).
    {
        // E { 1, 2 }; A { E e = 1; } (type 18, scalar).
        let mds = vec![md_fields(&[(1, 18)]), enum_descriptor(&[1, 2])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "ce-empty");
        set.push_submsg(&mds, &links, &[0x08, 0x01], "ce-valid-1");
        set.push_submsg(&mds, &links, &[0x08, 0x02], "ce-valid-2");
        set.push_submsg(&mds, &links, &[0x08, 0x00], "ce-invalid-0");
        set.push_submsg(&mds, &links, &[0x08, 0x05], "ce-invalid-5");
        set.push_submsg(&mds, &links, &[0x08, 0x85, 0x00], "ce-invalid-overlong-5");
        set.push_submsg(&mds, &links, &[0x08, 0x81, 0x00], "ce-valid-overlong-1");
        set.push_submsg(
            &mds,
            &links,
            &[0x08, 0x01, 0x08, 0x05],
            "ce-valid-then-invalid",
        );
        set.push_submsg(&mds, &links, &[0x08, 0x01, 0x08, 0x02], "ce-two-valid");
        // Wire-type mismatches: the field decodes as an unknown field.
        set.push_submsg(
            &mds,
            &links,
            &[0x0D, 0x01, 0x00, 0x00, 0x00],
            "ce-wrong-wire-32",
        );
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x01], "ce-wrong-wire-delimited");
        // An enum that includes 0: wire 0 is valid.
        let mds0 = vec![md_fields(&[(1, 18)]), enum_descriptor(&[0, 1])];
        set.push_submsg(&mds0, &links, &[0x08, 0x00], "ce0-valid-0");
        set.push_submsg(&mds0, &links, &[0x08, 0x02], "ce0-invalid-2");
        // Truncations of a two-field payload.
        let full = [0x08, 0x01, 0x08, 0x05];
        push_truncations(set, &mds, &links, &full, "ce-two");
    }
    // Enum with a value at/above the 64-bit mask boundary.
    {
        // E { 63, 64, 65 }: 63 is the top of the first mask word; 64/65
        // extend mask_limit to 96.
        let mds = vec![md_fields(&[(1, 18)]), enum_descriptor(&[63, 64, 65])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[0x08, 0x3F], "c64-valid-63");
        set.push_submsg(&mds, &links, &[0x08, 0x40], "c64-valid-64");
        set.push_submsg(&mds, &links, &[0x08, 0x41], "c64-valid-65");
        set.push_submsg(&mds, &links, &[0x08, 0x3E], "c64-invalid-62");
        set.push_submsg(&mds, &links, &[0x08, 0x42], "c64-invalid-66");
        set.push_submsg(&mds, &links, &[0x08, 0x80, 0x00], "c64-invalid-overlong-0");
    }
    // Sparse tail values (beyond mask_limit).
    {
        // E { 1000 } lands in the sparse tail (value > 512).
        let mds = vec![md_fields(&[(1, 18)]), enum_descriptor(&[1000])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[0x08, 0xE8, 0x07], "csp-valid-1000");
        set.push_submsg(&mds, &links, &[0x08, 0xE7, 0x07], "csp-invalid-999");
        set.push_submsg(&mds, &links, &[0x08, 0xE9, 0x07], "csp-invalid-1001");
        set.push_submsg(
            &mds,
            &links,
            &[0x08, 0xE8, 0x07, 0x08, 0xE7, 0x07],
            "csp-valid-then-invalid",
        );
    }
    // Negative enum values: the wire carries 10-byte sign-extended varints;
    // CheckValue truncates the u64 to u32 (`upb_MiniTableEnum_CheckValue`
    // takes uint32_t, enum.h:26-27), so -1 matches a table holding
    // 0xFFFFFFFF.
    {
        let mds = vec![md_fields(&[(1, 18)]), enum_descriptor(&[0xFFFF_FFFF])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[
                0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ],
            "cneg-valid--1",
        );
        set.push_submsg(
            &mds,
            &links,
            &[
                0x08, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ],
            "cneg-invalid--2",
        );
        // Overlong encoding of the invalid -2 value: raw span preserved.
        set.push_submsg(
            &mds,
            &links,
            &[
                0x08, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ],
            "cneg-invalid--2-overlong",
        );
    }
    // Repeated closed enums (encoded type 38), unpacked elements.
    {
        let mds = vec![
            md_fields(&[(1, 18 + REPEATED_BASE)]),
            enum_descriptor(&[1, 2]),
        ];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[], "cer-empty");
        set.push_submsg(&mds, &links, &[0x08, 0x01], "cer-one-valid");
        set.push_submsg(&mds, &links, &[0x08, 0x05], "cer-one-invalid");
        set.push_submsg(&mds, &links, &[0x08, 0x01, 0x08, 0x05], "cer-mixed");
        set.push_submsg(&mds, &links, &[0x08, 0x01, 0x08, 0x02], "cer-two-valid");
        set.push_submsg(&mds, &links, &[0x08, 0x85, 0x00], "cer-overlong-invalid");
        set.push_submsg(&mds, &links, &[0x08, 0x81, 0x00], "cer-overlong-valid");
        set.push_submsg(
            &mds,
            &links,
            &[
                0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ],
            "cer-neg-1-invalid",
        );
        let full = [0x08, 0x01, 0x08, 0x05];
        push_truncations(set, &mds, &links, &full, "cer-mixed");
    }
    // Repeated closed enums, packed.
    {
        let mds = vec![
            md_fields(&[(1, 18 + REPEATED_BASE)]),
            enum_descriptor(&[1, 2]),
        ];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[0x0A, 0x00], "cep-empty");
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x01], "cep-one-valid");
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x05], "cep-one-invalid");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x01, 0x05], "cep-mixed");
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x01, 0x02], "cep-two-valid");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x85, 0x00],
            "cep-overlong-invalid",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x02, 0x81, 0x00],
            "cep-overlong-valid",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x03, 0x05, 0x06, 0x07],
            "cep-all-invalid",
        );
        set.push_submsg(&mds, &links, &[0x0A, 0x03, 0x01, 0x05, 0x02], "cep-mixed-3");
        // Packed payload with a varint that terminates past the declared
        // size (zero-padding in the patch window) — both sides parse the
        // padding value.
        set.push_submsg(&mds, &links, &[0x0A, 0x01, 0x85], "cep-trunc-varint");
        set.push_submsg(&mds, &links, &[0x0A, 0x81, 0x80, 0x00], "cep-overlong-size");
        set.push_submsg(&mds, &links, &[0x0A, 0x05, 0x01], "cep-size-overrun");
        let full = [0x0A, 0x02, 0x01, 0x05];
        push_truncations(set, &mds, &links, &full, "cep-mixed");
    }
    // Packed negative enum values.
    {
        let mds = vec![
            md_fields(&[(1, 18 + REPEATED_BASE)]),
            enum_descriptor(&[0xFFFF_FFFF]),
        ];
        let links = vec![vec![1], vec![]];
        let neg1 = [
            0x0A, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        set.push_submsg(&mds, &links, &neg1, "cpneg-valid--1");
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x14, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xFE, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ],
            "cpneg-valid-then-invalid",
        );
    }
    // Closed enum in a oneof.
    {
        // A { oneof { E e = 1; uint32 x = 2; } }.
        let mds = vec![md_oneof(&[(1, 18), (2, 7)]), enum_descriptor(&[1, 2])];
        let links = vec![vec![1], vec![]];
        set.push_submsg(&mds, &links, &[0x08, 0x01], "ceo-valid");
        set.push_submsg(&mds, &links, &[0x08, 0x05], "ceo-invalid");
        set.push_submsg(
            &mds,
            &links,
            &[0x10, 0x07, 0x08, 0x01],
            "ceo-scalar-then-enum",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x08, 0x01, 0x10, 0x07],
            "ceo-enum-then-scalar",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x08, 0x05, 0x08, 0x01],
            "ceo-invalid-then-valid",
        );
    }
    // Closed enum as a map VALUE. The entry's val field links via SetSubEnum,
    // which requires the enum to include 0 (link.c:110-119); protoc
    // guarantees it, and the oracle reports link_failed when it is missing.
    {
        // A { map<uint32, E> m = 1; } with E { 0, 1, 2 }.
        let mds = vec![
            md_fields(&[(1, 17)]),
            map_descriptor(7, 18),
            enum_descriptor(&[0, 1, 2]),
        ];
        let links = vec![vec![1], vec![2], vec![]];
        set.push_submsg(&mds, &links, &[], "cem-empty");
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x01],
            "cem-valid",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x02],
            "cem-valid-2",
        );
        // Invalid value: the entry carries an unknown and is re-encoded under
        // the map field's tag (AddMapEntryUnknown).
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x07],
            "cem-invalid",
        );
        // Absent value: defaults to 0, which is valid for this enum.
        set.push_submsg(&mds, &links, &[0x0A, 0x02, 0x08, 0x05], "cem-val-absent");
        // A second entry with a valid value after an invalid one.
        set.push_submsg(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x05, 0x10, 0x07, 0x0A, 0x04, 0x08, 0x02, 0x10, 0x01,
            ],
            "cem-invalid-then-valid",
        );
        // Map-value enum WITHOUT 0: the link fails on both sides (oracle
        // link_failed; DUT refuses the schema).
        let mds_nozero = vec![
            md_fields(&[(1, 17)]),
            map_descriptor(7, 18),
            enum_descriptor(&[1, 2]),
        ];
        let links_nozero = vec![vec![1], vec![2], vec![]];
        set.push_submsg(
            &mds_nozero,
            &links_nozero,
            &[0x0A, 0x00],
            "cem-nozero-link-fails",
        );
    }
    // Closed enum as a repeated map VALUE.
    {
        // A { map<uint32, E> m = 1; } with repeated closed enum values
        // (entry val field type 38): valid elements store, invalid packed
        // elements re-encode as entry unknowns.
        let mds = vec![
            md_fields(&[(1, 17)]),
            map_descriptor(7, 18 + REPEATED_BASE),
            enum_descriptor(&[0, 1, 2]),
        ];
        let links = vec![vec![1], vec![2], vec![]];
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x05, 0x08, 0x05, 0x12, 0x01, 0x01],
            "cemr-valid",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x05, 0x08, 0x05, 0x12, 0x01, 0x05],
            "cemr-invalid",
        );
        set.push_submsg(
            &mds,
            &links,
            &[0x0A, 0x06, 0x08, 0x05, 0x12, 0x02, 0x01, 0x05],
            "cemr-mixed",
        );
    }
    // Unlinked closed enum: NOT generated — upstream dereferences a NULL sub
    // table during decode (UB; §49). The DUT refuses such schemas
    // (reject_deferred); covered by the DUT unit test
    // `closed_enum_unlinked_rejected`.
}

/// Encode-specific cases (oracle op `encode`): decode the payload over the
/// pool, then re-encode with the real upb_Encode under the given options.
/// The court derives option variants (0, Deterministic, SkipUnknown,
/// Deterministic|SkipUnknown) from every decode_submsg/decode_known case;
/// this generator adds the surfaces decode-only cases cannot reach:
///
/// * protoc-shape map fields (a REPEATED message field linked to the entry):
///   presence-less, so the map actually re-encodes — unlike the corpus's
///   singular-17 map shape, whose hasbit is never set by the decoder and is
///   therefore skipped on encode (QUIRKS.md §16; encode_shouldencode,
///   encoder.c:642-678);
/// * deterministic map ordering (int keys ascending; string keys bytewise
///   descending with ascending-size tie-break — map_sorter.c:28-34, 76-83);
/// * encode recursion depth boundaries (the encoder errors at
///   `--e->depth == 0`, one level earlier than the decoder's `< 0`);
/// * flagged-packed repeated fields in pool schemas (the packed flag controls
///   the encoded form).
fn gen_encode_corpus(set: &mut CaseSet) {
    use mdgen::*;

    // Protoc-shape maps: A { map<uint32,int32> m = 1; } with the map field a
    // repeated message field (RepeatedBase + 17).
    {
        let mds = vec![md_fields(&[(1, 17 + REPEATED_BASE)]), map_descriptor(7, 6)];
        let links = vec![vec![1], vec![]];
        set.push_encode(&mds, &links, &[], 0, 0, "enpm-empty");
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x07],
            0,
            0,
            "enpm-one",
        );
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x04, 0x08, 0x05, 0x10, 0x07],
            0,
            1,
            "enpm-one-det",
        );
        // Two entries in wire order 1 then 5: deterministic sorts ascending
        // and emits the REVERSED sorted order, so the output is 5 then 1
        // (backward-built buffer, encoder.c:594-640).
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x01, 0x10, 0x02, 0x0A, 0x04, 0x08, 0x05, 0x10, 0x07,
            ],
            0,
            1,
            "enpm-two-det-asc",
        );
        // SkipUnknown has no unknowns here; deterministic|skip.
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x01, 0x10, 0x02, 0x0A, 0x04, 0x08, 0x05, 0x10, 0x07,
            ],
            0,
            3,
            "enpm-two-det-skip",
        );
        // Duplicate keys collapse (last wins).
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x05, 0x10, 0x07, 0x0A, 0x04, 0x08, 0x05, 0x10, 0x02,
            ],
            0,
            1,
            "enpm-dup-det",
        );
        // NON-deterministic multi-entry map: the DUT emits insertion order,
        // the oracle the table order; the court's semantic fallback parses
        // both and compares dumps (classified map-order, NONDETERMINISM.md).
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x04, 0x08, 0x01, 0x10, 0x01, 0x0A, 0x04, 0x08, 0x03, 0x10, 0x03, 0x0A, 0x04,
                0x08, 0x02, 0x10, 0x02,
            ],
            0,
            0,
            "enpm-three-nondet",
        );
        // Unknown-entry: the re-encoded entry becomes an unknown field and is
        // emitted after the (absent) map content.
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00],
            0,
            0,
            "enpm-unknown-entry",
        );
        // Unknown-entry plus a valid entry.
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x07, 0x08, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x04, 0x08, 0x02, 0x10,
                0x01,
            ],
            0,
            0,
            "enpm-unknown-then-valid",
        );
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x07, 0x08, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x04, 0x08, 0x02, 0x10,
                0x01,
            ],
            0,
            1,
            "enpm-unknown-then-valid-det",
        );
    }
    // Protoc-shape map with a message VALUE and a nested map.
    {
        let mds = vec![
            md_fields(&[(1, 17 + REPEATED_BASE)]),
            map_descriptor(7, 17),
            md_fields(&[(1, 7)]),
        ];
        let links = vec![vec![1], vec![2], vec![]];
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x06, 0x08, 0x05, 0x12, 0x02, 0x08, 0x01],
            0,
            0,
            "enpm-msg-val",
        );
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x02, 0x08, 0x05],
            0,
            0,
            "enpm-msg-val-absent",
        );
        // Value sub-message with its own unknown: inserted; the unknown lives
        // inside the value.
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x09, 0x08, 0x05, 0x12, 0x05, 0x1D, 0x00, 0x00, 0x00, 0x00,
            ],
            0,
            0,
            "enpm-msg-val-unknown-inside",
        );
    }
    // Deterministic ordering of string keys (map_sorter.c:76-83): primary
    // bytewise DESCENDING, tie-break ascending size; the emitted order is the
    // REVERSE of the sorted iteration (backward-built buffer, encoder.c:594-640).
    {
        let mds = vec![md_fields(&[(1, 17 + REPEATED_BASE)]), map_descriptor(15, 7)];
        let links = vec![vec![1], vec![]];
        // Inserted as "a", "b", "aa" -> deterministic emits "aa", "a", "b"
        // (sorted descending "b", "a", "aa", emitted reversed).
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x05, 0x0A, 0x01, b'a', 0x10, 0x01, 0x0A, 0x05, 0x0A, 0x01, b'b', 0x10, 0x02,
                0x0A, 0x06, 0x0A, 0x02, b'a', b'a', 0x10, 0x03,
            ],
            0,
            1,
            "enps-str-det",
        );
        // Inserted as "aa", "ab", "a" -> sorted "a", "ab", "aa" (size
        // tie-break: "a" first; bytewise desc: "ab" before "aa"), emitted
        // reversed: "aa", "ab", "a".
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x06, 0x0A, 0x02, b'a', b'a', 0x10, 0x01, 0x0A, 0x06, 0x0A, 0x02, b'a', b'b',
                0x10, 0x02, 0x0A, 0x05, 0x0A, 0x01, b'a', 0x10, 0x03,
            ],
            0,
            1,
            "enps-str-det2",
        );
        // NON-deterministic multi-entry string map (fallback classification).
        set.push_encode(
            &mds,
            &links,
            &[
                0x0A, 0x05, 0x0A, 0x01, b'a', 0x10, 0x01, 0x0A, 0x05, 0x0A, 0x01, b'b', 0x10, 0x02,
                0x0A, 0x06, 0x0A, 0x02, b'a', b'a', 0x10, 0x03,
            ],
            0,
            0,
            "enps-three-nondet",
        );
    }
    // Encode recursion depth: the encoder errors at `--e->depth == 0`, one
    // level earlier than the decoder (`< 0`): D nested messages re-encode at
    // max depth D as MaxDepthExceeded.
    {
        let mds = vec![md_fields(&[(1, 17)])];
        let links = vec![vec![0]];
        set.push_encode(
            &mds,
            &links,
            &recursive_payload(99),
            100,
            0,
            "ened-99-at-100",
        );
        set.push_encode(
            &mds,
            &links,
            &recursive_payload(100),
            100,
            0,
            "ened-100-at-100",
        );
        set.push_encode(
            &mds,
            &links,
            &recursive_payload(101),
            100,
            0,
            "ened-101-at-100",
        );
        set.push_encode(&mds, &links, &recursive_payload(49), 50, 0, "ened-49-at-50");
        set.push_encode(&mds, &links, &recursive_payload(50), 50, 0, "ened-50-at-50");
        set.push_encode(&mds, &links, &recursive_payload(51), 50, 0, "ened-51-at-50");
    }
    // Flagged-packed repeated fields in a pool schema: the packed flag on the
    // descriptor selects the packed wire form on encode (encode_array,
    // encoder.c:457-577).
    {
        let mut enc = MessageEncoder::new(MSG_MOD_DEFAULT_IS_PACKED);
        enc.field(1, 7 + REPEATED_BASE, 0); // repeated uint32, default packed
        let sub_packed = enc.finish();
        let mds = vec![md_fields(&[(1, 17)]), sub_packed];
        let links = vec![vec![1], vec![]];
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x05, 0x0A, 0x03, 0x01, 0x02, 0x03],
            0,
            0,
            "enpack-in-sub",
        );
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x02, 0x0A, 0x00],
            0,
            0,
            "enpack-in-sub-empty",
        );
        // Unpacked wire input for a packed-flagged field: decode stores the
        // elements; encode emits the PACKED form.
        set.push_encode(
            &mds,
            &links,
            &[0x0A, 0x06, 0x08, 0x01, 0x08, 0x02, 0x08, 0x03],
            0,
            0,
            "enpack-in-sub-unpacked-input",
        );
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
    gen_decode_known_corpus(&mut set);
    gen_decode_submsg_corpus(&mut set);
    gen_encode_corpus(&mut set);

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
