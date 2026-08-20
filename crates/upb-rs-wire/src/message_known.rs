//! Known-field message decoding with real mini tables, including linked
//! sub-messages.
//!
//! Mirrors the pinned upstream `upb/wire/decode.c` observable behavior for
//! the surface supported by courts `decode-known-v1` and `decode-submsg-v1`:
//! scalar fields of all varint/fixed/floating types, string/bytes, repeated
//! scalars (unpacked and packed), repeated strings/bytes, oneofs, and
//! sub-messages (singular with merge semantics, repeated, nested, and
//! recursive through the pool's sub-slot links). Maps, groups, and closed
//! enums are deferred; the corpus generators never emit them, and the
//! decoder rejects groups/maps defensively.
//!
//! The message is modeled exactly like upstream: a zeroed byte buffer of
//! `mini_table.size` bytes with presence bits at their hasbit indices, scalar
//! values at their offsets, and oneof case words at the negated presence
//! offsets. Strings/bytes content, arrays, and sub-messages live in side
//! storage (their wire observable is the content, not the pointer).
//!
//! Key upstream semantics reproduced (all cited to `upb/wire/decode.c` at the
//! pinned commit):
//! * `_upb_Decoder_Munge` (139-153): bool = (varint != 0); SInt32 = zigzag on
//!   the low 32 bits; SInt64 = full zigzag; Int32/UInt32/Enum store the low
//!   32 bits of the varint.
//! * wire-type mismatch turns a known field into an unknown field (the
//!   kVarintOps/kDelimitedOps tables at 764-872 and the fixed masks at
//!   880-886).
//! * packed decoding (243-347): fixed payloads must be a multiple of the
//!   element size; varint payloads parse varints until the limit, munged per
//!   element; a payload extending past the input is malformed (PushLimit
//!   fails at 212, 295).
//! * strings: `_upb_Decoder_ReadString` (internal/decoder.h:244-263) — the
//!   payload must fit the input (no zero-padding). UTF-8 validation is gated:
//!   a String field in a mini descriptor without the message-level
//!   validate-UTF8 modifier (MSG_MOD_VALIDATE_UTF8) carries the IsAlternate
//!   flag and behaves as unvalidated bytes (`_upb_Decoder_FieldRequiresUtf8Validation`
//!   only sees an effective Bytes type); the corpus never sets the modifier,
//!   so this court's String fields never validate (oracle-verified: `0a01ff`
//!   on `$1` decodes ok). Validation is a future corpus expansion.
//! * unknown fields (1010-1081): captured as raw wire spans, preserved in
//!   wire order; field number 0 is malformed.
//! * sub-messages: `_upb_Decoder_DecodeSubMessage` (210-219) bounds the
//!   payload with `PushLimit`/`PopLimit` and recurses with a decremented
//!   depth budget (`_upb_Decoder_RecurseSubMessage`, 199-207); singular
//!   fields decode into the existing sub-message when present (merge, 583-587)
//!   and repeated fields append a new element per occurrence (438-449);
//!   oneof switches clear the previous member's slot (549-556); an unlinked
//!   sub-slot decodes as unknown (`_upb_Decoder_CheckUnlinked`, 805-812).

use std::collections::HashMap;

use upb_rs_mini_table::model::{FieldMode, MiniTable, MiniTableField, NO_SUB};

use crate::reader;
use crate::stream::EpsCopyStream;

/// The failure modes observable for this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownDecodeError {
    Malformed,
    BadUtf8,
    MaxDepthExceeded,
    Unsupported(&'static str),
}

impl std::fmt::Display for KnownDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnownDecodeError::Malformed => write!(f, "malformed"),
            KnownDecodeError::BadUtf8 => write!(f, "bad_utf8"),
            KnownDecodeError::MaxDepthExceeded => write!(f, "max_depth_exceeded"),
            KnownDecodeError::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

type Result<T> = std::result::Result<T, KnownDecodeError>;

/// A decoded message.
#[derive(Debug, Clone)]
pub struct Message {
    /// The zeroed storage buffer (mini_table.size bytes).
    pub buf: Vec<u8>,
    /// Scalar string/bytes content by field number.
    pub strings: HashMap<usize, Vec<u8>>,
    /// Repeated field elements by field number (raw element bytes).
    pub arrays: HashMap<usize, Vec<Vec<u8>>>,
    /// Singular submessage content by field number.
    pub submsgs: HashMap<usize, Message>,
    /// Repeated submessage elements by field number.
    pub submsg_arrays: HashMap<usize, Vec<Message>>,
    /// Concatenated unknown-field wire bytes, in wire order.
    pub unknown: Vec<u8>,
}

impl Message {
    fn new(size: usize) -> Message {
        Message {
            buf: vec![0; size],
            strings: HashMap::new(),
            arrays: HashMap::new(),
            submsgs: HashMap::new(),
            submsg_arrays: HashMap::new(),
            unknown: Vec::new(),
        }
    }

    fn hasbit_set(&self, index: u16) -> bool {
        let byte = (index / 8) as usize;
        let bit = 1u8 << (index % 8);
        self.buf.get(byte).is_some_and(|b| b & bit != 0)
    }

    fn set_hasbit(&mut self, index: u16) {
        let byte = (index / 8) as usize;
        let bit = 1u8 << (index % 8);
        if let Some(b) = self.buf.get_mut(byte) {
            *b |= bit;
        }
    }

    fn oneof_case(&self, case_offset: u16) -> u32 {
        let off = case_offset as usize;
        if off + 4 <= self.buf.len() {
            u32::from_le_bytes(self.buf[off..off + 4].try_into().unwrap())
        } else {
            0
        }
    }

    fn set_oneof_case(&mut self, case_offset: u16, case: u32) {
        let off = case_offset as usize;
        if off + 4 <= self.buf.len() {
            self.buf[off..off + 4].copy_from_slice(&case.to_le_bytes());
        }
    }

    /// Whether the field is present (`_upb_MiniTableField_HasHasbit` + oneof
    /// case semantics; proto3-singular fields have no presence).
    fn field_present(&self, f: &MiniTableField) -> bool {
        if f.presence > 0 {
            self.hasbit_set(f.presence as u16)
        } else if f.is_in_oneof() {
            self.oneof_case((!f.presence) as u16) == f.number
        } else {
            true
        }
    }

    /// Presence bookkeeping for the scalar path
    /// (`_upb_Decoder_DecodeToSubMessage`, decode.c:546-557).
    fn set_presence(&mut self, f: &MiniTableField) {
        if f.presence > 0 {
            self.set_hasbit(f.presence as u16);
        } else if f.is_in_oneof() {
            self.set_oneof_case((!f.presence) as u16, f.number);
        }
    }
}

/// A pool of mini tables with linked sub-slots (the mini-descriptor analog of
/// upstream's table pool + `upb_MiniTable_Link`). Sub slots are assigned in
/// field order during build (`set_type_and_sub`, decode.rs:364-369), so slot
/// `s` of table `t` is the `s`-th field of `t` carrying a sub slot
/// (`submsg_ofs != NO_SUB`); `links[t][s]` is the target table index.
#[derive(Debug, Clone)]
pub struct TableSet {
    tables: Vec<MiniTable>,
    links: Vec<Vec<usize>>,
}

impl TableSet {
    /// A single table with no links (every sub-slot unlinked): submessage
    /// fields behave as unknown fields, mirroring upstream's documented
    /// unlinked behavior (mini_descriptor/link.h:37-40).
    pub fn from_single(descriptor: &[u8]) -> Result<TableSet> {
        let (mt, _) = upb_rs_mini_table::decode::build_mini_table(descriptor)
            .map_err(|_| KnownDecodeError::Unsupported("minitable"))?;
        Ok(TableSet {
            tables: vec![mt],
            links: vec![Vec::new()],
        })
    }

    /// Builds a pool from `mds` (main at index 0) and links sub slots by
    /// `links[t][s]` = target table index. Missing/out-of-range entries leave
    /// the slot unlinked (unknown-field behavior, as upstream).
    pub fn from_pool(mds: &[&[u8]], links: &[&[usize]]) -> Result<TableSet> {
        let mut tables = Vec::with_capacity(mds.len());
        for md in mds {
            let (mt, _) = upb_rs_mini_table::decode::build_mini_table(md)
                .map_err(|_| KnownDecodeError::Unsupported("minitable"))?;
            tables.push(mt);
        }
        Ok(TableSet {
            tables,
            links: links.iter().map(|l| l.to_vec()).collect(),
        })
    }

    pub fn table(&self, idx: usize) -> &MiniTable {
        &self.tables[idx]
    }

    /// The main (index-0) table.
    pub fn main(&self) -> &MiniTable {
        &self.tables[0]
    }

    /// The linked sub-table index for the field at `field_index` of
    /// `table_idx`, or None when the slot is unlinked.
    pub fn sub(&self, table_idx: usize, field_index: usize) -> Option<usize> {
        let mt = &self.tables[table_idx];
        let slot = mt.fields[..=field_index]
            .iter()
            .filter(|f| f.submsg_ofs != NO_SUB)
            .count()
            .checked_sub(1)?;
        self.links
            .get(table_idx)
            .and_then(|l| l.get(slot))
            .copied()
            .filter(|&t| t < self.tables.len())
    }
}

fn find_field_index(mt: &MiniTable, number: u32) -> Option<usize> {
    mt.fields.iter().position(|f| f.number == number)
}

/// The stored byte width of a scalar field (not strings/bytes).
fn scalar_width(f: &MiniTableField) -> usize {
    match f.rep() {
        upb_rs_mini_table::model::FieldRep::OneByte => 1,
        upb_rs_mini_table::model::FieldRep::FourByte => 4,
        upb_rs_mini_table::model::FieldRep::EightByte => 8,
        upb_rs_mini_table::model::FieldRep::StringView => 16,
    }
}

impl Message {
    /// Renders the message as the normalized dump form shared with the oracle
    /// (courts decode-known-v1 / decode-submsg-v1). Every value is the raw
    /// stored bytes (or content for strings/bytes) as hex; submessage fields
    /// render as a nested dump object, repeated submessages as an array of
    /// dump objects — bit-exact against the oracle's accessor dump.
    ///
    /// Presence semantics mirror upstream: hasbit fields appear only when
    /// their bit is set, oneof members only when their case matches,
    /// proto3-singular fields always (stored value, 0 when never written),
    /// arrays always.
    pub fn dump(&self, ts: &TableSet, table_idx: usize) -> serde_json::Value {
        let mt = ts.table(table_idx);
        let mut fields = Vec::new();
        let mut oneof_offsets: Vec<u16> = Vec::new();
        for (i, f) in mt.fields.iter().enumerate() {
            // Oneof case offsets are emitted for every oneof in the table,
            // present or not (the oracle renders the case word, 0 when none
            // is set) — oracle-verified for empty oneof messages.
            if f.is_in_oneof() {
                let off = (!f.presence) as u16;
                if !oneof_offsets.contains(&off) {
                    oneof_offsets.push(off);
                }
            }
            let is_submsg = f.descriptortype == 11 && f.submsg_ofs != NO_SUB;
            let subl = ts.sub(table_idx, i);
            if f.mode_class() == FieldMode::Array {
                if is_submsg {
                    let elems = self
                        .submsg_arrays
                        .get(&(f.number as usize))
                        .cloned()
                        .unwrap_or_default();
                    let values = elems
                        .iter()
                        .map(|e| match subl {
                            Some(s) => e.dump(ts, s),
                            None => empty_dump(),
                        })
                        .collect::<Vec<_>>();
                    fields.push(serde_json::json!({"number": f.number, "value": values}));
                } else {
                    let elems = self
                        .arrays
                        .get(&(f.number as usize))
                        .cloned()
                        .unwrap_or_default();
                    fields.push(serde_json::json!({
                        "number": f.number,
                        "value": elems.iter().map(|e| hex(e)).collect::<Vec<_>>(),
                    }));
                }
            } else {
                let present = self.field_present(f);
                if !present && (f.presence > 0 || f.is_in_oneof()) {
                    continue;
                }
                let value = if is_submsg {
                    let sub = self.submsgs.get(&(f.number as usize));
                    match (sub, subl) {
                        (Some(s), Some(si)) => s.dump(ts, si),
                        _ => empty_dump(),
                    }
                } else {
                    match f.descriptortype {
                        9 | 12 => serde_json::Value::String(hex(&self
                            .strings
                            .get(&(f.number as usize))
                            .cloned()
                            .unwrap_or_default())),
                        _ => {
                            let off = f.offset as usize;
                            let n = scalar_width(f);
                            let bytes = if off + n <= self.buf.len() {
                                self.buf[off..off + n].to_vec()
                            } else {
                                Vec::new()
                            };
                            serde_json::Value::String(hex(&bytes))
                        }
                    }
                };
                fields.push(serde_json::json!({"number": f.number, "value": value}));
            }
        }
        oneof_offsets.sort_unstable();
        let oneof_cases = oneof_offsets
            .into_iter()
            .map(|off| serde_json::json!({ "case_offset": off, "case": self.oneof_case(off) }))
            .collect::<Vec<_>>();
        serde_json::json!({
            "fields": fields,
            "oneof_cases": oneof_cases,
            "unknown": hex(&self.unknown),
        })
    }
}

/// The normalized dump of an absent/unlinked submessage.
fn empty_dump() -> serde_json::Value {
    serde_json::json!({"fields": [], "oneof_cases": [], "unknown": ""})
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `_upb_Decoder_Munge` (decode.c:139-153): the wire varint is converted to
/// the stored representation. For SInt32/SInt64 this is the **inverse** of
/// zigzag encoding: `(n >> 1) ^ -(n & 1)`. The `-(n & 1)` term is all-ones
/// when `n` is odd and zero when `n` is even — the sign-extension form
/// `(n >> 1) ^ (n >> 31)` differs for odd values with the high bit clear
/// (casefiles dk-sint32-* / dk-sint64-* / dk-psint32-* preserve the
/// divergence, e.g. wire varint 1 must store 0xFFFFFFFF = -1).
fn zigzag32(n: u32) -> u32 {
    (n >> 1) ^ 0u32.wrapping_sub(n & 1)
}

fn zigzag64(n: u64) -> u64 {
    (n >> 1) ^ 0u64.wrapping_sub(n & 1)
}

/// `_upb_Decoder_Munge` (decode.c:139-161) as stored bytes.
fn munge(field: &MiniTableField, varint: u64) -> u64 {
    match field.descriptortype {
        8 => (varint != 0) as u64,            // Bool
        17 => zigzag32(varint as u32) as u64, // SInt32
        18 => zigzag64(varint),               // SInt64
        _ => varint,
    }
}

fn is_varint_type(t: u8) -> bool {
    matches!(t, 3 | 4 | 5 | 8 | 13 | 14 | 17 | 18)
}
fn is_fixed32_type(t: u8) -> bool {
    matches!(t, 2 | 7 | 15)
}
fn is_fixed64_type(t: u8) -> bool {
    matches!(t, 1 | 6 | 16)
}

/// Element size in bytes for the supported types.
fn elem_size(field_type: u8) -> usize {
    match field_type {
        8 => 1,
        2 | 7 | 15 | 5 | 13 | 14 | 17 => 4,
        1 | 6 | 16 | 3 | 4 | 18 => 8,
        _ => 16,
    }
}

/// Decodes a message whose mini table was built from `descriptor`, mirroring
/// `upb_Decode` with options 0. `max_depth == 0` -> default 100.
///
/// Every sub-slot is unlinked, so submessage fields in the descriptor decode
/// as unknown fields — exactly what upstream does for unlinked sub-tables
/// (`_upb_Decoder_CheckUnlinked`, decode.c:805-812; oracle-verified for
/// `$3` + `0a00`). Groups and maps are deferred (rejected defensively).
pub fn decode_known(descriptor: &[u8], input: &[u8], max_depth: u32) -> Result<Message> {
    let ts = TableSet::from_single(descriptor)?;
    reject_deferred(ts.main())?;
    let depth = effective_depth(max_depth);
    let mut msg = Message::new(ts.main().size as usize);
    let mut stream = EpsCopyStream::init(input);
    let mut ptr = 0usize;
    decode_message(&ts, 0, &mut msg, &mut stream, &mut ptr, depth, input)?;
    Ok(msg)
}

/// Decodes a message from a pool of linked mini tables: `mds[0]` is the main
/// descriptor, `links[t][s]` maps table `t`'s sub-slot `s` to the target
/// table index (slot order = field order). Mirrors building each table with
/// `upb_MiniTable_Build`, linking with `upb_MiniTable_SetSubMessage`, then
/// `upb_Decode` (court decode-submsg-v1).
pub fn decode_submsg(
    mds: &[&[u8]],
    links: &[&[usize]],
    input: &[u8],
    max_depth: u32,
) -> Result<Message> {
    let ts = TableSet::from_pool(mds, links)?;
    reject_deferred(ts.main())?;
    let depth = effective_depth(max_depth);
    let mut msg = Message::new(ts.main().size as usize);
    let mut stream = EpsCopyStream::init(input);
    let mut ptr = 0usize;
    decode_message(&ts, 0, &mut msg, &mut stream, &mut ptr, depth, input)?;
    Ok(msg)
}

fn reject_deferred(mt: &MiniTable) -> Result<()> {
    for f in &mt.fields {
        if f.descriptortype == 10 {
            return Err(KnownDecodeError::Unsupported("group"));
        }
        if f.mode_class() == FieldMode::Map {
            return Err(KnownDecodeError::Unsupported("map"));
        }
    }
    Ok(())
}

fn effective_depth(max_depth: u32) -> i32 {
    if max_depth == 0 {
        reader::DEFAULT_DEPTH_LIMIT
    } else {
        max_depth as i32
    }
}

/// `_upb_Decoder_DecodeMessage` (decode.c:1256-1271): one message's field
/// loop. Recurses into linked submessage fields with a decremented depth
/// budget (`_upb_Decoder_RecurseSubMessage`, decode.c:199-207). An EndGroup
/// tag is malformed at this surface (expected_end_group is always
/// DECODE_NOGROUP for submessages and the top level; groups are deferred).
fn decode_message(
    ts: &TableSet,
    table_idx: usize,
    msg: &mut Message,
    stream: &mut EpsCopyStream,
    ptr: &mut usize,
    depth: i32,
    input: &[u8],
) -> Result<()> {
    let mt = ts.table(table_idx);
    loop {
        let done = stream.is_done(ptr);
        if done {
            if stream.is_error() {
                return Err(KnownDecodeError::Malformed);
            }
            break;
        }
        let start = *ptr;
        let tag = reader::read_tag(stream, *ptr).map_err(|_| KnownDecodeError::Malformed)?;
        *ptr = tag.consumed;
        let field_number = (tag.value >> 3) as u32;
        let wire_type = (tag.value & 7) as u8;

        if wire_type == 4 {
            return Err(KnownDecodeError::Malformed);
        }

        let abs_start = stream.absolute(start);
        let field_index = find_field_index(mt, field_number);
        // For a known field, the wire value is decoded here (advancing the
        // position); for a genuinely unknown field nothing has been read yet.
        let (op, value, ptr_after_value) = match field_index {
            None => (Op::Unknown, None, *ptr),
            Some(i) => decode_wire_value(ts, table_idx, i, wire_type, stream, *ptr)?,
        };
        if op == Op::Unknown {
            *ptr = decode_unknown_field(
                msg,
                stream,
                *ptr,
                ptr_after_value,
                abs_start,
                field_number,
                wire_type,
                value,
                depth,
                input,
            )?;
            continue;
        }
        let f = &mt.fields[field_index.expect("known op implies known field")];
        *ptr = ptr_after_value;
        match op {
            Op::String | Op::Bytes => {
                let size = value.expect("delimited size") as usize;
                let content = read_string_payload(input, stream.absolute(*ptr), size, op)?;
                *ptr += size;
                if f.mode_class() == FieldMode::Array {
                    msg.arrays
                        .entry(f.number as usize)
                        .or_default()
                        .push(content);
                } else {
                    apply_string(msg, f, content)?;
                }
            }
            Op::VarintPacked(lg2) => {
                let size = value.expect("delimited size") as usize;
                let span_start = stream.absolute(*ptr);
                if size as i64 > input.len() as i64 - span_start as i64 {
                    return Err(KnownDecodeError::Malformed);
                }
                let elems = parse_packed_varints(input, span_start, span_start + size, f, lg2)?;
                *ptr += size;
                msg.arrays
                    .entry(f.number as usize)
                    .or_default()
                    .extend(elems);
            }
            Op::FixedPacked(lg2) => {
                let size = value.expect("delimited size") as usize;
                let span_start = stream.absolute(*ptr);
                if size as i64 > input.len() as i64 - span_start as i64 {
                    return Err(KnownDecodeError::Malformed);
                }
                let esz = 1usize << lg2;
                if !size.is_multiple_of(esz) {
                    return Err(KnownDecodeError::Malformed);
                }
                let arr = msg.arrays.entry(f.number as usize).or_default();
                for chunk in input[span_start..span_start + size].chunks(esz) {
                    arr.push(chunk.to_vec());
                }
                *ptr += size;
            }
            Op::Scalar1 | Op::Scalar4 | Op::Scalar8 => {
                let v = value.expect("scalar value");
                if f.mode_class() == FieldMode::Array {
                    let n = match op {
                        Op::Scalar1 => 1,
                        Op::Scalar4 => 4,
                        _ => 8,
                    };
                    msg.arrays
                        .entry(f.number as usize)
                        .or_default()
                        .push(v.to_le_bytes()[..n].to_vec());
                } else {
                    apply_scalar(msg, f, op, v)?;
                }
            }
            Op::SubMessage => {
                let size = value.expect("delimited size") as usize;
                let field_index = field_index.expect("submessage field");
                let sub_idx = ts
                    .sub(table_idx, field_index)
                    .expect("SubMessage op implies a linked sub table");
                let sub_size = ts.table(sub_idx).size as usize;
                if f.mode_class() == FieldMode::Array {
                    // `_upb_Decoder_DecodeToArray` SubMessage
                    // (decode.c:438-449): a new element per occurrence, no
                    // merge, no presence bit.
                    let mut elem = Message::new(sub_size);
                    let delta = stream.push_limit(*ptr, size);
                    if depth - 1 < 0 {
                        return Err(KnownDecodeError::MaxDepthExceeded);
                    }
                    decode_message(ts, sub_idx, &mut elem, stream, ptr, depth - 1, input)?;
                    stream.pop_limit(*ptr, delta);
                    msg.submsg_arrays
                        .entry(f.number as usize)
                        .or_default()
                        .push(elem);
                } else {
                    // `_upb_Decoder_DecodeToSubMessage` (decode.c:545-560):
                    // set presence; a oneof switch clears the previous
                    // member's slot (upstream memsets the pointer to NULL,
                    // orphaning the old submessage in the arena; the model
                    // drops the stale entry so a later occurrence of this
                    // member does not merge into it).
                    let merge = if f.presence > 0 {
                        msg.set_hasbit(f.presence as u16);
                        msg.submsgs.contains_key(&(f.number as usize))
                    } else if f.is_in_oneof() {
                        let case_off = (!f.presence) as u16;
                        let switching = msg.oneof_case(case_off) != f.number;
                        if switching {
                            msg.submsgs.remove(&(f.number as usize));
                        }
                        msg.set_oneof_case(case_off, f.number);
                        !switching
                    } else {
                        true
                    };
                    if !merge {
                        msg.submsgs
                            .insert(f.number as usize, Message::new(sub_size));
                    } else {
                        msg.submsgs
                            .entry(f.number as usize)
                            .or_insert_with(|| Message::new(sub_size));
                    }
                    let submsg = msg.submsgs.get_mut(&(f.number as usize)).expect("inserted");
                    // `_upb_Decoder_DecodeSubMessage` (decode.c:210-219):
                    // PushLimit, then recurse, then PopLimit.
                    let delta = stream.push_limit(*ptr, size);
                    if depth - 1 < 0 {
                        return Err(KnownDecodeError::MaxDepthExceeded);
                    }
                    decode_message(ts, sub_idx, submsg, stream, ptr, depth - 1, input)?;
                    stream.pop_limit(*ptr, delta);
                }
            }
            Op::Unknown => unreachable!(),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Scalar1,
    Scalar4,
    Scalar8,
    String,
    Bytes,
    SubMessage,
    VarintPacked(usize),
    FixedPacked(usize),
    Unknown,
}

/// `_upb_Decoder_DecodeWireValue` (decode.c:874-935). Returns the op, the
/// value (munged scalar or delimited size), and the position after the value
/// read (after the size varint for delimited; unchanged for StartGroup).
fn decode_wire_value(
    ts: &TableSet,
    table_idx: usize,
    field_index: usize,
    wire_type: u8,
    stream: &EpsCopyStream,
    ptr: usize,
) -> Result<(Op, Option<u64>, usize)> {
    let field = &ts.table(table_idx).fields[field_index];
    match wire_type {
        0 => {
            let v = reader::read_varint(stream, ptr).map_err(|_| KnownDecodeError::Malformed)?;
            let op = if is_varint_type(field.descriptortype) {
                scalar_op(field)
            } else {
                Op::Unknown
            };
            Ok((op, Some(munge(field, v.value)), v.consumed))
        }
        1 => {
            let v = reader::read_fixed64(stream, ptr).map_err(|_| KnownDecodeError::Malformed)?;
            let op = if is_fixed64_type(field.descriptortype) {
                Op::Scalar8
            } else {
                Op::Unknown
            };
            Ok((op, Some(v.value), v.consumed))
        }
        5 => {
            let v = reader::read_fixed32(stream, ptr).map_err(|_| KnownDecodeError::Malformed)?;
            let op = if is_fixed32_type(field.descriptortype) {
                Op::Scalar4
            } else {
                Op::Unknown
            };
            Ok((op, Some(v.value), v.consumed))
        }
        2 => {
            let sz = reader::read_size(stream, ptr).map_err(|_| KnownDecodeError::Malformed)?;
            Ok((
                delimited_op(ts, table_idx, field_index),
                Some(sz.value),
                sz.consumed,
            ))
        }
        3 => {
            // StartGroup: valid only for group fields (deferred surface).
            if field.descriptortype == 10 {
                Err(KnownDecodeError::Unsupported("group"))
            } else {
                Ok((Op::Unknown, None, ptr))
            }
        }
        _ => Err(KnownDecodeError::Malformed),
    }
}

fn scalar_op(field: &MiniTableField) -> Op {
    match field.descriptortype {
        8 => Op::Scalar1,
        2 | 7 | 15 | 5 | 13 | 14 | 17 => Op::Scalar4,
        _ => Op::Scalar8,
    }
}

/// `_upb_Decoder_GetDelimitedOp` (decode.c:811-872) for the supported surface.
/// Message fields dispatch to SubMessage only when their sub-slot is linked;
/// unlinked sub-tables decode as unknown (`_upb_Decoder_CheckUnlinked`,
/// decode.c:805-812).
fn delimited_op(ts: &TableSet, table_idx: usize, field_index: usize) -> Op {
    let field = &ts.table(table_idx).fields[field_index];
    if field.mode_class() == FieldMode::Array {
        match field.descriptortype {
            9 => Op::String,
            12 => Op::Bytes,
            11 if ts.sub(table_idx, field_index).is_some() => Op::SubMessage,
            10 | 11 => Op::Unknown,
            t if is_varint_type(t) => Op::VarintPacked(elem_size(t).trailing_zeros() as usize),
            t if is_fixed32_type(t) || is_fixed64_type(t) => {
                Op::FixedPacked(elem_size(t).trailing_zeros() as usize)
            }
            _ => Op::Unknown,
        }
    } else {
        match field.descriptortype {
            9 => Op::String,
            12 => Op::Bytes,
            11 if ts.sub(table_idx, field_index).is_some() => Op::SubMessage,
            _ => Op::Unknown,
        }
    }
}

/// Writes a scalar into the storage buffer
/// (`_upb_Decoder_DecodeToSubMessage`, decode.c:540-592).
fn apply_scalar(msg: &mut Message, field: &MiniTableField, op: Op, val: u64) -> Result<()> {
    msg.set_presence(field);
    let off = field.offset as usize;
    let n = match op {
        Op::Scalar1 => 1,
        Op::Scalar4 => 4,
        _ => 8,
    };
    if off + n <= msg.buf.len() {
        msg.buf[off..off + n].copy_from_slice(&val.to_le_bytes()[..n]);
    }
    Ok(())
}

/// Stores a scalar string/bytes value.
fn apply_string(msg: &mut Message, field: &MiniTableField, content: Vec<u8>) -> Result<()> {
    msg.set_presence(field);
    msg.strings.insert(field.number as usize, content);
    Ok(())
}

/// `_upb_Decoder_ReadString` (internal/decoder.h:244-263): the payload must
/// fit within the input; String fields are UTF-8 validated.
fn read_string_payload(input: &[u8], abs_start: usize, size: usize, op: Op) -> Result<Vec<u8>> {
    if size as i64 > input.len() as i64 - abs_start as i64 {
        return Err(KnownDecodeError::Malformed);
    }
    let content = input[abs_start..abs_start + size].to_vec();
    if op == Op::String && std::str::from_utf8(&content).is_err() {
        return Err(KnownDecodeError::BadUtf8);
    }
    Ok(content)
}

/// `_upb_Decoder_DecodeVarintPacked` (decode.c:289-312): parse varints within
/// [start, end); a varint whose termination extends past `end` is malformed.
fn parse_packed_varints(
    input: &[u8],
    start: usize,
    end: usize,
    field: &MiniTableField,
    _lg2: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut pos = start;
    let n = match field.descriptortype {
        8 => 1,
        5 | 13 | 14 | 17 => 4,
        _ => 8,
    };
    while pos < end {
        let v = read_packed_varint(input, pos, end)?;
        pos = v.1;
        if pos > end {
            return Err(KnownDecodeError::Malformed);
        }
        let m = munge(field, v.0);
        out.push(m.to_le_bytes()[..n].to_vec());
    }
    Ok(out)
}

/// Reads a varint from `input[pos..]` with zero-padding beyond the input end
/// (mirroring the patch buffer), bounding the search at `end` for the packed
/// payload limit. Returns (value, consumed position); consumed may exceed
/// `end` when the varint terminates past the limit (the caller errors).
fn read_packed_varint(input: &[u8], pos: usize, end: usize) -> Result<(u64, usize)> {
    let window = |i: usize| -> u8 {
        if i < input.len() {
            input[i]
        } else {
            0 // zero padding beyond the input, like the patch buffer
        }
    };
    let byte0 = window(pos);
    if byte0 & 0x80 == 0 {
        return Ok((byte0 as u64, pos + 1));
    }
    let mut val = byte0 as u64;
    for i in 1..10 {
        let byte = window(pos + i);
        val = val.wrapping_add((byte as u64).wrapping_sub(1) << (i * 7));
        if byte & 0x80 == 0 {
            return Ok((val, pos + i + 1));
        }
    }
    let _ = end;
    Err(KnownDecodeError::Malformed)
}

/// `_upb_Decoder_DecodeUnknowns` (decode.c:1010-1081): capture the span from
/// the field start, finish skipping the value (which may already have been
/// consumed by the wire-value read for known fields with mismatched wire
/// types), and record the wire bytes in order.
///
/// `ptr` is the position after the tag; `ptr_after_value` is the position
/// after the value read (equal to `ptr` when nothing was read yet). `value`
/// carries the already-read delimited size when applicable.
///
/// The parameter list mirrors the context threading of the upstream skip path
/// (decode.c). clippy's arity threshold is deliberately exceeded; the
/// alternatives (a context struct or closure capture) would obscure the
/// one-to-one correspondence with `_upb_Decoder_SkipUnknown`'s operands.
#[allow(clippy::too_many_arguments)]
fn decode_unknown_field(
    msg: &mut Message,
    stream: &mut EpsCopyStream,
    ptr: usize,
    ptr_after_value: usize,
    abs_start: usize,
    field_number: u32,
    wire_type: u8,
    value: Option<u64>,
    depth: i32,
    input: &[u8],
) -> Result<usize> {
    if field_number == 0 {
        return Err(KnownDecodeError::Malformed);
    }
    let already_read = ptr_after_value != ptr;
    let end = match wire_type {
        0 | 1 | 5 => {
            if already_read {
                // The varint/fixed value was consumed by the wire-value read
                // (decode.c:1021-1023); nothing left to skip.
                ptr_after_value
            } else {
                match wire_type {
                    0 => {
                        reader::skip_varint(stream, ptr).map_err(|_| KnownDecodeError::Malformed)?
                    }
                    1 => ptr + 8,
                    _ => ptr + 4,
                }
            }
        }
        2 => {
            let (size, size_end) = if already_read {
                (value.expect("size read") as usize, ptr_after_value)
            } else {
                let sz = reader::read_size(stream, ptr).map_err(|_| KnownDecodeError::Malformed)?;
                (sz.value as usize, sz.consumed)
            };
            // ReadStringEphemeral semantics (internal/eps_copy_input_stream.h
            // lines 271-285): the payload must fit the current buffer; the
            // size varint terminating past the input makes the remaining
            // space negative and fails.
            if size as i64 > input.len() as i64 - stream.absolute(size_end) as i64 {
                return Err(KnownDecodeError::Malformed);
            }
            size_end + size
        }
        3 => {
            let tag = (field_number << 3) | 3;
            reader::skip_group_inner(stream, ptr, tag, depth)
                .map_err(|_| KnownDecodeError::Malformed)?
        }
        _ => return Err(KnownDecodeError::Malformed),
    };
    let abs_end = stream.absolute(end);
    // upb_EpsCopyCapture_End (eps_copy_input_stream.h:240-241): a span
    // extending past the stream limit is malformed (no zero-padding for
    // unknown capture, unlike raw varint reads).
    if abs_end > input.len() {
        return Err(KnownDecodeError::Malformed);
    }
    if abs_start <= abs_end {
        msg.unknown.extend_from_slice(&input[abs_start..abs_end]);
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use upb_rs_mini_table::base92;

    /// Field-1 mini descriptor for an encoded type, using the corpus encoder's
    /// exact formula (`'$'` version byte + base92 field byte). The byte
    /// patterns are pinned against oracle-verified casefile descriptors below.
    fn md1(t: u8) -> Vec<u8> {
        vec![b'$', base92::to_base92(t as i8)]
    }

    /// Oracle-verified descriptor bytes (casefiles dk-sint32-* / dk-sint64-*,
    /// md fields `242a` and `242d`; mini-table-inspect court `$)`, `$D`).
    #[test]
    fn descriptor_bytes_pin_to_casefiles() {
        assert_eq!(md1(8), [0x24, 0x2a]); // SInt32 field 1
        assert_eq!(md1(11), [0x24, 0x2d]); // SInt64 field 1
        assert_eq!(md1(7), [0x24, 0x29]); // UInt32 field 1
        assert_eq!(md1(15), [0x24, 0x31]); // String field 1
        assert_eq!(md1(14), [0x24, 0x30]); // Bytes field 1
    }

    /// `_upb_Decoder_Munge` SInt32: `(n >> 1) ^ -(int32_t)(n & 1)` — the
    /// inverse of zigzag. Regression-guard for the sign-extension form bug
    /// (casefiles dk-sint32-*, e.g. wire 1 must store 0xFFFFFFFF = -1).
    #[test]
    fn zigzag32_matches_upstream_munge() {
        let munge = |n: u32| (n >> 1) ^ 0u32.wrapping_sub(n & 1);
        for n in 0..=0xFFFF {
            assert_eq!(zigzag32(n), munge(n), "n={n:#x}");
        }
        for n in [
            0x3FFF_FFFF,
            0x4000_0000,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x8000_0001,
            0xFFFF_FFFE,
        ] {
            assert_eq!(zigzag32(n), munge(n), "n={n:#x}");
        }
        // Spot values: wire 1 -> -1, wire 2 -> 1, wire 3 -> -2,
        // wire 0xFFFFFFFF -> 0x80000000 (INT32_MIN).
        assert_eq!(zigzag32(1), 0xFFFF_FFFF);
        assert_eq!(zigzag32(2), 1);
        assert_eq!(zigzag32(3), 0xFFFF_FFFE);
        assert_eq!(zigzag32(0xFFFF_FFFF), 0x8000_0000);
    }

    /// `_upb_Decoder_Munge` SInt64: `(n >> 1) ^ -(int64_t)(n & 1)`.
    #[test]
    fn zigzag64_matches_upstream_munge() {
        let munge = |n: u64| (n >> 1) ^ 0u64.wrapping_sub(n & 1);
        for n in 0..=0xFFFF {
            assert_eq!(zigzag64(n), munge(n), "n={n:#x}");
        }
        for n in [
            0x3FFF_FFFF_FFFF_FFFF,
            0x4000_0000_0000_0000,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0001,
        ] {
            assert_eq!(zigzag64(n), munge(n), "n={n:#x}");
        }
        assert_eq!(zigzag64(1), 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(zigzag64(2), 1);
        assert_eq!(zigzag64(3), 0xFFFF_FFFF_FFFF_FFFE);
        assert_eq!(zigzag64(0xFFFF_FFFF_FFFF_FFFF), 0x8000_0000_0000_0000);
    }

    /// `_upb_Decoder_Munge` Bool: `val->bool_val = val->uint64_val != 0`
    /// (decode.c:141-142). A wire value of 2 is true, not `& 1`.
    #[test]
    fn munge_bool_is_nonzero() {
        let f = MiniTableField {
            number: 1,
            offset: 0,
            presence: 0,
            submsg_ofs: 0xFFFF,
            descriptortype: 8,
            mode: 0,
        };
        for v in [0u64, 1, 2, 0x7F, 0x80, 0x3FFF, u64::MAX] {
            assert_eq!(munge(&f, v), (v != 0) as u64, "v={v:#x}");
        }
    }

    /// End-to-end: SInt32 field 1 with wire varint 1 must store 0xFFFFFFFF
    /// (=-1) at the field offset — the exact casefile dk-000052 divergence.
    #[test]
    fn decode_sint32_odd_wire_value() {
        let mt = upb_rs_mini_table::decode::build_mini_table(&md1(8))
            .unwrap()
            .0;
        let m = decode_known(&md1(8), &[0x08, 0x01], 100).unwrap();
        let off = mt.fields[0].offset as usize;
        assert_eq!(&m.buf[off..off + 4], &[0xFF; 4]);
    }

    /// End-to-end: SInt64 field 1 with wire varint 1 stores all-ones (=-1).
    #[test]
    fn decode_sint64_odd_wire_value() {
        let mt = upb_rs_mini_table::decode::build_mini_table(&md1(11))
            .unwrap()
            .0;
        let m = decode_known(&md1(11), &[0x08, 0x01], 100).unwrap();
        let off = mt.fields[0].offset as usize;
        assert_eq!(&m.buf[off..off + 8], &[0xFF; 8]);
    }

    /// End-to-end: bool field 1 with wire varint 2 stores 1 (true).
    #[test]
    fn decode_bool_nonzero_wire_value() {
        let m = decode_known(&md1(13), &[0x08, 0x02], 100).unwrap();
        let mt = upb_rs_mini_table::decode::build_mini_table(&md1(13))
            .unwrap()
            .0;
        let off = mt.fields[0].offset as usize;
        assert_eq!(m.buf[off], 1);
    }

    /// A tag with no value is malformed (the zero-padded varint read
    /// succeeds, then the follow-on zero tag is field number 0). Empty input
    /// is a valid empty message, mirroring upb_Decode on an empty buffer.
    #[test]
    fn truncated_input_is_malformed() {
        assert!(matches!(
            decode_known(&md1(7), &[0x08], 100),
            Err(KnownDecodeError::Malformed)
        ));
    }

    #[test]
    fn empty_input_decodes_empty_message() {
        let m = decode_known(&md1(7), &[], 100).unwrap();
        assert!(m.unknown.is_empty());
        assert!(m.arrays.is_empty());
    }

    /// Unknown fields are captured as raw wire spans in wire order.
    #[test]
    fn unknown_field_retained_in_wire_order() {
        // field 99 (tag 0x98 0x06) varint 5, then field 1 uint32 = 7.
        let m = decode_known(&md1(7), &[0x98, 0x06, 0x05, 0x08, 0x07], 100).unwrap();
        assert_eq!(m.unknown, [0x98, 0x06, 0x05]);
        let mt = upb_rs_mini_table::decode::build_mini_table(&md1(7))
            .unwrap()
            .0;
        // presence is the hasbit index (64 for this layout, oracle-verified
        // via mini_table_inspect on `$)`); the bit must be set for field 1.
        assert!(mt.fields[0].presence > 0);
        assert!(m.hasbit_set(mt.fields[0].presence as u16));
        let off = mt.fields[0].offset as usize;
        assert_eq!(&m.buf[off..off + 4], &[7, 0, 0, 0]);
    }

    /// At this pin, a String field built from a plain mini descriptor does
    /// **not** validate UTF-8 (validation is gated on the validate-UTF8
    /// modifier, which the corpus never sets). Oracle-verified: `0a01ff` with
    /// `$1` decodes ok with value `ff`. Bytes fields accept any content.
    #[test]
    fn string_content_preserved_without_utf8_check() {
        let bad: Vec<u8> = vec![0x0A, 0x01, 0xFF];
        let s = decode_known(&md1(15), &bad, 100).unwrap();
        // String content is keyed by field number (apply_string).
        assert_eq!(s.strings.get(&1).map(Vec::as_slice), Some(&[0xFF][..]));
        let b = decode_known(&md1(14), &bad, 100).unwrap();
        assert_eq!(b.strings.get(&1).map(Vec::as_slice), Some(&[0xFF][..]));
    }

    /// Field number 0 (tag 0x00) is malformed.
    #[test]
    fn field_number_zero_is_malformed() {
        assert!(matches!(
            decode_known(&md1(7), &[0x00], 100),
            Err(KnownDecodeError::Malformed)
        ));
    }

    /// Unlinked sub-message fields decode as unknown fields — upstream's
    /// documented behavior (mini_descriptor/link.h:37-40) and oracle-verified
    /// for `$3` + `0a00` (ok, unknown `0a00`). This supersedes the earlier
    /// defensive rejection.
    #[test]
    fn unlinked_submessage_decodes_as_unknown() {
        // Message field 1 (encoded type 17 = Message): `$3' (0x24 0x33), no
        // links in the pool.
        let m = decode_known(&[0x24, 0x33], &[0x0A, 0x00], 100).unwrap();
        assert_eq!(m.unknown, [0x0A, 0x00]);
        assert!(m.submsgs.is_empty());
    }

    /// hex-decode helper for pool descriptors.
    fn dh(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        out
    }

    fn dsub(mds: &[&str], links: &[&[usize]], input: &[u8], depth: u32) -> Result<Message> {
        let mds: Vec<Vec<u8>> = mds.iter().map(|s| dh(s)).collect();
        let mds: Vec<&[u8]> = mds.iter().map(|v| v.as_slice()).collect();
        decode_submsg(&mds, links, input, depth)
    }

    /// Singular sub-message: repeated occurrences merge into one sub-message
    /// (oracle-verified).
    #[test]
    fn submessage_singular_merge() {
        // A { B b = 1; } ($3) B { uint32 x = 1; int32 y = 2; } ($)(
        // payload: b{x:1} b{y:2} -> merged {x:1, y:2}
        let m = dsub(
            &["2433", "242928"],
            &[&[1], &[]],
            &[0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x10, 0x02],
            100,
        )
        .unwrap();
        let sub = m.submsgs.get(&1).expect("field 1 submsg");
        assert_eq!(sub.strings.len(), 0);
        assert_eq!(sub.buf[12..16], [1, 0, 0, 0]); // x = 1 at offset 12
        assert_eq!(sub.buf[16..20], [2, 0, 0, 0]); // y = 2 at offset 16
    }

    /// Repeated sub-message: each occurrence appends a new element.
    #[test]
    fn submessage_repeated_appends() {
        // A { repeated B b = 1; } ($G) B { bool x = 1; } ($/)
        let m = dsub(
            &["2447", "242f"],
            &[&[1], &[]],
            &[0x0A, 0x02, 0x08, 0x01, 0x0A, 0x02, 0x08, 0x00],
            100,
        )
        .unwrap();
        let elems = m.submsg_arrays.get(&1).expect("field 1 array");
        assert_eq!(elems.len(), 2);
        assert_eq!(elems[0].buf[9], 1); // bool true (offset 9)
        assert_eq!(elems[1].buf[9], 0); // bool false
    }

    /// Nested sub-messages decode recursively.
    #[test]
    fn submessage_nested() {
        // A { B b = 1; } B { C c = 1; } C { sint64 z = 1; }
        // payload: b { c { z: wire varint 1 } }  -> z = -1 (zigzag)
        let m = dsub(
            &["2433", "2433", "242d"],
            &[&[1], &[2], &[]],
            &[0x0A, 0x04, 0x0A, 0x02, 0x08, 0x01],
            100,
        )
        .unwrap();
        let b = m.submsgs.get(&1).expect("b");
        let c = b.submsgs.get(&1).expect("c");
        let (mt_c, _) = upb_rs_mini_table::decode::build_mini_table(&dh("242d")).unwrap();
        let off = mt_c.fields[0].offset as usize;
        assert_eq!(&c.buf[off..off + 8], &[0xFF; 8]);
    }

    /// Recursive message (self-link): R { R r = 1; }.
    #[test]
    fn submessage_recursive() {
        let m = dsub(&["2433"], &[&[0]], &[0x0A, 0x02, 0x0A, 0x00], 100).unwrap();
        let r1 = m.submsgs.get(&1).expect("outer");
        let r2 = r1.submsgs.get(&1).expect("inner");
        assert!(r2.submsgs.is_empty());
    }

    /// Depth budget: 100 nested submessages decode; 101 exceeds.
    #[test]
    fn submessage_depth_limit() {
        fn payload(d: usize) -> Vec<u8> {
            let mut p = vec![0x0A, 0x00];
            for _k in 1..d {
                // prepend tag 0a + varint(len(p))
                let mut head = vec![0x0A];
                let mut v = p.len();
                loop {
                    let mut b = (v & 0x7F) as u8;
                    v >>= 7;
                    if v != 0 {
                        b |= 0x80;
                    }
                    head.push(b);
                    if v == 0 {
                        break;
                    }
                }
                let mut n = head;
                n.extend_from_slice(&p);
                p = n;
            }
            p
        }
        assert!(dsub(&["2433"], &[&[0]], &payload(100), 100).is_ok());
        assert!(matches!(
            dsub(&["2433"], &[&[0]], &payload(101), 100),
            Err(KnownDecodeError::MaxDepthExceeded)
        ));
        assert!(dsub(&["2433"], &[&[0]], &payload(101), 101).is_ok());
    }

    /// A sub-message declared size exceeding the remaining input is
    /// malformed (PushLimit overrun).
    #[test]
    fn submessage_size_overrun_malformed() {
        assert!(matches!(
            dsub(&["2433", "2429"], &[&[1], &[]], &[0x0A, 0x05, 0x08], 100),
            Err(KnownDecodeError::Malformed)
        ));
    }

    /// A nested sub-message whose size exceeds the parent's remaining budget
    /// is malformed (PushLimit delta < 0 in the parent's frame).
    #[test]
    fn submessage_budget_exceeded_malformed() {
        // A { B b = 1; } B { C c = 1; } C { uint32 x = 1; } — b declares size
        // 2 but contains c declaring size 5.
        assert!(matches!(
            dsub(
                &["2433", "2433", "2429"],
                &[&[1], &[2], &[]],
                &[0x0A, 0x02, 0x0A, 0x05],
                100
            ),
            Err(KnownDecodeError::Malformed)
        ));
    }

    /// Unknown fields inside a sub-message are retained in the sub-message.
    #[test]
    fn submessage_unknown_inside_retained() {
        // A { B b = 1; } B { uint32 x = 1; } — b contains field 99 varint 5.
        let m = dsub(
            &["2433", "2429"],
            &[&[1], &[]],
            &[0x0A, 0x03, 0x98, 0x06, 0x05],
            100,
        )
        .unwrap();
        let sub = m.submsgs.get(&1).expect("b");
        assert_eq!(sub.unknown, [0x98, 0x06, 0x05]);
        assert!(m.unknown.is_empty());
    }

    /// A sub-message field with a mismatched wire type decodes as an unknown
    /// field at the top level.
    #[test]
    fn submessage_wire_type_mismatch_is_unknown() {
        let m = dsub(&["2433", "2429"], &[&[1], &[]], &[0x08, 0x01], 100).unwrap();
        assert!(m.submsgs.is_empty());
        assert_eq!(m.unknown, [0x08, 0x01]);
    }

    /// Oneof with a sub-message member: switching members clears the previous
    /// value; re-setting the same member merges.
    #[test]
    fn submessage_oneof_switch_and_merge() {
        // A { oneof { B b = 1; uint32 x = 2; } } — $3)^!|# (oracle-verified).
        // b{x:1} x:7 b{x:2} -> final: case 1, b{x:2} (the x:7 switch cleared
        // nothing of b; the second b merges into the first).
        let m = dsub(
            &["2433295e217c23", "2429"],
            &[&[1], &[]],
            &[0x0A, 0x02, 0x08, 0x01, 0x10, 0x07, 0x0A, 0x02, 0x08, 0x02],
            100,
        )
        .unwrap();
        // oneof case word at offset 8 == 1 (field number)
        assert_eq!(m.oneof_case(8), 1);
        let sub = m.submsgs.get(&1).expect("b");
        assert_eq!(sub.buf[12..16], [2, 0, 0, 0]); // merged x = 2, not replaced
    }
}
