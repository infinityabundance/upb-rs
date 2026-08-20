//! Mini descriptor decoding and mini table layout, mirroring
//! `upb/mini_descriptor/decode.c` at the pinned commit
//! `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`.
//!
//! Grammar (wire_constants.h): a version tag (`$` message, `%` map,
//! `&` message set) followed by field-type characters (base92 values 0..18,
//! +20 for repeated), modifier varints (`L`..`[`), skip varints (`_`..`~`),
//! an optional oneof section introduced by `^`, and `~`/`|` oneof
//! separators. Layout follows upb_MtDecoder_AssignHasbits /
//! CalculateAlignments / AssignOffsets / AllocateSubs.

use crate::base92::{self, DecodeError};
use crate::model::*;

// kUpb_Reserved_Hasbytes = sizeof(struct upb_Message) = 8 on 64-bit
// (upb/message/internal/types.h:25-30).
const RESERVED_HASBYTES: u32 = 8;
const RESERVED_HASBITS: i32 = (RESERVED_HASBYTES * 8) as i32; // 64
const ONE_OF_ITEM_INDEX_SENTINEL: u16 = u16::MAX;
const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
const REP_TABLE_LEN: usize = 19; // sizeof(kUpb_EncodedToFieldRep)
const TYPE_TABLE_LEN: usize = 19; // sizeof(kUpb_EncodedToType)

// Presence classes stored transiently in field.offset during parsing
// (decode.c:102-111).
const NO_PRESENCE: u16 = 0;
const HASBIT_PRESENCE: u16 = 1;
const REQUIRED_PRESENCE: u16 = 2;
const ONEOF_BASE: u16 = 3;

// Encoded type constants (mini_descriptor/internal/wire_constants.h:16-38).
const ENC_DOUBLE: i8 = 0;
const ENC_FLOAT: i8 = 1;
const ENC_FIXED32: i8 = 2;
const ENC_FIXED64: i8 = 3;
const ENC_SFIXED32: i8 = 4;
const ENC_SFIXED64: i8 = 5;
const ENC_INT32: i8 = 6;
const ENC_UINT32: i8 = 7;
const ENC_SINT32: i8 = 8;
const ENC_INT64: i8 = 9;
const ENC_UINT64: i8 = 10;
const ENC_SINT64: i8 = 11;
const ENC_OPEN_ENUM: i8 = 12;
const ENC_BOOL: i8 = 13;
const ENC_BYTES: i8 = 14;
const ENC_STRING: i8 = 15;
const ENC_GROUP: i8 = 16;
const ENC_MESSAGE: i8 = 17;
const ENC_CLOSED_ENUM: i8 = 18;
const ENC_REPEATED_BASE: i8 = 20;

// Encoded field modifiers (wire_constants.h:40-45).
const MOD_FLIP_PACKED: u32 = 1 << 0;
const MOD_IS_REQUIRED: u32 = 1 << 1;
const MOD_IS_PROTO3_SINGULAR: u32 = 1 << 2;
const MOD_FLIP_VALIDATE_UTF8: u32 = 1 << 3;

// Message modifiers (mini_descriptor/internal/modifiers.h:24-28).
const MSG_MOD_VALIDATE_UTF8: u32 = 1 << 0;
const MSG_MOD_DEFAULT_IS_PACKED: u32 = 1 << 1;
const MSG_MOD_IS_EXTENDABLE: u32 = 1 << 2;

// Encoded char ranges (wire_constants.h:47-60).
const CHAR_MAX_FIELD: u8 = b'I';
const CHAR_MIN_MODIFIER: u8 = b'L';
const CHAR_MAX_MODIFIER: u8 = b'[';
const CHAR_END: u8 = b'^';
const CHAR_MIN_SKIP: u8 = b'_';
const CHAR_MAX_SKIP: u8 = b'~';
const CHAR_ONEOF_SEPARATOR: u8 = b'~';
const CHAR_FIELD_SEPARATOR: u8 = b'|';
const CHAR_MIN_ONEOF_FIELD: u8 = b' ';
const CHAR_MAX_ONEOF_FIELD: u8 = b'b';

// Version tags (wire_constants.h:63-68).
const VERSION_MAP: u8 = b'%';
const VERSION_MESSAGE: u8 = b'$';
const VERSION_MESSAGE_SET: u8 = b'&';

/// `kUpb_EncodedToType` (decode.c:155-175).
fn encoded_to_type(enc: i8) -> u8 {
    match enc {
        ENC_DOUBLE => 1,
        ENC_FLOAT => 2,
        ENC_INT64 => 3,
        ENC_UINT64 => 4,
        ENC_INT32 => 5,
        ENC_FIXED64 => 6,
        ENC_FIXED32 => 7,
        ENC_BOOL => 8,
        ENC_STRING => 9,
        ENC_GROUP => 10,
        ENC_MESSAGE => 11,
        ENC_BYTES => 12,
        ENC_UINT32 => 13,
        ENC_OPEN_ENUM | ENC_CLOSED_ENUM => 14,
        ENC_SFIXED32 => 15,
        ENC_SFIXED64 => 16,
        ENC_SINT32 => 17,
        ENC_SINT64 => 18,
        _ => 0, // invalid; the caller rejects types >= TYPE_TABLE_LEN
    }
}

/// `kUpb_EncodedToFieldRep` (decode.c:180-198).
fn encoded_to_field_rep(enc: i8) -> Option<FieldRep> {
    Some(match enc {
        ENC_DOUBLE | ENC_FIXED64 | ENC_INT64 | ENC_UINT64 | ENC_SFIXED64 | ENC_SINT64 => {
            FieldRep::EightByte
        }
        ENC_FLOAT | ENC_FIXED32 | ENC_SFIXED32 | ENC_INT32 | ENC_UINT32 | ENC_SINT32
        | ENC_OPEN_ENUM | ENC_CLOSED_ENUM => FieldRep::FourByte,
        ENC_BOOL => FieldRep::OneByte,
        ENC_STRING | ENC_BYTES => FieldRep::StringView,
        _ => return None,
    })
}

fn is_packable(field_type: u8) -> bool {
    // upb_FieldType_IsPackable (upb/base/descriptor_constants.h:94-103):
    // String(9), Bytes(12), Message(11), Group(10) are not packable.
    !matches!(field_type, 9..=12)
}

/// Oneof layout item (decode.c:69-76).
#[derive(Debug, Clone, Copy)]
struct OneofItem {
    field_index: u16,
    rep: u8,
}

struct Decoder {
    msg_modifiers: u32,
    last_field_number: u32,
    last_field: Option<usize>,
    need_dense_below: bool,
    dense_below: u8,
    ext: u8,
    required_count: u8,
    rep_counts: [u16; 4],
    oneofs: Vec<OneofItem>,
    sub_count: u32,
    field_bytes: usize,
    fields: Vec<MiniTableField>,
}

/// Builds a mini table from a mini descriptor string. Returns the table and
/// the version tag byte that was consumed (None for an empty descriptor).
pub fn build_mini_table(data: &[u8]) -> Result<(MiniTable, Option<u8>), DecodeError> {
    let mut d = Decoder {
        msg_modifiers: 0,
        last_field_number: 0,
        last_field: None,
        need_dense_below: true,
        dense_below: 0,
        ext: EXT_NON_EXTENDABLE,
        required_count: 0,
        rep_counts: [0; 4],
        oneofs: Vec::new(),
        sub_count: 0,
        field_bytes: 0,
        fields: Vec::new(),
    };
    let mut table = MiniTable {
        size: RESERVED_HASBYTES as u16,
        field_count: 0,
        ext: EXT_NON_EXTENDABLE,
        dense_below: 0,
        required_count: 0,
        fields: Vec::new(),
    };

    // Version tag handling (decode.c:797-820). An empty descriptor is a valid
    // empty message.
    if data.is_empty() {
        finish_table(&mut d, &mut table);
        return Ok((table, None));
    }
    let version = data[0];
    let body = &data[1..];
    match version {
        VERSION_MAP => {
            parse_message(&mut d, &mut table, body)?;
            assign_hasbits(&mut d, &mut table)?;
            parse_map(&mut d, &mut table)?;
        }
        VERSION_MESSAGE => {
            parse_message(&mut d, &mut table, body)?;
            assign_hasbits(&mut d, &mut table)?;
            calculate_alignments(&mut d, &mut table)?;
            assign_offsets(&mut d, &mut table)?;
        }
        VERSION_MESSAGE_SET => {
            parse_message_set(&mut d, &mut table, body)?;
        }
        _ => {
            return Err(DecodeError::Message(format!(
                "Error building mini table: Invalid message version: {}",
                printable(version)
            )))
        }
    }
    finish_table(&mut d, &mut table);
    Ok((table, Some(version)))
}

fn finish_table(d: &mut Decoder, table: &mut MiniTable) {
    table.dense_below = d.dense_below;
    // Merge, never overwrite: parse_map/parse_message_set set table.ext
    // directly (IsMapEntry / IsMessageSet) while the message path sets d.ext
    // (Extendable). Upstream mutates a single table struct; the split state
    // here must combine both contributions.
    table.ext |= d.ext;
    table.required_count = d.required_count;
    allocate_subs(d, table);
}

/// Renders a character the way C's `%c` would for error strings. Bytes
/// outside printable ASCII render as the 6-character literal `\u00xx` (the
/// same convention the oracle uses when embedding the message in JSON), and
/// NUL renders as nothing because an embedded NUL terminates the C status
/// string (upb_Status_SetErrorMessage semantics).
fn printable(ch: u8) -> String {
    if ch == 0 {
        String::new()
    } else if (0x20..=0x7e).contains(&ch) {
        (ch as char).to_string()
    } else {
        format!("\\u00{ch:02x}")
    }
}

fn parse_message(d: &mut Decoder, table: &mut MiniTable, data: &[u8]) -> Result<(), DecodeError> {
    // upb_MtDecoder_Parse (decode.c:466-538).
    let mut i = 0usize;
    while i < data.len() {
        let ch = data[i];
        i += 1;
        // C's `char ch` is signed: bytes >= 0x80 are negative and therefore
        // satisfy `ch <= kUpb_EncodedValue_MaxField`, landing in the field
        // branch with a uint8 ch (producing "Invalid field type: -21").
        let ch_signed = ch as i8;
        if ch_signed <= CHAR_MAX_FIELD as i8 {
            // Note: control characters (ch < ' ') also land here; upstream
            // treats them as an invalid field type (-1) via _upb_FromBase92.
            if table.field_count == u16::MAX {
                return Err(err("Fields in message exceed the limit of 65535"));
            }
            table.field_count += 1;
            let number = d.last_field_number.wrapping_add(1);
            if number == 0 || number > MAX_FIELD_NUMBER {
                return Err(err(&format!("Invalid field number: {number}")));
            }
            d.last_field_number = number;
            let mut field = MiniTableField {
                number,
                offset: 0,
                presence: 0,
                submsg_ofs: NO_SUB,
                descriptortype: 0,
                mode: 0,
            };
            d.last_field = Some(d.fields.len());
            set_field(d, ch, &mut field)?;
            d.fields.push(field);
        } else if (CHAR_MIN_MODIFIER..=CHAR_MAX_MODIFIER).contains(&ch) {
            let (modv, ni) =
                base92::decode_varint(data, i, ch, CHAR_MIN_MODIFIER, CHAR_MAX_MODIFIER)
                    .map_err(err_from)?;
            i = ni;
            match d.last_field {
                Some(fi) => {
                    let field = &mut d.fields[fi];
                    modify_field(modv, field)?;
                }
                None => {
                    if modv & MSG_MOD_IS_EXTENDABLE != 0 {
                        d.ext |= EXT_EXTENDABLE;
                    }
                    d.msg_modifiers = modv;
                }
            }
        } else if ch == CHAR_END {
            i = decode_oneofs(d, data, i)?;
        } else if (CHAR_MIN_SKIP..=CHAR_MAX_SKIP).contains(&ch) {
            if d.need_dense_below {
                d.dense_below = table.field_count as u8;
                d.need_dense_below = false;
            }
            let (skip, ni) = base92::decode_varint(data, i, ch, CHAR_MIN_SKIP, CHAR_MAX_SKIP)
                .map_err(err_from)?;
            i = ni;
            if skip == 0 {
                return Err(err("Invalid skip value: 0"));
            }
            if skip > u32::MAX - d.last_field_number {
                return Err(err("Field number overflow"));
            }
            d.last_field_number += skip;
            d.last_field_number = d.last_field_number.wrapping_sub(1);
        } else {
            return Err(err(&format!("Invalid char: {}", printable(ch))));
        }
    }
    if d.need_dense_below {
        d.dense_below = table.field_count as u8;
    }
    d.field_bytes = align_up(d.fields.len() * 12, 8);
    Ok(())
}

/// `upb_MiniTable_SetField` (decode.c:177-227).
fn set_field(d: &mut Decoder, ch: u8, field: &mut MiniTableField) -> Result<(), DecodeError> {
    // _upb_FromBase92 returns -1 for characters outside the alphabet
    // (including control bytes that pass the `ch <= 'I'` gate).
    let mut typ = base92::from_base92(ch).unwrap_or(-1);
    let pointer_rep = FieldRep::EightByte; // 64-bit platform
    if ch >= base92::to_base92(ENC_REPEATED_BASE) {
        typ -= ENC_REPEATED_BASE;
        field.mode = FieldMode::Array as u8 | ((pointer_rep as u8) << 6);
        field.offset = NO_PRESENCE;
    } else {
        field.mode = FieldMode::Scalar as u8;
        field.offset = HASBIT_PRESENCE;
        if typ == ENC_GROUP || typ == ENC_MESSAGE {
            field.mode |= (pointer_rep as u8) << 6;
        } else if (typ as usize) >= REP_TABLE_LEN {
            // (unsigned long)(-1) >= 19 in C, so control chars land here.
            return Err(err(&format!("Invalid field type: {typ}")));
        } else {
            field.mode |= (encoded_to_field_rep(typ).expect("in-table rep") as u8) << 6;
        }
    }
    if (typ as usize) >= TYPE_TABLE_LEN {
        return Err(err(&format!("Invalid field type: {typ}")));
    }
    set_type_and_sub(d, field, typ);
    Ok(())
}

/// `upb_MiniTable_SetTypeAndSub` (decode.c:123-153).
fn set_type_and_sub(d: &mut Decoder, field: &mut MiniTableField, encoded_type: i8) {
    let is_proto3_enum = encoded_type == ENC_OPEN_ENUM;
    let mut typ = encoded_to_type(encoded_type);
    if is_proto3_enum {
        // Open enums are stored as Int32 with the alternate flag.
        typ = 5; // kUpb_FieldType_Int32
        field.mode |= LABEL_FLAG_ALTERNATE;
    } else if typ == 9 && d.msg_modifiers & MSG_MOD_VALIDATE_UTF8 == 0 {
        // String without UTF-8 validation is stored as Bytes + alternate.
        typ = 12;
        field.mode |= LABEL_FLAG_ALTERNATE;
    }
    field.descriptortype = typ;

    let is_packable_field =
        field.mode_class() == FieldMode::Array && is_packable(field.descriptortype);
    if is_packable_field && d.msg_modifiers & MSG_MOD_DEFAULT_IS_PACKED != 0 {
        field.mode |= LABEL_FLAG_PACKED;
    }

    // Sub assignment: message/group/enum fields reference a sub table entry.
    if matches!(typ, 10 | 11 | 14) {
        field.submsg_ofs = d.sub_count as u16;
        d.sub_count += 1;
    } else {
        field.submsg_ofs = NO_SUB;
    }
}

/// `upb_MtDecoder_ModifyField` (decode.c:229-281).
fn modify_field(field_modifiers: u32, field: &mut MiniTableField) -> Result<(), DecodeError> {
    if field_modifiers & MOD_FLIP_PACKED != 0 {
        let packable = field.mode_class() == FieldMode::Array && is_packable(field.descriptortype);
        if !packable {
            return Err(err(&format!(
                "Cannot flip packed on unpackable field {}",
                field.number
            )));
        }
        field.mode ^= LABEL_FLAG_PACKED;
    }
    if field_modifiers & MOD_FLIP_VALIDATE_UTF8 != 0 {
        if field.descriptortype != 12 || field.mode & LABEL_FLAG_ALTERNATE == 0 {
            return Err(err(&format!(
                "Cannot flip ValidateUtf8 on field {}, type={}, mode={}",
                field.number, field.descriptortype, field.mode
            )));
        }
        field.descriptortype = 9; // kUpb_FieldType_String
        field.mode &= !LABEL_FLAG_ALTERNATE;
    }
    let singular = field_modifiers & MOD_IS_PROTO3_SINGULAR != 0;
    let required = field_modifiers & MOD_IS_REQUIRED != 0;
    if (singular || required) && field.offset != HASBIT_PRESENCE {
        return Err(err(&format!(
            "Invalid modifier(s) for repeated field {}",
            field.number
        )));
    }
    if singular && required {
        return Err(err(&format!(
            "Field {} cannot be both singular and required",
            field.number
        )));
    }
    if singular && (field.descriptortype == 10 || field.descriptortype == 11) {
        return Err(err(&format!(
            "Field {} cannot be a singular submessage",
            field.number
        )));
    }
    if singular {
        field.offset = NO_PRESENCE;
    }
    if required {
        field.offset = REQUIRED_PRESENCE;
    }
    Ok(())
}

/// `upb_MtDecoder_DecodeOneofs` + `_DecodeOneofField` + `_PushOneof`
/// (decode.c:283-414).
fn decode_oneofs(d: &mut Decoder, data: &[u8], mut i: usize) -> Result<usize, DecodeError> {
    let mut item = OneofItem {
        rep: 0,
        field_index: ONE_OF_ITEM_INDEX_SENTINEL,
    };
    while i < data.len() {
        let ch = data[i];
        i += 1;
        if ch == CHAR_FIELD_SEPARATOR {
            // No action (decode.c:399-400).
        } else if ch == CHAR_ONEOF_SEPARATOR {
            push_oneof(d, &mut item)?;
            item.field_index = ONE_OF_ITEM_INDEX_SENTINEL;
        } else {
            let (ni, it) = decode_oneof_field(d, data, i, ch, item)?;
            item = it;
            i = ni;
        }
    }
    push_oneof(d, &mut item)?;
    Ok(i)
}

/// `upb_MtDecoder_DecodeOneofField` (decode.c:348-391): `first_ch` already
/// consumed; returns (next index, updated item).
fn decode_oneof_field(
    d: &mut Decoder,
    data: &[u8],
    i: usize,
    first_ch: u8,
    mut item: OneofItem,
) -> Result<(usize, OneofItem), DecodeError> {
    let (field_num, ni) = base92::decode_varint(
        data,
        i,
        first_ch,
        CHAR_MIN_ONEOF_FIELD,
        CHAR_MAX_ONEOF_FIELD,
    )
    .map_err(err_from)?;
    let fi = d
        .fields
        .iter()
        .position(|f| f.number == field_num)
        .ok_or_else(|| {
            err(&format!(
                "Couldn't add field number {field_num} to oneof, no such field number."
            ))
        })?;
    let f = &mut d.fields[fi];
    if f.offset != HASBIT_PRESENCE {
        return Err(err(&format!(
            "Cannot add repeated, required, or singular field {field_num} to oneof."
        )));
    }
    // Oneof storage must fit the largest member (decode.c:374-386).
    let rep = f.mode >> 6;
    let (new_size, new_align) = size_align_of_rep(rep);
    let (current_size, current_align) = size_align_of_rep(item.rep);
    if new_size > current_size || (new_size == current_size && new_align > current_align) {
        item.rep = rep;
    }
    // Prepend to the linked list (decode.c:387-389).
    f.offset = item.field_index;
    item.field_index = (fi as u16).wrapping_add(ONEOF_BASE);
    Ok((ni, item))
}

/// `upb_MtDecoder_PushOneof` (decode.c:283-301).
fn push_oneof(d: &mut Decoder, item: &mut OneofItem) -> Result<(), DecodeError> {
    if item.field_index == ONE_OF_ITEM_INDEX_SENTINEL {
        return Err(err("Empty oneof"));
    }
    item.field_index = item.field_index.wrapping_sub(ONEOF_BASE);
    d.rep_counts[FieldRep::FourByte as usize] += 1; // oneof case field
    d.rep_counts[item.rep as usize] += 1;
    d.oneofs.push(*item);
    Ok(())
}

/// Size of a field representation on the 64-bit platform (decode.c:303-323).
fn size_of_rep(rep: u8) -> usize {
    match rep {
        0 => 1,
        1 => 4,
        2 => 16, // upb_StringView on 64-bit
        _ => 8,
    }
}

/// Alignment of a field representation on the 64-bit platform (decode.c:325-346).
fn align_of_rep(rep: u8) -> usize {
    match rep {
        0 => 1,
        1 => 4,
        _ => 8, // StringView and 8-byte align to 8 on 64-bit
    }
}

fn size_align_of_rep(rep: u8) -> (usize, usize) {
    (size_of_rep(rep), align_of_rep(rep))
}

/// `upb_MtDecoder_AssignHasbits` (decode.c:623-659).
fn assign_hasbits(d: &mut Decoder, table: &mut MiniTable) -> Result<(), DecodeError> {
    let mut last_hasbit: i32 = RESERVED_HASBITS - 1;
    for f in d.fields.iter_mut() {
        match f.offset {
            REQUIRED_PRESENCE => {
                last_hasbit += 1;
                f.presence = last_hasbit as i16;
            }
            NO_PRESENCE => {
                f.presence = 0;
            }
            _ => {}
        }
    }
    if last_hasbit >= RESERVED_HASBITS + 63 {
        return Err(err("Too many required fields"));
    }
    d.required_count = (last_hasbit - (RESERVED_HASBITS - 1)) as u8;
    for f in d.fields.iter_mut() {
        if f.offset == HASBIT_PRESENCE {
            if last_hasbit >= i16::MAX as i32 {
                return Err(err("Too many fields with presence"));
            }
            last_hasbit += 1;
            f.presence = last_hasbit as i16;
        }
    }
    table.size = if last_hasbit != 0 {
        ((last_hasbit as u32 + 1).div_ceil(8)) as u16
    } else {
        0
    };
    Ok(())
}

/// `upb_MtDecoder_CalculateAlignments` (decode.c:581-617).
fn calculate_alignments(d: &mut Decoder, table: &mut MiniTable) -> Result<(), DecodeError> {
    for f in &d.fields {
        if f.offset >= ONEOF_BASE {
            continue;
        }
        d.rep_counts[(f.mode >> 6) as usize] += 1;
    }
    let mut base = table.size as usize;
    for rep in 0..4u8 {
        let count = d.rep_counts[rep as usize];
        if count > 0 {
            base = align_up(base, align_of_rep(rep));
            d.rep_counts[rep as usize] = base as u16;
            base += size_of_rep(rep) * count as usize;
        }
    }
    if base > u16::MAX as usize {
        return Err(err(&format!(
            "Message size exceeded maximum size of {} bytes",
            u16::MAX
        )));
    }
    table.size = base as u16;
    Ok(())
}

/// `upb_MtDecoder_AssignOffsets` (decode.c:668-706).
fn assign_offsets(d: &mut Decoder, table: &mut MiniTable) -> Result<(), DecodeError> {
    let rep_counts = &mut d.rep_counts;
    for f in d.fields.iter_mut() {
        if f.offset >= ONEOF_BASE {
            continue;
        }
        let rep = f.mode >> 6;
        let offset = rep_counts[rep as usize];
        rep_counts[rep as usize] += size_of_rep(rep) as u16;
        f.offset = offset;
    }
    let oneofs = std::mem::take(&mut d.oneofs);
    for item in &oneofs {
        let rep_counts = &mut d.rep_counts;
        let case_offset = {
            let offset = rep_counts[FieldRep::FourByte as usize];
            rep_counts[FieldRep::FourByte as usize] += size_of_rep(FieldRep::FourByte as u8) as u16;
            offset
        };
        if case_offset > i16::MAX as u16 {
            return Err(err("Message size exceeded maximum size for oneofs"));
        }
        let data_offset = {
            let offset = rep_counts[item.rep as usize];
            rep_counts[item.rep as usize] += size_of_rep(item.rep) as u16;
            offset
        };
        let mut fi = item.field_index as usize;
        loop {
            let f = &mut d.fields[fi];
            f.presence = !(case_offset as i16);
            let next_offset = f.offset;
            f.offset = data_offset;
            if next_offset == ONE_OF_ITEM_INDEX_SENTINEL {
                break;
            }
            fi = (next_offset - ONEOF_BASE) as usize;
        }
    }
    d.oneofs = oneofs;
    table.size = align_up(table.size as usize, 8) as u16;
    Ok(())
}

/// `upb_MtDecoder_AllocateSubs` (decode.c:441-464): convert per-field sub
/// indices into relative byte offsets (in u32 units). `ofs` decreases by the
/// field size on every field and increases by the pointer size for each sub.
fn allocate_subs(d: &mut Decoder, table: &mut MiniTable) {
    let mut ofs = d.field_bytes;
    for (i, f) in d.fields.iter_mut().enumerate() {
        if f.submsg_ofs != NO_SUB {
            let u32_ofs = ofs / SUBMSG_OFFSET_BYTES as usize;
            debug_assert_eq!(ofs % 4, 0);
            debug_assert_eq!((i * 12 + ofs) % 8, 0);
            if u32_ofs > u16::MAX as usize {
                // Upstream errors here; the allocation size check makes it
                // unreachable in practice for valid tables.
                f.submsg_ofs = NO_SUB;
                continue;
            }
            f.submsg_ofs = u32_ofs as u16;
            ofs += 8;
        }
        ofs -= 12;
    }
    table.fields = std::mem::take(&mut d.fields);
}

/// `upb_MtDecoder_ParseMap` (decode.c:739-764).
fn parse_map(d: &mut Decoder, table: &mut MiniTable) -> Result<(), DecodeError> {
    if table.field_count != 2 {
        return Err(err(&format!("{} fields in map", table.field_count)));
    }
    if !d.oneofs.is_empty() {
        return Err(err("Map entry cannot have oneof"));
    }
    validate_entry_field(&d.fields[0], 1)?;
    validate_entry_field(&d.fields[1], 2)?;
    // upb_MapEntry layout (upb/message/internal/map_entry.h:24-39):
    //   struct upb_Message (8) + uint64_t hasbits (8) + union k (16) +
    //   union v (16) = 48 bytes on 64-bit.
    d.fields[0].offset = 16; // offsetof(upb_MapEntry, k)
    d.fields[1].offset = 32; // offsetof(upb_MapEntry, v)
    table.size = 48; // sizeof(upb_MapEntry)
    table.ext |= EXT_MAP_ENTRY;
    Ok(())
}

/// `upb_MtDecoder_ValidateEntryField` (decode.c:708-737).
fn validate_entry_field(f: &MiniTableField, expected_num: u32) -> Result<(), DecodeError> {
    let name = if expected_num == 1 { "key" } else { "val" };
    if f.number != expected_num {
        return Err(err(&format!(
            "map {name} did not have expected number ({} vs {expected_num})",
            f.number
        )));
    }
    if f.mode_class() != FieldMode::Scalar {
        return Err(err(&format!(
            "map {name} cannot be repeated or map, or be in oneof"
        )));
    }
    let not_ok: u32 = if expected_num == 1 {
        // Float|Double|Message|Group|Bytes|Enum
        (1 << 2) | (1 << 1) | (1 << 11) | (1 << 10) | (1 << 12) | (1 << 14)
    } else {
        1 << 10
    };
    if not_ok & (1u32 << f.field_type()) != 0 {
        return Err(err(&format!(
            "map {name} cannot have type {}",
            f.descriptortype
        )));
    }
    Ok(())
}

/// `upb_MtDecoder_ParseMessageSet` (decode.c:766-780).
fn parse_message_set(
    d: &mut Decoder,
    table: &mut MiniTable,
    data: &[u8],
) -> Result<(), DecodeError> {
    if !data.is_empty() {
        return Err(err(&format!(
            "Invalid message set encode length: {}",
            data.len()
        )));
    }
    table.size = RESERVED_HASBYTES as u16;
    table.field_count = 0;
    table.ext = EXT_MESSAGE_SET;
    table.dense_below = 0;
    d.dense_below = 0;
    Ok(())
}

fn align_up(v: usize, align: usize) -> usize {
    v.div_ceil(align) * align
}

fn err(msg: &str) -> DecodeError {
    DecodeError::Message(format!("Error building mini table: {msg}"))
}

fn err_from(e: DecodeError) -> DecodeError {
    match e {
        DecodeError::OverlongVarint => {
            DecodeError::Message("Error building mini table: Overlong varint".to_string())
        }
        other => other,
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Message(m) => write!(f, "{m}"),
            DecodeError::OverlongVarint => write!(f, "Overlong varint"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_descriptor() {
        let (mt, v) = build_mini_table(b"").unwrap();
        assert_eq!(v, None);
        assert_eq!(mt.size, 8);
        assert_eq!(mt.field_count, 0);
        assert_eq!(mt.ext, EXT_NON_EXTENDABLE);
    }

    #[test]
    fn empty_message() {
        let (mt, v) = build_mini_table(b"$").unwrap();
        assert_eq!(v, Some(b'$'));
        assert_eq!(mt.size, 8);
        assert_eq!(mt.field_count, 0);
    }

    #[test]
    fn single_uint32_field() {
        // ')' is base92 7 -> UInt32 (field type 13), scalar.
        let (mt, _) = build_mini_table(b"$)").unwrap();
        assert_eq!(mt.field_count, 1);
        let f = &mt.fields[0];
        assert_eq!(f.number, 1);
        assert_eq!(f.descriptortype, 13);
        assert_eq!(f.mode_class(), FieldMode::Scalar);
        assert_eq!(f.rep(), FieldRep::FourByte);
        assert_eq!(f.presence, 64); // first hasbit after the reserved 64
        assert_eq!(mt.size, 16); // 9 hasbit bytes aligned up to 8
    }

    #[test]
    fn invalid_version() {
        let e = build_mini_table(b"X").unwrap_err();
        assert!(e.to_string().contains("Invalid message version: X"), "{e}");
    }

    #[test]
    fn invalid_char() {
        let e = build_mini_table(b"$J").unwrap_err();
        assert!(e.to_string().contains("Invalid char: J"), "{e}");
    }

    #[test]
    fn control_char_is_invalid_field_type() {
        // 0x01 <= 'I', so upstream reads it as a field char and reports an
        // invalid type (-1).
        let e = build_mini_table(&[b'$', 0x01]).unwrap_err();
        assert!(e.to_string().contains("Invalid field type: -1"), "{e}");
    }

    #[test]
    fn repeated_bytes_is_array() {
        // 'D' is base92 34 -> RepeatedBase(20) + 14 = repeated Bytes.
        let (mt, _) = build_mini_table(b"$D").unwrap();
        let f = &mt.fields[0];
        assert_eq!(f.mode_class(), FieldMode::Array);
        assert_eq!(f.descriptortype, 12); // Bytes
                                          // Repeated fields have no presence; the pointer is placed after the
                                          // 8 reserved hasbit bytes (aligned to 8).
        assert_eq!(f.presence, 0);
        assert_eq!(f.offset, 8);
        assert_eq!(mt.size, 16);
    }

    #[test]
    fn map_descriptor() {
        // '%' + ')' (base92 7 -> UInt32 key) + '(' (base92 6 -> Int32 val).
        let (mt, v) = build_mini_table(b"%)(").unwrap();
        assert_eq!(v, Some(b'%'));
        assert_eq!(mt.field_count, 2);
        assert_eq!(mt.ext & EXT_MAP_ENTRY, EXT_MAP_ENTRY);
        // upb_MapEntry: message(8) + hasbits(8) + k(16) + v(16).
        assert_eq!(mt.fields[0].offset, 16);
        assert_eq!(mt.fields[1].offset, 32);
        assert_eq!(mt.size, 48);
    }

    #[test]
    fn messageset_descriptor() {
        let (mt, v) = build_mini_table(b"&").unwrap();
        assert_eq!(v, Some(b'&'));
        assert_eq!(mt.ext, EXT_MESSAGE_SET);
        assert_eq!(mt.size, 8);
    }
}
