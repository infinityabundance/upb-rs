//! Mini descriptor *encoding* for corpus generation (generation tooling only;
//! not the DUT). Mirrors upb/mini_descriptor/internal/encode.c and the
//! wire_constants.h character ranges, so generated descriptors are exactly
//! what upstream's upb_MiniTable_Build consumes.

use upb_rs_mini_table::base92::{self};

pub const REPEATED_BASE: usize = 20;

/// Encoded field modifier bits (wire_constants.h:40-45).
pub const MOD_FLIP_PACKED: u32 = 1 << 0;
pub const MOD_IS_REQUIRED: u32 = 1 << 1;
pub const MOD_IS_PROTO3_SINGULAR: u32 = 1 << 2;
pub const MOD_FLIP_VALIDATE_UTF8: u32 = 1 << 3;

/// Message modifier bits (mini_descriptor/internal/modifiers.h:24-28).
pub const MSG_MOD_VALIDATE_UTF8: u32 = 1 << 0;
pub const MSG_MOD_DEFAULT_IS_PACKED: u32 = 1 << 1;

const CHAR_MIN_MODIFIER: u8 = b'L';
const CHAR_MAX_MODIFIER: u8 = b'[';
const CHAR_MIN_SKIP: u8 = b'_';
const CHAR_MAX_SKIP: u8 = b'~';
const CHAR_MIN_ONEOF_FIELD: u8 = b' ';
const CHAR_MAX_ONEOF_FIELD: u8 = b'b';

/// The field type char for an encoded type (scalar or repeated).
pub fn type_char(encoded_type: usize) -> u8 {
    if encoded_type >= REPEATED_BASE {
        base92::to_base92((encoded_type - REPEATED_BASE + REPEATED_BASE) as i8)
    } else {
        base92::to_base92(encoded_type as i8)
    }
}

/// Builds a message mini descriptor: version '$', optional message modifiers,
/// then fields (ascending numbers) with optional skips and field modifiers,
/// then an optional oneof section (each oneof is a group of field numbers
/// separated by '|'; oneofs separated by '~'; the last oneof ends at the end
/// of the string).
pub struct MessageEncoder {
    out: Vec<u8>,
    last_field_num: u32,
    oneof_state: u8, // 0 = not started, 1 = started, 2 = emitted field
}

impl MessageEncoder {
    pub fn new(msg_modifiers: u32) -> MessageEncoder {
        let mut out = Vec::new();
        out.push(b'$');
        if msg_modifiers != 0 {
            base92::encode_varint(
                &mut out,
                msg_modifiers,
                CHAR_MIN_MODIFIER,
                CHAR_MAX_MODIFIER,
            );
        }
        MessageEncoder {
            out,
            last_field_num: 0,
            oneof_state: 0,
        }
    }

    /// Adds a field. `encoded_type` is the kUpb_EncodedType value (0..18) or
    /// +REPEATED_BASE for repeated.
    pub fn field(&mut self, field_num: u32, encoded_type: usize, field_modifiers: u32) {
        debug_assert!(field_num > self.last_field_num, "fields must ascend");
        if field_num != self.last_field_num + 1 {
            let skip = field_num - self.last_field_num;
            base92::encode_varint(&mut self.out, skip, CHAR_MIN_SKIP, CHAR_MAX_SKIP);
        }
        self.last_field_num = field_num;
        self.out.push(type_char(encoded_type));
        if field_modifiers != 0 {
            base92::encode_varint(
                &mut self.out,
                field_modifiers,
                CHAR_MIN_MODIFIER,
                CHAR_MAX_MODIFIER,
            );
        }
    }

    /// Starts the oneof section (must come after all fields).
    pub fn start_oneofs(&mut self) {
        self.out.push(b'^');
        self.oneof_state = 1;
    }

    /// Adds a field number to the current oneof; `first_in_oneof` should be
    /// true for the first member of each oneof.
    pub fn oneof_field(&mut self, field_num: u32, first_in_oneof: bool) {
        if !first_in_oneof {
            self.out.push(b'|');
        }
        base92::encode_varint(
            &mut self.out,
            field_num,
            CHAR_MIN_ONEOF_FIELD,
            CHAR_MAX_ONEOF_FIELD,
        );
        self.oneof_state = 2;
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// A map mini descriptor: '%' + key field + value field (scalar encoded types).
pub fn map_descriptor(key_encoded_type: usize, val_encoded_type: usize) -> Vec<u8> {
    let mut out = vec![b'%'];
    out.push(type_char(key_encoded_type));
    out.push(type_char(val_encoded_type));
    out
}

/// A message set descriptor.
pub fn messageset_descriptor() -> Vec<u8> {
    vec![b'&']
}

#[cfg(test)]
mod tests {
    use super::*;
    use upb_rs_mini_table::decode::build_mini_table;

    #[test]
    fn empty_message_roundtrip() {
        let enc = MessageEncoder::new(0);
        let desc = enc.finish();
        assert_eq!(desc, b"$");
        let (mt, v) = build_mini_table(&desc).unwrap();
        assert_eq!(mt.field_count, 0);
        assert_eq!(v, Some(b'$'));
    }

    #[test]
    fn one_uint32() {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7, 0); // UInt32
        let desc = enc.finish();
        assert_eq!(desc, b"$)");
        let (mt, _) = build_mini_table(&desc).unwrap();
        assert_eq!(mt.field_count, 1);
        assert_eq!(mt.fields[0].descriptortype, 13);
    }

    #[test]
    fn repeated_bytes() {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 14 + REPEATED_BASE, 0); // repeated Bytes
        let desc = enc.finish();
        assert_eq!(desc, b"$D");
        let (mt, _) = build_mini_table(&desc).unwrap();
        assert_eq!(
            mt.fields[0].mode_class(),
            upb_rs_mini_table::model::FieldMode::Array
        );
    }

    #[test]
    fn map_roundtrip() {
        let desc = map_descriptor(7, 6); // UInt32 key, Int32 val
        assert_eq!(desc, b"%)(");
        let (mt, v) = build_mini_table(&desc).unwrap();
        assert_eq!(v, Some(b'%'));
        assert_eq!(mt.field_count, 2);
        assert_eq!(mt.size, 48);
    }

    #[test]
    fn oneof_roundtrip() {
        let mut enc = MessageEncoder::new(0);
        enc.field(1, 7, 0); // UInt32
        enc.field(2, 6, 0); // Int32
        enc.start_oneofs();
        enc.oneof_field(1, true);
        enc.oneof_field(2, false);
        let desc = enc.finish();
        let (mt, _) = build_mini_table(&desc).unwrap();
        assert_eq!(mt.field_count, 2);
        assert!(mt.fields[0].is_in_oneof());
        assert!(mt.fields[1].is_in_oneof());
        assert_eq!(mt.fields[0].presence, mt.fields[1].presence); // same oneof
    }
}
