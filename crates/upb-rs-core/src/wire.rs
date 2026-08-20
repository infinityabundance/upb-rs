//! Wire-format constants mirroring `upb/wire/types.h` and
//! `upb/wire/internal/constants.h` at upstream commit
//! `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`.

/// Wire types as encoded on the wire (upb/wire/types.h lines 12-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    Varint = 0,
    SixtyFourBit = 1,
    Delimited = 2,
    StartGroup = 3,
    EndGroup = 4,
    ThirtyTwoBit = 5,
}

impl WireType {
    pub fn from_tag(tag: u32) -> Option<WireType> {
        match (tag & 0x7) as u8 {
            0 => Some(WireType::Varint),
            1 => Some(WireType::SixtyFourBit),
            2 => Some(WireType::Delimited),
            3 => Some(WireType::StartGroup),
            4 => Some(WireType::EndGroup),
            5 => Some(WireType::ThirtyTwoBit),
            // 6 and 7 are invalid wire types; upstream rejects them
            // (upb/wire/reader.h `_upb_WireReader_SkipValueForceInline`,
            // `default:` arm).
            _ => None,
        }
    }
}

/// Default recursion depth limit (upb/wire/internal/constants.h line 11).
pub const DEFAULT_DEPTH_LIMIT: u32 = 100;

/// MessageSet wire format field numbers (upb/wire/internal/constants.h).
pub const MSGSET_ITEM: u32 = 1;
pub const MSGSET_TYPE_ID: u32 = 2;
pub const MSGSET_MESSAGE: u32 = 3;

/// Bits used by tags: 3 wire-type bits (upb/wire/internal/reader.h line 19).
pub const TAG_WIRE_TYPE_BITS: u32 = 3;
pub const TAG_WIRE_TYPE_MASK: u32 = 7;

/// Maximum number of bytes a single field can occupy on the wire:
/// 5-byte tag + 10-byte varint. Upstream guarantees this many bytes are
/// readable after `IsDone()` returns false
/// (upb/wire/internal/eps_copy_input_stream.h line 33).
pub const EPS_COPY_SLOP_BYTES: usize = 16;

/// Maximum bytes in a varint (1 + 9 continuation bytes).
pub const MAX_VARINT_BYTES: usize = 10;

/// Maximum bytes in a tag or size varint (upb reads at most 5).
pub const MAX_TAG_BYTES: usize = 5;
