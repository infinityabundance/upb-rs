//! A faithful Rust model of `upb_WireReader` (pinned commit
//! `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`).
//!
//! Upstream sources:
//! * `upb/wire/internal/reader.h:41-89` — fast paths and tag field/wire type
//!   accessors
//! * `upb/wire/reader.c:19-61` — long varint/tag/size loops
//! * `upb/wire/reader.h:128-161` — `_upb_WireReader_SkipValueForceInline`
//! * `upb/wire/reader.c:63-80` — `_upb_WireReader_SkipGroup`
//!
//! Quirks preserved deliberately (see forensics/QUIRKS.md):
//! * `val += (byte - 1) << (i * 7)` arithmetic with the first byte stored raw;
//!   this is exactly equivalent to LEB128 for terminated varints and defines
//!   the observable value for overlong/10-byte encodings.
//! * A varint may consume at most 10 bytes; a tag or size at most 5.
//! * Tags whose value exceeds `UINT32_MAX` and sizes whose value exceeds
//!   `INT32_MAX` are rejected (upstream checks the value *after* the
//!   terminating byte is found, only at the 5th byte).
//! * `SkipValue` rejects field number 0 and wire types 6/7 and EndGroup.

use upb_rs_core::error::{Error, ErrorCode};
use upb_rs_core::wire::{WireType, MAX_TAG_BYTES, MAX_VARINT_BYTES};

use crate::stream::EpsCopyStream;

/// Result of a successful primitive read: the value (when applicable) and the
/// absolute consumed position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    pub value: u64,
    pub consumed: usize,
}

/// Default group recursion depth limit (`kUpb_WireFormat_DefaultDepthLimit`).
pub const DEFAULT_DEPTH_LIMIT: i32 = 100;

type ReadResult = Result<ReadOutcome, Error>;

fn window_byte(window: &[u8], idx: usize) -> Result<u8, Error> {
    // The slop guarantee makes every reachable read in-bounds; this defensive
    // path converts a modeling error into a malformed result instead of a
    // panic, so a wrong model shows up as a court residual, never as an abort
    // on hostile input (charter §22).
    window.get(idx).copied().ok_or(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })
}

/// Reads a varint (`upb_WireReader_ReadVarint` + `_upb_WireReader_ReadLongVarint`).
pub fn read_varint(stream: &EpsCopyStream, ptr: usize) -> ReadResult {
    let window = &stream.window;
    let byte0 = window_byte(window, ptr)?;
    if byte0 & 0x80 == 0 {
        return Ok(ReadOutcome {
            value: byte0 as u64,
            consumed: ptr + 1,
        });
    }
    // `_upb_WireReader_ReadLongVarint`: the first byte is carried raw (its
    // 0x80 continuation bit is cancelled by the (byte - 1) terms below).
    let mut val = byte0 as u64;
    for i in 1..MAX_VARINT_BYTES {
        let byte = window_byte(window, ptr + i)?;
        val = val.wrapping_add((byte as u64).wrapping_sub(1) << (i * 7));
        if byte & 0x80 == 0 {
            return Ok(ReadOutcome {
                value: val,
                consumed: ptr + i + 1,
            });
        }
    }
    // All 10 bytes had the continuation bit set.
    Err(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })
}

/// Reads a tag (`upb_WireReader_ReadTag` + `_upb_WireReader_ReadLongTag`).
pub fn read_tag(stream: &EpsCopyStream, ptr: usize) -> ReadResult {
    let window = &stream.window;
    let byte0 = window_byte(window, ptr)?;
    if byte0 & 0x80 == 0 {
        return Ok(ReadOutcome {
            value: byte0 as u64,
            consumed: ptr + 1,
        });
    }
    let mut val = byte0 as u64;
    for i in 1..MAX_TAG_BYTES {
        let byte = window_byte(window, ptr + i)?;
        val = val.wrapping_add((byte as u64).wrapping_sub(1) << (i * 7));
        if byte & 0x80 == 0 {
            if val > u32::MAX as u64 {
                break;
            }
            return Ok(ReadOutcome {
                value: val,
                consumed: ptr + i + 1,
            });
        }
    }
    Err(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })
}

/// Reads a size (`upb_WireReader_ReadSize` + `_upb_WireReader_ReadLongSize`).
/// Sizes are signed 32-bit in upstream; values above `INT32_MAX` are rejected.
pub fn read_size(stream: &EpsCopyStream, ptr: usize) -> ReadResult {
    let window = &stream.window;
    let byte0 = window_byte(window, ptr)?;
    if byte0 & 0x80 == 0 {
        return Ok(ReadOutcome {
            value: byte0 as u64,
            consumed: ptr + 1,
        });
    }
    let mut val = byte0 as u64;
    for i in 1..MAX_TAG_BYTES {
        let byte = window_byte(window, ptr + i)?;
        val = val.wrapping_add((byte as u64).wrapping_sub(1) << (i * 7));
        if byte & 0x80 == 0 {
            if val > i32::MAX as u64 {
                break;
            }
            return Ok(ReadOutcome {
                value: val,
                consumed: ptr + i + 1,
            });
        }
    }
    Err(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })
}

/// Reads a fixed32 (`upb_WireReader_ReadFixed32`); wire bytes are
/// little-endian.
pub fn read_fixed32(stream: &EpsCopyStream, ptr: usize) -> ReadResult {
    let window = &stream.window;
    let mut v: u32 = 0;
    for i in 0..4 {
        let b = window_byte(window, ptr + i)? as u32;
        v |= b << (8 * i);
    }
    Ok(ReadOutcome {
        value: v as u64,
        consumed: ptr + 4,
    })
}

/// Reads a fixed64 (`upb_WireReader_ReadFixed64`); wire bytes are
/// little-endian.
pub fn read_fixed64(stream: &EpsCopyStream, ptr: usize) -> ReadResult {
    let window = &stream.window;
    let mut v: u64 = 0;
    for i in 0..8 {
        let b = window_byte(window, ptr + i)? as u64;
        v |= b << (8 * i);
    }
    Ok(ReadOutcome {
        value: v,
        consumed: ptr + 8,
    })
}

/// Skips a varint (`upb_WireReader_SkipVarint`).
pub fn skip_varint(stream: &EpsCopyStream, ptr: usize) -> Result<usize, Error> {
    let window = &stream.window;
    for p in (ptr..).take(MAX_VARINT_BYTES) {
        if window_byte(window, p)? & 0x80 == 0 {
            return Ok(p + 1);
        }
    }
    Err(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })
}

/// The tag value for the end of the group started by `tag`
/// (`_upb_WireReader_SkipGroup` line 69).
pub fn end_group_tag(tag: u32) -> u32 {
    (tag & !7) | (WireType::EndGroup as u32)
}

/// `_upb_WireReader_SkipGroup` (recursive, depth-limited).
pub fn skip_group_inner(
    stream: &mut EpsCopyStream,
    ptr: usize,
    tag: u32,
    depth_limit: i32,
) -> Result<usize, Error> {
    if depth_limit - 1 < 0 {
        return Err(Error {
            code: ErrorCode::Malformed,
            offset: None,
        });
    }
    let end_tag = end_group_tag(tag);
    let mut p = ptr;
    loop {
        let done = stream.is_done(&mut p);
        if done {
            if stream.is_error() {
                return Err(Error {
                    code: ErrorCode::Malformed,
                    offset: None,
                });
            }
            break;
        }
        let t = read_tag(stream, p)?;
        p = t.consumed;
        if t.value as u32 == end_tag {
            return Ok(p);
        }
        p = skip_value(stream, p, t.value as u32, depth_limit - 1)?;
    }
    // Encountered limit end before the end group tag.
    Err(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })
}

/// `upb_WireReader_SkipValue` with the default depth limit.
pub fn skip_value(
    stream: &mut EpsCopyStream,
    ptr: usize,
    tag: u32,
    depth_limit: i32,
) -> Result<usize, Error> {
    // `_upb_WireReader_SkipValueForceInline` line 131: field number 0 is an
    // error.
    if (tag >> 3) == 0 {
        return Err(Error {
            code: ErrorCode::Malformed,
            offset: None,
        });
    }
    let wt = WireType::from_tag(tag).ok_or(Error {
        code: ErrorCode::Malformed,
        offset: None,
    })?;
    match wt {
        WireType::Varint => skip_varint(stream, ptr),
        WireType::ThirtyTwoBit => Ok(ptr + 4),
        WireType::SixtyFourBit => Ok(ptr + 8),
        WireType::Delimited => {
            let size = read_size(stream, ptr)?;
            if !stream.check_size(size.consumed, size.value as usize) {
                return Err(stream.return_error());
            }
            Ok(size.consumed + size.value as usize)
        }
        WireType::StartGroup => skip_group_inner(stream, ptr, tag, depth_limit),
        // EndGroup and invalid wire types are errors here (EndGroup should
        // have been handled by the caller).
        WireType::EndGroup => Err(Error {
            code: ErrorCode::Malformed,
            offset: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome_ok(r: ReadResult) -> (u64, usize) {
        let o = r.expect("expected ok");
        (o.value, o.consumed)
    }

    #[test]
    fn one_byte_varint() {
        let s = EpsCopyStream::init(&[0x7F]);
        assert_eq!(outcome_ok(read_varint(&s, 0)), (0x7F, 1));
    }

    #[test]
    fn two_byte_varint() {
        // 0xAC 0x02 = 0x2C | 0x02<<7 = 44 + 256 = 300.
        let s = EpsCopyStream::init(&[0xAC, 0x02]);
        assert_eq!(outcome_ok(read_varint(&s, 0)), (300, 2));
    }

    #[test]
    fn ten_byte_varint_max() {
        // 0xFF * 9 then 0x01: ten bytes, value wraps.
        let bytes = [0xFF; 9];
        let last = [0x01];
        let s = EpsCopyStream::init(
            bytes
                .iter()
                .chain(&last)
                .copied()
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let (v, c) = outcome_ok(read_varint(&s, 0));
        assert_eq!(c, 10);
        assert_eq!(v, u64::MAX);
    }

    #[test]
    fn ten_continuation_bytes_error() {
        let s = EpsCopyStream::init(&[0xFF; 10]);
        assert!(read_varint(&s, 0).is_err());
    }

    #[test]
    fn zero_padded_truncated_varint_has_known_value() {
        // 1-byte input 0xFF: window is zero-padded, so byte 1 is 0x00 and the
        // value is 0xFF + (0-1)<<7 = 127, consumed 2 (unbounded).
        let s = EpsCopyStream::init(&[0xFF]);
        assert_eq!(outcome_ok(read_varint(&s, 0)), (127, 2));
    }

    #[test]
    fn tag_overflow_rejected() {
        // 5-byte tag exceeding UINT32_MAX.
        let s = EpsCopyStream::init(&[0xFF, 0xFF, 0xFF, 0xFF, 0x10]);
        assert!(read_tag(&s, 0).is_err());
    }

    #[test]
    fn tag_max_ok() {
        let s = EpsCopyStream::init(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        assert_eq!(outcome_ok(read_tag(&s, 0)), (0xFFFF_FFFF, 5));
    }

    #[test]
    fn size_overflow_rejected() {
        let s = EpsCopyStream::init(&[0xFF, 0xFF, 0xFF, 0xFF, 0x08]);
        assert!(read_size(&s, 0).is_err());
    }

    #[test]
    fn fixed_reads_little_endian() {
        let s = EpsCopyStream::init(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(outcome_ok(read_fixed32(&s, 0)), (0x1234_5678, 4));
    }

    #[test]
    fn skip_group_valid() {
        // Group body: field 2 varint (0x10 0x01) then end-group (0x0C).
        let input = [0x10, 0x01, 0x0C];
        let mut s = EpsCopyStream::init(&input);
        assert_eq!(
            skip_group_inner(&mut s, 0, 0x0B, DEFAULT_DEPTH_LIMIT),
            Ok(3)
        );
    }

    #[test]
    fn skip_group_unterminated() {
        let input = [0x10, 0x01];
        let mut s = EpsCopyStream::init(&input);
        assert!(skip_group_inner(&mut s, 0, 0x0B, DEFAULT_DEPTH_LIMIT).is_err());
    }

    #[test]
    fn skip_value_field_zero_rejected() {
        let mut s = EpsCopyStream::init(&[0x00]);
        assert!(skip_value(&mut s, 0, 0x00, DEFAULT_DEPTH_LIMIT).is_err());
    }

    #[test]
    fn skip_value_delimited_fits() {
        let input = [0x03, 0xAA, 0xBB, 0xCC];
        let mut s = EpsCopyStream::init(&input);
        assert_eq!(skip_value(&mut s, 0, 0x0A, DEFAULT_DEPTH_LIMIT), Ok(4));
    }

    #[test]
    fn skip_value_delimited_overruns() {
        // Declared size 4, only 3 bytes of payload: CheckSize fails.
        let input = [0x04, 0xAA, 0xBB, 0xCC];
        let mut s = EpsCopyStream::init(&input);
        assert!(skip_value(&mut s, 0, 0x0A, DEFAULT_DEPTH_LIMIT).is_err());
    }
}
