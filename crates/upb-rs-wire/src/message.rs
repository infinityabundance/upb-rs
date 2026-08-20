//! Message-level decoding for the empty (zero-field, non-extendable) mini
//! table surface.
//!
//! Mirrors `_upb_Decoder_DecodeEmptyMessage` in `upb/wire/decode.c:1205-1239`
//! (pinned commit `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`): when a mini
//! table has no fields and is not extendable, upb decodes a message purely as
//! unknown fields:
//!
//! ```c
//! while (!IsDone(&ptr)) {
//!   capture_end = ptr;
//!   tag = ReadTag(ptr);
//!   if ((tag & 7) == EndGroup) { d->end_group = tag >> 3; break; }
//!   ptr = SkipValueForceInline(ptr, tag, d->depth);
//!   capture_end = ptr;
//! }
//! ```
//!
//! Observables reproduced here:
//! * success (the whole input is captured as one unknown-field span and
//!   re-encoded byte-for-byte), or malformed.
//! * a top-level EndGroup tag is malformed (`d->end_group != DECODE_NOGROUP`
//!   at decode.c:1283).
//! * group recursion depth is bounded by `d->depth` (default 100); exceeding
//!   it reports **malformed** because the skip path throws
//!   `kUpb_ErrorCode_Malformed` (not `MaxDepthExceeded`, which is only used by
//!   the submessage-recursion path that cannot trigger here).
//! * field number 0, wire types 6/7, oversized delimited payloads, and all
//!   read-level malformations propagate as malformed.

use upb_rs_core::wire::WireType;

use crate::reader::{self, DEFAULT_DEPTH_LIMIT};
use crate::stream::EpsCopyStream;

/// The failure mode for this surface. (Upstream reports these as decode
/// statuses; the Rust side classifies them as an error type.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Wire format was corrupt (`kUpb_DecodeStatus_Malformed`).
    Malformed,
}

/// Result of a successful `decode_empty`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeEmptyResult {
    /// The captured unknown-field span (re-encoded bytes). On success this is
    /// the whole input, byte-for-byte.
    pub unknown: Vec<u8>,
}

/// Mirrors `upb_Decode` with an empty mini table. `max_depth == 0` selects
/// `kUpb_WireFormat_DefaultDepthLimit` (100), like upstream's options
/// encoding.
pub fn decode_empty(input: &[u8], max_depth: u32) -> Result<DecodeEmptyResult, DecodeError> {
    let depth: i32 = if max_depth == 0 {
        DEFAULT_DEPTH_LIMIT
    } else {
        max_depth as i32
    };
    let mut stream = EpsCopyStream::init(input);
    let mut ptr = 0usize;
    let mut capture_end = 0usize;
    let mut end_group = false;

    loop {
        let done = stream.is_done(&mut ptr);
        if done {
            if stream.is_error() {
                return Err(DecodeError::Malformed);
            }
            break;
        }
        capture_end = ptr;
        let tag = reader::read_tag(&stream, ptr).map_err(|_| DecodeError::Malformed)?;
        ptr = tag.consumed;
        if tag.value & 7 == WireType::EndGroup as u64 {
            end_group = true;
            break;
        }
        ptr = reader::skip_value(&mut stream, ptr, tag.value as u32, depth)
            .map_err(|_| DecodeError::Malformed)?;
        capture_end = ptr;
    }

    if end_group {
        // `_upb_Decoder_DecodeTop` (decode.c:1283): a dangling end group is
        // malformed.
        return Err(DecodeError::Malformed);
    }

    // `upb_EpsCopyCapture_End` bounds check (decode.c:1229).
    if !stream.capture_ok(capture_end) {
        return Err(DecodeError::Malformed);
    }

    let abs_end = stream.absolute(capture_end);
    if abs_end > input.len() {
        // Defensive: the model guarantees abs_end <= len on success; a
        // violation is a modeling bug that must surface as a court residual.
        return Err(DecodeError::Malformed);
    }
    Ok(DecodeEmptyResult {
        unknown: input[0..abs_end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_hex(input: &[u8], depth: u32) -> Option<String> {
        match decode_empty(input, depth) {
            Ok(r) => Some(r.unknown.iter().map(|b| format!("{b:02x}")).collect()),
            Err(_) => None,
        }
    }

    #[test]
    fn empty_input_decodes_ok() {
        assert_eq!(ok_hex(&[], 0), Some(String::new()));
    }

    #[test]
    fn scalar_field_round_trips() {
        assert_eq!(ok_hex(&[0x08, 0x01], 0), Some("0801".into()));
    }

    #[test]
    fn truncated_varint_malformed() {
        // Tag with no value: zero-padded read succeeds, next IsDone errors.
        assert_eq!(ok_hex(&[0x08], 0), None);
    }

    #[test]
    fn delimited_exact_and_overrun() {
        assert_eq!(
            ok_hex(&[0x0A, 0x03, 0xAA, 0xBB, 0xCC], 0),
            Some("0a03aabbcc".into())
        );
        assert_eq!(ok_hex(&[0x0A, 0x04, 0xAA, 0xBB, 0xCC], 0), None);
    }

    #[test]
    fn top_level_end_group_malformed() {
        assert_eq!(ok_hex(&[0x0C], 0), None);
    }

    #[test]
    fn field_zero_malformed() {
        assert_eq!(ok_hex(&[0x00], 0), None);
    }

    #[test]
    fn complete_group_ok() {
        assert_eq!(ok_hex(&[0x0B, 0x0C], 0), Some("0b0c".into()));
    }

    #[test]
    fn group_depth_limit() {
        // Three nested groups need depth 3; depth 2 fails (malformed, via the
        // skip path).
        assert_eq!(
            ok_hex(&[0x0B, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C], 0),
            Some("0b0b0b0c0c0c".into())
        );
        assert_eq!(ok_hex(&[0x0B, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C], 2), None);
        assert_eq!(
            ok_hex(&[0x0B, 0x0B, 0x0C, 0x0C], 2),
            Some("0b0b0c0c".into())
        );
    }
}
