//! A Rust model of `upb_EpsCopyInputStream`.
//!
//! Upstream semantics being reproduced (pinned commit
//! `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`):
//!
//! * `kUpb_EpsCopyInputStream_SlopBytes = 16`
//!   (`upb/wire/internal/eps_copy_input_stream.h:33`)
//! * Init with `size <= 16` copies the input into a 32-byte patch buffer and
//!   **zero-pads** the remainder (`:69-75`). Reads may therefore consume
//!   zero bytes past the true end of the input; the decoder notices only at
//!   the next `IsDone()`.
//! * Init with `size > 16` keeps the input in place; `end` is placed 16 bytes
//!   before the true end and `limit = 16` (`:76-80`), so reads may consume up
//!   to 16 real bytes past `end`.
//! * `IsDone()` (`:188-209`) distinguishes Done (exactly at the limit), Not
//!   Done (more data), and NeedFallback (past the limit_ptr). The fallback
//!   (`eps_copy_input_stream.c:25-47`) copies the remaining real bytes into
//!   the patch buffer when the overrun is less than the current limit, and
//!   errors when the overrun exceeds the limit.
//!
//! This module models exactly that state machine. `bounded` in the court
//! protocol corresponds to "`IsDone` at the final position does not report an
//! error".

use upb_rs_core::error::{Error, ErrorCode};
use upb_rs_core::wire::EPS_COPY_SLOP_BYTES;

/// A model of `upb_EpsCopyInputStream`.
///
/// Invariants:
/// * `window` is always at least `EPS_COPY_SLOP_BYTES * 2` bytes long.
/// * For `input.len() <= 16` the window is the input followed by zeros.
/// * For `input.len() > 16` the window is the whole input; reads never exceed
///   it because the slop guarantee bounds every read start to
///   `ptr < end = len - 16`.
/// * After a fallback copy the window is the 32-byte patch (16 real bytes +
///   16 zeros) and `limit == 0`, so any further overrun is an error.
#[derive(Debug, Clone)]
pub struct EpsCopyStream {
    /// The readable window (input + zero padding, or the patch buffer).
    pub(crate) window: Vec<u8>,
    /// Position of the logical "end" within `window`.
    end: usize,
    /// Limit relative to `end` (isize because sub-message pushes can make it
    /// negative in later courts; here it is always 0 or 16).
    limit: isize,
    /// Offset that converts window coordinates to absolute input coordinates.
    base: usize,
    error: bool,
}

impl EpsCopyStream {
    /// Mirrors `upb_EpsCopyInputStream_Init` +
    /// `InitWithErrorHandler` with a NULL error handler.
    pub fn init(input: &[u8]) -> EpsCopyStream {
        let mut window = Vec::with_capacity(EPS_COPY_SLOP_BYTES * 2);
        if input.len() <= EPS_COPY_SLOP_BYTES {
            // Patch-buffer mode: zero-pad to 2 * SlopBytes.
            window.extend_from_slice(input);
            window.resize(EPS_COPY_SLOP_BYTES * 2, 0);
            EpsCopyStream {
                window,
                end: input.len(),
                limit: 0,
                base: 0,
                error: false,
            }
        } else {
            // In-place mode: reads may go up to SlopBytes past `end`, which is
            // still inside the real input.
            window.extend_from_slice(input);
            EpsCopyStream {
                window,
                end: input.len() - EPS_COPY_SLOP_BYTES,
                limit: EPS_COPY_SLOP_BYTES as isize,
                base: 0,
                error: false,
            }
        }
    }

    /// True if the stream is in the error state
    /// (`upb_EpsCopyInputStream_IsError`).
    pub fn is_error(&self) -> bool {
        self.error
    }

    /// The limit pointer: `end + min(0, limit)`.
    fn limit_ptr(&self) -> isize {
        self.end as isize + self.limit.min(0)
    }

    /// Absolute position of a window pointer (input coordinates).
    pub fn absolute(&self, ptr: usize) -> usize {
        self.base + ptr
    }

    /// Mirrors `upb_EpsCopyInputStream_IsDone` (returns true at a limit; the
    /// caller must then consult `is_error` to distinguish EOF from error).
    /// May mutate the stream by performing the fallback patch copy.
    pub fn is_done(&mut self, ptr: &mut usize) -> bool {
        let p = *ptr as isize;
        if p < self.limit_ptr() {
            return false;
        }
        let overrun = p - self.end as isize;
        if overrun == self.limit {
            // Done: exactly at the limit.
            return true;
        }
        if overrun < self.limit {
            // NeedFallback with overrun < limit: copy the remaining real data
            // into the patch buffer and continue (eps_copy_input_stream.c
            // lines 27-42).
            debug_assert!(overrun < EPS_COPY_SLOP_BYTES as isize);
            debug_assert!(self.end + EPS_COPY_SLOP_BYTES <= self.window.len());
            let mut patch = vec![0u8; EPS_COPY_SLOP_BYTES * 2];
            patch[..EPS_COPY_SLOP_BYTES]
                .copy_from_slice(&self.window[self.end..self.end + EPS_COPY_SLOP_BYTES]);
            let new_ptr = overrun as usize;
            self.base += *ptr - new_ptr;
            *ptr = new_ptr;
            self.window = patch;
            self.end = EPS_COPY_SLOP_BYTES;
            self.limit -= EPS_COPY_SLOP_BYTES as isize;
            debug_assert!((*ptr as isize) < self.limit_ptr());
            return false;
        }
        // overrun > limit: error.
        self.error = true;
        true
    }

    /// Mirrors `upb_EpsCopyInputStream_CheckSize`: returns true iff a
    /// delimited field of `size` bytes starting at `ptr` fits within the
    /// current limit.
    pub fn check_size(&self, ptr: usize, size: usize) -> bool {
        // size <= limit - (ptr - end), with ptrdiff arithmetic like upstream.
        let available = self.limit - (ptr as isize - self.end as isize);
        (size as isize) <= available
    }

    /// Mirrors the `upb_EpsCopyCapture_End` bounds check
    /// (`ptr - end > limit` fails); the stream position must not overrun the
    /// current limit for a capture to be valid.
    pub fn capture_ok(&self, ptr: usize) -> bool {
        (ptr as isize - self.end as isize) <= self.limit
    }

    /// Mirrors `upb_EpsCopyInputStream_ReturnError`: sets the error state and
    /// returns the malformed error.
    pub fn return_error(&mut self) -> Error {
        self.error = true;
        Error {
            code: ErrorCode::Malformed,
            offset: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_is_zero_padded() {
        // Input 0xFF (1 byte): the window is [0xFF, 0, 0, ...].
        let mut s = EpsCopyStream::init(&[0xFF]);
        let mut ptr = 0;
        // Not done at start.
        assert!(!s.is_done(&mut ptr));
        assert_eq!(s.window[1], 0);
    }

    #[test]
    fn long_input_keeps_real_tail() {
        let input: Vec<u8> = (0..24u8).collect();
        let mut s = EpsCopyStream::init(&input);
        let mut ptr = 0;
        assert!(!s.is_done(&mut ptr));
        // end = 24 - 16 = 8: window[8..24] are real bytes.
        assert_eq!(s.end, 8);
        assert_eq!(s.window[23], 23);
    }

    #[test]
    fn fallback_copies_tail_into_patch() {
        let input: Vec<u8> = (0..20u8).collect();
        let mut s = EpsCopyStream::init(&input);
        // end = 4. Position 6 has overrun 2 < limit 16 -> fallback copy.
        let mut ptr = 6;
        assert!(!s.is_done(&mut ptr));
        // After fallback: limit 0, end 16, ptr = overrun = 2, base = 6 - 2 = 4.
        assert_eq!(s.limit, 0);
        assert_eq!(s.end, 16);
        assert_eq!(ptr, 2);
        assert_eq!(s.absolute(ptr), 6);
        // The window now holds the real tail: window[0] == input[4] == 4.
        assert_eq!(s.window[0], 4);
    }

    #[test]
    fn overrun_past_limit_errors() {
        let input = vec![0u8; 3];
        let mut s = EpsCopyStream::init(&input);
        let mut ptr = 5; // overrun 5 > limit 0
        assert!(s.is_done(&mut ptr));
        assert!(s.is_error());
    }

    #[test]
    fn exact_end_is_done_without_error() {
        let input = vec![0u8; 3];
        let mut s = EpsCopyStream::init(&input);
        let mut ptr = 3; // exactly at end, overrun 0 == limit 0
        assert!(s.is_done(&mut ptr));
        assert!(!s.is_error());
    }
}
