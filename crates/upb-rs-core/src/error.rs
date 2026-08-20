//! Error model mirroring `upb/base/error_handler.h` at upstream commit
//! `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (lines 55-60).
//!
//! Upstream classifies all runtime errors into four codes. `MaxDepthExceeded`
//! is only produced by depth-checking paths; `OutOfMemory` is produced by
//! arena allocation failures under an error handler. Decode/encode failures
//! surface as `Malformed`.
//!
//! The Rust implementation uses `Result` rather than longjmp, but the
//! classification is preserved exactly: a court comparing error *classes*
//! observes the same four-way taxonomy.

/// Error codes mirroring `upb_ErrorCode` (upb/base/error_handler.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    Ok = 0,
    OutOfMemory = 1,
    Malformed = 2,
    MaxDepthExceeded = 3,
}

impl ErrorCode {
    /// Maps the integer codes used by the oracle protocol / upstream enum.
    pub fn from_i32(code: i32) -> Option<ErrorCode> {
        match code {
            0 => Some(ErrorCode::Ok),
            1 => Some(ErrorCode::OutOfMemory),
            2 => Some(ErrorCode::Malformed),
            3 => Some(ErrorCode::MaxDepthExceeded),
            _ => None,
        }
    }
}

/// The failure returned by parsing/encoding operations.
///
/// `upb_DecodeStatus`-style boolean/numeric outcomes in upstream are
/// represented here; `bytes_consumed` records how far into the input the
/// operation got when it failed, which courts use to compare failure
/// positions exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: ErrorCode,
    /// Byte offset at which the failure was detected, when meaningful.
    pub offset: Option<usize>,
}

impl Error {
    pub fn malformed(offset: usize) -> Error {
        Error {
            code: ErrorCode::Malformed,
            offset: Some(offset),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
