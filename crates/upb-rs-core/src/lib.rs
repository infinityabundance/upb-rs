//! upb-rs-core: core types, wire constants, and the error model.
//!
//! This crate mirrors the observable semantics of the pinned upstream upb
//! headers `upb/wire/types.h`, `upb/wire/internal/constants.h`,
//! `upb/base/descriptor_constants.h`, and `upb/base/error_handler.h`
//! (see forensics/SOURCE_BASELINE.md for provenance).

pub mod error;
pub mod wire;
