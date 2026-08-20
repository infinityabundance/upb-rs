//! upb-rs-core: core types, wire constants, the error model, and the arena.
//!
//! This crate mirrors the observable semantics of the pinned upstream upb
//! headers `upb/wire/types.h`, `upb/wire/internal/constants.h`,
//! `upb/base/descriptor_constants.h`, `upb/base/error_handler.h`, and
//! `upb/mem/arena.*` (see forensics/SOURCE_BASELINE.md for provenance).

pub mod arena;
pub mod array;
pub mod error;
pub mod map;
pub mod wire;
