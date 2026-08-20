//! upb-rs-mini-table: mini descriptor decoding and mini table model.
//!
//! Mirrors the pinned upstream mini descriptor subsystem
//! (`upb/mini_descriptor/*` and `upb/mini_table/internal/*` at commit
//! `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`): the base92 encoding, the
//! descriptor grammar (`$` messages, `%` maps, `&` message sets), the
//! hasbit/rep placement layout algorithm, and the resulting `upb_MiniTable`
//! structure.
//!
//! The observable contract is the *layout*: message size, per-field offsets,
//! presence indices, oneof case offsets, and submessage offsets. The court
//! `mini-table-inspect-v1` compares a normalized rendering of the table built
//! by the pinned oracle against the Rust model.

pub mod base92;
pub mod decode;
pub mod inspect;
pub mod model;
