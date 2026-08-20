//! # upb-rs
//!
//! A **custodial native-Rust reimplementation of Google's upb (μpb) Protocol
//! Buffers runtime**, engineered as a pure-Rust kernel that can occupy the
//! same position the C upb kernel occupies in the official Protocol Buffers
//! architecture — with observable-behavior parity proven by differential
//! courts against a pinned upstream oracle.
//!
//! This is **not** a wrapper, a binding, a `bindgen` façade, or another
//! independent protobuf library. It is a compatibility implementation whose
//! behavioral oracle is the pinned upstream protobuf source tree
//! (see `third_party/protobuf/PIN.md` in the repository).
//!
//! # Workspace umbrella
//!
//! This crate is the umbrella for the `upb-rs` workspace. It re-exports the
//! individual subsystem crates:
//!
//! * [`core`](upb_rs_core) — wire constants and the upb error model
//!   (`upb/wire/types.h`, `upb/base/error_handler.h` semantics)
//! * [`wire`](upb_rs_wire) — binary wire-format reader
//!   (`upb_EpsCopyInputStream` + `upb_WireReader` semantics)
//! * [`oracle`](upb_rs_oracle) — client for the pinned upstream C upb oracle
//!   (differential-court tooling only)
//! * [`casefile`](upb_rs_casefile) — machine-readable residual casefile model
//!
//! # Ground rules
//!
//! Production semantics are native Rust: no linking, FFI calls, C sources,
//! subprocess delegation, or wrapping of another runtime. The upstream C
//! implementation appears only in oracle tooling and differential courts
//! (the `oracle` crate), never in the production path.
//!
//! A passing unit test is not evidence of compatibility. Every parity claim
//! must survive independent falsification; the repository maintains the
//! differential courts, receipts, and casefiles that make that possible.
//!
//! # Status
//!
//! Early development: wire-primitive decoding (varint/tag/size/fixed/skip)
//! is under differential test against the pinned oracle. See
//! `STATUS.md` and `PARITY.toml` in the repository for the machine-readable
//! claim manifest.

pub use upb_rs_casefile as casefile;
pub use upb_rs_core as core;
pub use upb_rs_oracle as oracle;
pub use upb_rs_wire as wire;
