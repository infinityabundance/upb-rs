//! Client for the pinned upstream upb oracle (`tools/oracle`), protocol v1.
//!
//! The oracle is a separate process linked against the pinned C upb; courts
//! communicate with it over stdin/stdout JSON-lines pipes. The DUT and the
//! oracle never share memory (charter §19). This crate only implements the
//! protocol envelope; court runners choose which operations to send.

pub mod client;
pub mod protocol;

pub use client::{OracleClient, OracleError};
pub use protocol::{OracleRequest, OracleResponse, PrimitiveOp, ResponseStatus};
