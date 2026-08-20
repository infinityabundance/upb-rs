//! upb-rs-wire: binary wire-format reader.
//!
//! This is a faithful Rust model of the observable behavior of the pinned
//! upstream upb reader:
//!
//! * `upb/wire/internal/reader.h` — fast paths for one-byte varints/tags/sizes
//! * `upb/wire/reader.c:19-61` — long varint/tag/size loops; the
//!   `val += (byte - 1) << (i * 7)` arithmetic, the 10-byte varint bound, the
//!   5-byte tag/size bounds, and the `UINT32_MAX`/`INT32_MAX` rejections
//! * `upb/wire/internal/eps_copy_input_stream.h` + `eps_copy_input_stream.c`
//!   — the 16-byte slop guarantee, the zero-padded 32-byte patch buffer, and
//!   the `IsDoneFallback` tail-copy behavior
//!
//! The most important compatibility surface is that raw reads past the end of
//! *short* inputs (<= 16 bytes) succeed using zero-padded bytes, and the error
//! only surfaces at the next `IsDone()` check — exactly like upstream. Courts
//! `wire-primitives-v1` preserve this observable behavior.

pub mod reader;
pub mod stream;
