# upb-rs

A **custodial native-Rust reimplementation of Google's upb (μpb) Protocol
Buffers runtime**, engineered as a pure-Rust kernel that can occupy the same
position the C upb kernel occupies in the official Protocol Buffers
architecture — with observable-behavior parity proven by differential
courts against a pinned upstream oracle.

This is **not** a wrapper, a binding, a `bindgen` façade, or another
independent protobuf library. It is a compatibility implementation whose
behavioral oracle is the pinned upstream protobuf source tree in
`third_party/protobuf` (see `third_party/protobuf/PIN.md`).

## Non-negotiable ground rules (§1, §6, §42, §47 of the charter)

- Production semantics are native Rust. No linking, FFI calls, C sources,
  subprocess delegation, or wrapping of another runtime in the production
  crates. The upstream C implementation appears only in oracle tooling,
  differential courts, and benchmarks, and CI rejects forbidden linkage.
- A passing unit test is not evidence of compatibility. Every parity claim
  must survive independent falsification: pinned oracle, generated corpora,
  hostile inputs, differential receipts, retained casefiles, and an
  auditable evidence pack (`receipts/`).
- No surface is PARITY-SEALED while unexplained residuals remain. See
  `STATUS.md` and `PARITY.toml` for the machine-readable claim manifest.

## Layout

```
crates/         production Rust crates (upb-rs, upb-rs-core, upb-rs-wire, ...)
forensics/      living engineering atlases (source, version, surface,
                behavior, kernel, memory, error, nondeterminism, quirks, ...)
tools/          oracle server (C, links pinned libupb), corpus generators,
                court runners, casefile tooling
courts/         differential courts and their runners
corpus/         generated input corpora (replayable by seed)
casefiles/      permanent records of every historically important residual
receipts/       immutable evidence packs per run
conformance/    upstream conformance dashboard
security/       historical security regression corpus
fuzz/           differential fuzz targets
benches/        comparative benchmarks
integration/    upstream patch series for kernel integration (later)
abi/            version-scoped C ABI manifests (later)
third_party/    pinned upstream protobuf (oracle only)
```

## Quick start (Phase 0 state)

```sh
# 1. Build the pinned oracle (requires cmake + a C compiler)
tools/oracle/build.sh

# 2. Run the first differential court (wire primitives: varint/tag/size)
cargo run --manifest-path courts/wire-primitives/Cargo.toml -- --corpus corpus/generated/wire-primitives-v1

# 3. Inspect the evidence
cat receipts/latest/residuals.json
```

See `forensics/SOURCE_BASELINE.md` for the source authority hierarchy and
`courts/` for the differential protocol.

## Status

See `STATUS.md` (court exit criteria per surface) and `PARITY.toml`
(machine-readable claims). Badges and marketing claims are derived from
`PARITY.toml` only.
