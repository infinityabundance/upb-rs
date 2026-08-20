# UNSAFE_LEDGER.md

Every `unsafe` location in the production crates must be listed here with its
SAFETY justification (charter §7). Unsafe must be rare, isolated, auditable,
justified, and mechanically stressed; semantic logic stays in safe Rust.

## Current state (2026-08-20)

**Zero `unsafe` blocks in the production crates** (`crates/upb-rs*`).
The wire reader, eps-copy stream model, error model, and protocol client are
entirely safe Rust. No FFI exists in the production path; the only C code in
the repository is oracle tooling (`tools/oracle/`, linked against the pinned
upstream `libupb`), which is never linked into or called from the production
crates.

When unsafe is introduced (expected first at the arena implementation, which
may use raw bump-allocation primitives in a narrow `arena/raw` module), every
location must be registered here with: preconditions, pointer provenance,
alignment assumptions, lifetime assumptions, aliasing assumptions,
initialization state, ownership rules, why the preconditions hold, and the
test/invariant that protects it.
