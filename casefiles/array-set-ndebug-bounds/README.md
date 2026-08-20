# array-set-ndebug-bounds — `upb_Array_Set` bounds semantics and the §49 divergence

**Status**: MODELED-AS-DOCUMENTED (upstream behavior preserved within
bounds; the heap-overflow case is refused — see below).
**Court**: `collections-v1` (the `uint32-basic` and `boundary-sizes` cases
exercise in-bounds `set`; no corpus case produces an out-of-bounds index —
by design).
**Oracle**: protobuf `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`.
**Date**: 2026-08-20.

## What it is

`upb_Array_Set` (`upb/message/array.c:80-85`) contains
`UPB_ASSERT(i < upb_Array_Size(arr))` — a **debug-only** assertion. In
NDEBUG builds (the pinned oracle and any release libupb) it is compiled
out, and the function writes into the element buffer unconditionally:

- `i < size`: normal element overwrite (both DUT and C agree byte-for-byte).
- `size <= i < capacity`: upstream writes into the uninitialized-but-
  allocated region. **Oracle-verified never-observable**: every size-growth
  path re-initializes the region between the old and new sizes
  (`upb_Array_Resize` zero-fills `[oldsize, newsize)`, array.c:147-161;
  `upb_Array_Append` writes the new last slot), so a write at `i >= size` is
  erased before it could ever be dumped — the only observable effect is
  `ok == true`. The DUT mirrors upstream exactly: `Array::set` writes into
  the element buffer whenever `i < capacity`, regardless of `size` (the
  byte is kept for exact-memory fidelity, though no observable depends on
  it), and reports success.
- `i >= capacity`: upstream writes past the end of the heap allocation —
  C undefined behavior (heap overflow). The DUT **refuses** (`set` returns
  false) instead of reproducing it.

## Why it exists

The assertion is a debug aid; NDEBUG builds trade the check for speed. The
API contract is effectively "the caller must pass a valid index", and the
write is not bounds-checked in release builds.

## When it was introduced

`upb_Array_Set` has had this shape for the lifetime of the pinned tree;
the DUT's original model bounds-checked against `size` (stricter than
upstream) and was corrected during the collections court archaeology.

## What relies on it

Generated code and the decoder only ever `Set` indices `< size` (the
decoder appends/resizes first). The observable difference matters only for
adversarial or buggy callers.

## What would break if "cleaned up"

Nothing upstream — but a Rust model that *silently wrote* at `i >=
capacity` would create a memory-safety hole (buffer overflow in the DUT's
owned storage). Per charter §49, a memory-safety vulnerability is not a
compatibility requirement: the accepted/rejected contract is preserved
(in-bounds writes succeed, including the invisible `size <= i < capacity`
case), the unsafe consequence is eliminated, and this divergence is
documented rather than reproduced.

## Which court preserves it

`collections-v1` `uint32-basic` (set at index 0 with size 5) and
`boundary-sizes` (set at index 2 with size 3, plus out-of-bounds `get`
rejected). The `size <= i < capacity` case (ok=true, invisible write) was
verified by direct oracle interrogation: `new(4) append(1) set(3)
resize(2) resize(4)` dumps `01000000`, `0100000000000000`, and
`01000000000000000000000000000000` — the write at slot 3 is never dumped
and is erased by the second resize's zero-fill.
