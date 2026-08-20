# oracle-map-iterate-begin — oracle emitter bug exposed by the collections court

**Status**: FIXED (oracle tooling defect; the fix is regression-covered by the
permanent collections corpus — this casefile is the evidence record per
charter §21).
**Court**: `collections-v1` (casefiles `col-000009` `bool-u32`,
`col-000010` `double-double`, `col-000032`+ `rand-map-*`; historical
receipts under `receipts/collections-v1-*` retain the full residual
records).
**Oracle**: protobuf `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`.
**Date**: 2026-08-20.

## What it is

The oracle's `map_trace` iterate op initialized its iteration state with
`size_t iter = 0`. upb's table iterator (`_upb_tablenext`,
`upb/hash/common.c:296-306` with the scan helper `next()`) **increments the
state before scanning** (`++i` first), so the canonical starting state is
`kUpb_Map_Begin` = `(size_t)-1` (`upb/message/map.h:84`). Starting at 0
silently skipped any entry whose hash position was slot 0, so the oracle
reported `"entries":[]` for maps whose entries landed there.

## Why it existed

The iterate op was smoke-tested with string keys and a handful of numeric
keys that happened to hash to non-zero slots; `u32-u32` also passed by
hash-position luck. Only a corpus with many small maps (the `rand-map-*`
cases, keys 0..6 against a fresh 4-slot table) forced an entry into slot 0.

## When it was introduced

With the `map_trace` op in the collections-court tooling (Phase 1).

## What relies on it

The `map_trace` iterate output is the map differential surface. The fix
(`iter = kUpb_Map_Begin`) is in `tools/oracle/src/oracle.c`; the DUT
already compared iteration as a sorted set, so no DUT change was needed.

## What would break if "cleaned up"

None — this was purely oracle tooling. But note the general lesson: upb's
`*_Next` iterator protocol is *advance-then-test*, which is easy to get
wrong at the call site; every future oracle op that iterates must start at
`kUpb_Map_Begin` (`(size_t)-1`) or the documented equivalent for the table
type.

## Which court preserves it

`collections-v1` — the `rand-map-*` and `bool-u32`/`double-double` cases
remain in the permanent corpus (seed `0x757062636f`).
