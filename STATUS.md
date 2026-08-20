# STATUS.md — court exit criteria per surface

States (§42): UNMAPPED → MAPPED → MODELED → IMPLEMENTED → ORACLE-TESTED →
RESIDUALS-OPEN → PARITY-SEALED.

A surface is never PARITY-SEALED while unexplained residuals remain.
Completion is defined by court exit criteria, not by compilation or
happy-path tests.

| Surface                   | State         | Court / evidence                                       |
|---------------------------|---------------|--------------------------------------------------------|
| wire decode: varint       | ORACLE-TESTED | courts/wire-primitives (1537 cases, 0 residuals)       |
| wire decode: tag          | ORACLE-TESTED | courts/wire-primitives (1537 cases, 0 residuals)       |
| wire decode: size         | ORACLE-TESTED | courts/wire-primitives (1537 cases, 0 residuals)       |
| wire decode: fixed32/64   | ORACLE-TESTED | courts/wire-primitives (1537 cases, 0 residuals)       |
| wire decode: skip         | ORACLE-TESTED | courts/wire-primitives (1537 cases, 0 residuals)       |
| wire decode: message (empty mini table, pure unknown fields) | ORACLE-TESTED | courts/decode-empty (338 cases, 0 residuals) |
| wire decode: message (known fields) | PARITY-SEALED | courts/decode-known (517 cases, 0 residuals; scope: scalars, strings/bytes, repeated, oneofs) |
| wire decode: sub-messages | PARITY-SEALED | courts/decode-submsg (259 cases, 0 residuals; merge, repeated, nested, recursive, depth limits) |
| wire decode: maps         | PARITY-SEALED | courts/decode-submsg (259 cases, 0 residuals; map fields, last-wins, unknown-entry re-encode, message values, nested maps) |
| wire decode: groups       | PARITY-SEALED | courts/decode-submsg (259 cases, 0 residuals; singular/merge, repeated, nested, oneof, unlinked, depth, malformed EndGroup) |
| wire decode: closed enums | PARITY-SEALED | courts/decode-submsg (259 cases, 0 residuals; valid/invalid/overlong/negative values, packed re-encode, map-value enums, SetSubEnum include-0 rule) |
| wire encode               | UNMAPPED      | —                                                     |
| mini tables               | ORACLE-TESTED | courts/mini-table-inspect (701 cases, 0 residuals)  |
| mini descriptors          | ORACLE-TESTED | courts/mini-table-inspect (701 cases, 0 residuals)  |
| arena / memory            | PARITY-SEALED | courts/arena (61 cases, 0 residuals; forensics/MEMORY_MODEL.md) |
| arrays                    | PARITY-SEALED | courts/collections (52 cases, 0 residuals; numeric ctypes) |
| maps (content)            | PARITY-SEALED | courts/collections (52 cases, 0 residuals; iteration as sorted set) |
| error model               | MAPPED        | forensics/ERROR_MODEL.md                              |
| reflection                | UNMAPPED      | —                                                     |
| JSON                      | UNMAPPED      | —                                                     |
| text format               | UNMAPPED      | —                                                     |
| unknown fields            | UNMAPPED      | —                                                     |
| conformance suite         | UNMAPPED      | conformance/                                          |
| Rust kernel integration   | UNMAPPED      | forensics/KERNEL_ATLAS.md                             |
| C ABI                     | UNMAPPED      | abi/                                                  |
| security corpus           | MAPPED        | forensics/SECURITY_HISTORY.md                         |

## Current phase

Phase 0 (archaeology + court infrastructure) is established; seven courts are
live and sealed at 0 residuals over the charter boundary-length corpus:
wire-primitives (1537), decode-empty (338), mini-table-inspect (701),
decode-known (517), decode-submsg (259), arena (61), and collections (52).
Phase 1 (core representation + arena) is sealed: the ArenaPool, Array, and
Map models are PARITY-SEALED against the real upb_Arena / upb_Array /
upb_Map. Phase 2 (binary wire parity) is underway: map fields, group fields,
and closed-enum fields decode are sealed inside the decode-submsg court
(184 -> 259 cases; last-wins inserts, empty entries, string keys/values,
message values, nested maps, unknown-inside-entry re-encode via
AddMapEntryUnknown, group merge/bounds, closed-enum raw-span preservation and
packed re-encode, negative values, the SetSubEnum include-0 rule). Next
milestones per forensics/OPEN_QUESTIONS.md: the encoder court (wire.encode),
then merge/clear/clone and unknown handling, then deterministic mode.
