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
| wire encode               | PARITY-SEALED | courts/encode (3129 cases, 0 residuals; 3127 byte-exact + 2 classified map-order; presence semantics, deterministic reversed sort, SkipUnknown, depth off-by-one) |
| message ops (merge/clear/clone) | PARITY-SEALED | courts/msgop (544 cases, 0 residuals; 543 byte-exact + 1 classified map-order; MergeFrom = encode+decode, Clear, DeepClone presence re-set) |
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

Phase 0 (archaeology + court infrastructure) is established; nine courts are
live and sealed at 0 residuals over the charter boundary-length corpus:
wire-primitives (1537), decode-empty (338), mini-table-inspect (701),
decode-known (517), decode-submsg (259), encode (3129), msgop (544), arena
(61), and collections (52).
Phase 1 (core representation + arena) is sealed: the ArenaPool, Array, and
Map models are PARITY-SEALED against the real upb_Arena / upb_Array /
upb_Map. Phase 2 (binary wire parity) is underway: the decoder surface
(maps, groups, closed enums), the encoder surface (options 0 / Deterministic /
SkipUnknown), and the message-operations surface (MergeFrom / Clear /
DeepClone) are sealed; remaining Phase-2 items per forensics/OPEN_QUESTIONS.md:
unknown-field handling courts (discard-unknown at the reflection level is a
Phase-4 surface), then Phase 3 mini descriptors at scale.
