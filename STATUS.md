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
| wire decode: sub-messages | PARITY-SEALED | courts/decode-submsg (93 cases, 0 residuals; merge, repeated, nested, recursive, depth limits) |
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

Phase 0 (archaeology + court infrastructure) is established; eight courts are
live and sealed at 0 residuals over the charter boundary-length corpus:
wire-primitives (1537), decode-empty (338), mini-table-inspect (701),
decode-known (517), decode-submsg (93), arena (61), and collections (52).
Phase 1 (core representation + arena) is sealed: the ArenaPool, Array, and Map
models are PARITY-SEALED against the real upb_Arena / upb_Array / upb_Map.
The collections court exposed two tooling defects on the way (an oracle
emitter bug — map iteration must start at kUpb_Map_Begin, otherwise entries
hashing to slot 0 are skipped; and a corpus encoding bug — numeric map
keys/values must be exactly key_size/val_size bytes, the DUT now enforces
this loudly). Next milestones per forensics/OPEN_QUESTIONS.md: wire encode,
maps-as-message-fields (MapEntry slot linking, _upb_Decoder_DecodeToMap),
groups, and closed enums, then the schema synthesis engine.
