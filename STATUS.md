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
| arena / memory            | MAPPED        | forensics/MEMORY_MODEL.md                             |
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

Phase 0 (archaeology + court infrastructure) is established; five courts are
live and sealed at 0 residuals over the charter boundary-length corpus:
wire-primitives (1537), decode-empty (338), mini-table-inspect (701),
decode-known (517), and decode-submsg (93). The decode-submsg court seals
linked sub-message decode — singular merge semantics, repeated/nested/
recursive sub-messages, depth budget boundaries (MaxDepthExceeded),
truncations, size/budget overruns, unlinked slots — and caught two
implementation defects on the way (the oneof-case-word dump regression,
casefile oneof-case-word-dump; an oracle tooling validation bug). Next
milestones per forensics/OPEN_QUESTIONS.md: maps, groups, and closed enums
(with linked sub-enums), then the encoder court, and the schema synthesis
engine.
