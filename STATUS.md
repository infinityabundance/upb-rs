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
| wire decode: message (known fields) | RESIDUALS-OPEN | courts/decode-known (339/366 cases; 27 residuals, all in the SInt32/SInt64 zigzag munge path) |
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

Phase 0 (archaeology + court infrastructure) is established; the wire-primitives,
decode-empty, and mini-table-inspect courts are live and sealed at 0 residuals
over the charter boundary-length corpus. The decode-known court (known-field
message decode) is live at RESIDUALS-OPEN: 339/366 cases equal, with 27
residuals confined to the SInt32/SInt64 zigzag munge bit pattern
(casefiles dk-sint32-*, dk-sint64-*, dk-psint32-* in the latest
receipts/decode-known-v1-*). Next milestones per forensics/OPEN_QUESTIONS.md:
close the zigzag residuals, then submessages/maps/closed-enum decode, the
encoder court, and the schema synthesis engine.
