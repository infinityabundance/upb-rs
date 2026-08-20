# BEHAVIOR_ATLAS.md — cross-cutting behavior table

Oracle: `third_party/protobuf` @ `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (37-dev).
All "upstream" citations are file:line at that pin. Status vocabulary (§42 of
the charter, mirrored in `STATUS.md`/`PARITY.toml`): UNMAPPED → MAPPED → MODELED
→ IMPLEMENTED → ORACLE-TESTED → RESIDUALS-OPEN → PARITY-SEALED.

Atlas homes cited below are the sibling atlases in `forensics/` written in the
same archaeological pass (`SURFACE_ATLAS.md` §3 wire / §4 message / §8
json+text / §9 hash, `MEMORY_MODEL.md`, `ERROR_MODEL.md`, `KERNEL_ATLAS.md`,
`SECURITY_HISTORY.md`, `NONDETERMINISM.md`, `QUIRKS.md`, `OPEN_QUESTIONS.md`).
`SOURCE_BASELINE.md` is still absent (see `OPEN_QUESTIONS.md` §5.3).
`crates/upb-rs-core/src/wire.rs` mirrors the wire constants at this pin
(verified by inspection).

## A. Wire decode

| # | Behavior | What upstream does (file:line) | Documented in | Court | Parity |
|---|---|---|---|---|---|
| 1 | varint u64 decode | 1-byte fast path; else add-trick `val += (byte-1)<<7i`, 10-byte bound, 10th byte wraps to bit 63 (`upb/wire/internal/reader.h:41-53`, `upb/wire/reader.c:19-31`) | PARITY.toml `wire.decode.varint` | wire-primitives-v1 | ORACLE-TESTED |
| 2 | varint overflow (>10 bytes / un-terminated 10th) | error (reader.c:29-30) | PARITY.toml `wire.decode.varint` | wire-primitives-v1 | ORACLE-TESTED |
| 3 | overlong varints | accepted, decode to mathematical value (reader.c:22-27) | QUIRKS §1-2 | wire-primitives-v1 | ORACLE-TESTED |
| 4 | tag decode | 5-byte bound + `UINT32_MAX` check (reader.c:33-46; reader.h:55-67) | PARITY.toml `wire.decode.tag` | wire-primitives-v1 | ORACLE-TESTED |
| 5 | tag with field number 0 | error in skip + decode paths (reader.h:131-133; decode.c:989-991, 1014-1016) | QUIRKS §6 | court TBD | UNMAPPED |
| 6 | size decode | 5-byte bound + `INT32_MAX` check, signed int (reader.c:48-61; reader.h:69-81) | PARITY.toml `wire.decode.size` | wire-primitives-v1 | ORACLE-TESTED |
| 7 | fixed32/64 | big-endian swap via `upb_BigEndian32/64` (reader.h:83-106) | PARITY.toml `wire.decode.fixed` | court TBD | MAPPED |
| 8 | invalid wire types 6/7 | error (reader.h:155-159; decode.c:931-934) | `crates/upb-rs-core/src/wire.rs:26-31` | court TBD | MAPPED |
| 9 | scalar decode (varint kinds) | op-table dispatch; int32 truncates u64 silently; bool `!=0`; zigzag for sint (decode.c:139-161, 764-789) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 10 | scalar decode (fixed kinds) | wire-type mask `kFixed32OkMask`/`kFixed64OkMask` else unknown-field (decode.c:880-914) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 11 | packed decode (fixed) | length must be multiple of elem size, else Malformed (decode.c:243-287) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 12 | packed decode (varint) | per-element varint under a sub-limit (decode.c:289-312) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 13 | packed decode (enum, closed) | unknown values skipped, re-encoded as unknown varint field (decode.c:314-347; decoder.h:275-296) | QUIRKS §15 | court TBD | UNMAPPED |
| 14 | unpacked encoding of packable field | accepted (both forms decode; `kUpb_DecodeOp_*` table handles packed and unpacked tags) (decode.c:811-872) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 15 | packed encoding of unpackable field | no packed concept for unpackable types: each delimited payload on repeated string/bytes/message is one element (op tables decode.c:839-856); a *varint* payload on such a field is an unknown field (decode.c:764-789) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 16 | unknown fields (any type) | captured as byte spans, appended to aux in order (decode.c:1010-1081) | SURFACE_ATLAS §4 | court TBD | UNMAPPED |
| 17 | unknown group fields | skipped with depth accounting, stored raw including group tags (decode.c:1028-1035; reader.c:63-80) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 18 | UTF-8 validation on decode | `descriptortype==String` ⇒ validate via utf8_range ⇒ `kUpb_DecodeStatus_BadUtf8`; Bytes never unless alternate+`AlwaysValidateUtf8` (decoder.h:231-263; decode.h:54-62; tests utf8_test.cc:33-126) | SURFACE_ATLAS §8 | court TBD | UNMAPPED |
| 19 | proto2 string = bytes+IsAlternate | stored as Bytes; `FlipValidateUtf8` promotes to String (mini_descriptor/decode.c:242-254; field.h:58) | QUIRKS §15 | court TBD | UNMAPPED |
| 20 | open (proto3) enums | lowered to Int32 in minitable — never value-checked (mini_descriptor/decode.c:128-135) | QUIRKS §15 | court TBD | UNMAPPED |
| 21 | closed (proto2) enums | value-checked on varint path; bad value ⇒ unknown field (decode.c:891-900) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 22 | recursion depth limit | default 100; sub-message and group recursion both decrement (constants.h:11; decode.c:191-205; reader.c:63-68) | QUIRKS §7 | court TBD | UNMAPPED |
| 23 | required-field check | deferred, reported at end; `MissingRequired`; caveats documented (decode.h:35-52; decoder.c:18-29) | ERROR_MODEL.md | court TBD | UNMAPPED |
| 24 | sub-message merge on re-decode | same sub-message object reused, fields merged in place (decode.c:540-592) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 25 | map entry decode | entry parsed into a synthetic `upb_MapEntry`; unknown fields in entry ⇒ whole entry re-encoded to unknowns (decode.c:474-535; encoder.c:48-70) | QUIRKS §15 | court TBD | UNMAPPED |
| 26 | MessageSet decode | item state machine; out-of-order type_id/message tolerated; dup payload ignored; non-item fields dropped (decode.c:594-719) | QUIRKS §10 | court TBD | UNMAPPED |
| 27 | truncated input | zero-padded patch ⇒ parses then Malformed via IsDone (eps_copy_input_stream.h:64-84; eps_copy_input_stream.c:25-47) | QUIRKS §5 | court TBD | UNMAPPED |
| 28 | `AliasString` | strings/unknowns alias input buffer; else copied; adjacent unknowns coalesce (decode.h:31-33; decode.c:118-130; message.c:38-99) | MEMORY_MODEL.md | court TBD | UNMAPPED |
| 29 | `DisableFastTable` | forces the slow (but behaviorally identical) path (decode.h:64-67) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |
| 30 | `upb_DecodeLengthPrefixed` | hand-decodes length varint (≤10 bytes), `> INT32_MAX` ⇒ Malformed (decode.c:1340-1373) | SURFACE_ATLAS §3 | court TBD | UNMAPPED |

## B. Wire encode

| # | Behavior | What upstream does (file:line) | Documented in | Court | Parity |
|---|---|---|---|---|---|
| 31 | base-field order on wire | ascending field number (reverse traversal into a reverse-built buffer) (encoder.c:800-812; mini_descriptor/decode.c:466-538) | NONDETERMINISM §2 | court TBD | UNMAPPED |
| 32 | unknown-field byte order on encode | original forward order, after base fields (encoder.c:776-798) | NONDETERMINISM §6 | court TBD | UNMAPPED |
| 33 | extension order on encode | aux order, after base fields; not interleaved with fields (encoder.c:722-762) | NONDETERMINISM §2 | court TBD | UNMAPPED |
| 34 | map encode (default) | hash-table iteration order (encoder.c:615-637) | NONDETERMINISM §1-2 | court TBD | UNMAPPED |
| 35 | map encode (deterministic) | sorted by key via `_upb_mapsorter` (encoder.c:602-614; map_sorter.c:28-155) | NONDETERMINISM §2 | court TBD | UNMAPPED |
| 36 | map-entry payload order | value before key (encoder.c:579-592) | NONDETERMINISM §2 | court TBD | UNMAPPED |
| 37 | 2 GB size limit | delimited length `> INT32_MAX` ⇒ `MaxSizeExceeded` (encoder.c:282-288) | ERROR_MODEL.md | court TBD | UNMAPPED |
| 38 | presence check (what gets emitted) | proto3 scalar non-zero; hasbit; oneof case; empty arrays/maps skipped (encoder.c:642-678) | SURFACE_ATLAS §4 | court TBD | UNMAPPED |
| 39 | `SkipUnknown` | unknowns not encoded (encode.h:38-39; encoder.c:776-778) | SURFACE_ATLAS | court TBD | UNMAPPED |
| 40 | `CheckRequired` | encode fails if required missing (encode.h:41-42; encoder.c:768-774) | ERROR_MODEL.md | court TBD | UNMAPPED |
| 41 | MessageSet encode | canonical item layout, type_id then message, inside group (encoder.c:695-708) | QUIRKS §10 | court TBD | UNMAPPED |
| 42 | error contract | `*buf = NULL` on failure even for callers ignoring status (encoder.c:824-844) | QUIRKS §13 | court TBD | UNMAPPED |

## C. Message semantics

| # | Behavior | What upstream does (file:line) | Documented in | Court | Parity |
|---|---|---|---|---|---|
| 43 | repeated element order | preserved decode (decode.c:362-433) and encode (encoder.c:457-577); compare is order-sensitive (compare.c:44-63) | NONDETERMINISM §7 | court TBD | UNMAPPED |
| 44 | map equality | order-independent, per-key lookup (compare.c:65-93) | NONDETERMINISM §5 | court TBD | UNMAPPED |
| 45 | unknown-field equality | parse + stable sort by tag + recursive compare, depth 100 (compare.c:248-252; compare_unknown.c:101-163, 321-354) | NONDETERMINISM §5 | court TBD | UNMAPPED |
| 46 | extension equality | per-extension lookup both ways; maps can't be extensions (compare.c:192-239) | NONDETERMINISM §5 | court TBD | UNMAPPED |
| 47 | partial compare (`kUpb_CompareOption_Partial`) | only msg2's fields checked; maps allow msg1 ⊇ msg2 (compare.c:70-78, 143-152) | SURFACE_ATLAS | court TBD | UNMAPPED |
| 48 | presence (proto2 hasbit / oneof case / proto3 default) | `HasPresence`/`DataIsZero`/oneof-case discriminators (internal/accessors.h; encode_shouldencode encoder.c:642-678) | SURFACE_ATLAS §4 | court TBD | UNMAPPED |
| 49 | oneof set semantics | setting a member clears the previous (decode.c:549-557; accessors.h:892-896) | SURFACE_ATLAS §4 | court TBD | UNMAPPED |
| 50 | merge (`upb_Message_MergeFrom`) | encode(src, non-deterministic) + decode into dst; appends unknowns, overwrites scalars, merges submessages (merge.c:14-38) | NONDETERMINISM §6 | court TBD | UNMAPPED |
| 51 | clear | `memset` message + `in->size = 0`; aux memory arena-leaked (internal/accessors.h:876-885) | QUIRKS §15 | court TBD | UNMAPPED |
| 52 | deep copy/clone | field-by-field; unknowns/extensions cloned in aux order; strings re-copied; `upb_Map_Next` iteration order used for maps (copy.c:186-304) | NONDETERMINISM §6 | court TBD | UNMAPPED |
| 53 | shallow copy | memcpy + shallow aux clone; string views aliased (copy.c:306-342) | MEMORY_MODEL.md | court TBD | UNMAPPED |
| 54 | map insert/replace | remove-then-insert; returns Replaced; relocates entry (internal/map.h:172-203) | NONDETERMINISM §1.1 | court TBD | UNMAPPED |
| 55 | unknown delete | prefix-strip / truncate / split with memmove order preservation (unknown_fields.c:82-154) | NONDETERMINISM §6 | court TBD | UNMAPPED |
| 56 | extension promotion | `GetOrPromoteExtension` re-parses unknowns; message-only; depth 100 (promote.c:118-200) | QUIRKS §12 | court TBD | UNMAPPED |
| 57 | freeze | transitive freeze of fields/extensions/maps/arrays (message.c:191-258) | MEMORY_MODEL.md | court TBD | UNMAPPED |

## D. JSON

| # | Behavior | What upstream does (file:line) | Documented in | Court | Parity |
|---|---|---|---|---|---|
| 58 | field order in JSON output | ascending field number, then extensions in aux order (encode.c:741-763; reflection/message.c:137-195) | NONDETERMINISM §3 | court TBD | UNMAPPED |
| 59 | JSON map order | hash order, unsorted (encode.c:690-710) | NONDETERMINISM §3 | court TBD | UNMAPPED |
| 60 | 64-bit ints | quoted strings on encode (encode.c:623-628); double-mediated range checks + exact string parse on decode (decode.c:697-769) | QUIRKS §11 | court TBD | UNMAPPED |
| 61 | NaN/Infinity/-Infinity | quoted on encode; accepted on decode (encode.c:315-326; decode.c:785-790) | QUIRKS §11 | court TBD | UNMAPPED |
| 62 | duplicate JSON keys | no detection; last wins (decode.c:1025-1033) | QUIRKS §11 | court TBD | UNMAPPED |
| 63 | enum values in JSON | name lookup by json_name; unknown ⇒ error/ignore (decode.c:829-862); unknown numbers print as ints (encode.c:209-227) | QUIRKS §11 | court TBD | UNMAPPED |
| 64 | JSON number grammar | no leading zero; strtod superset; ERANGE check disabled; `> DBL_MAX` errors (decode.c:293-360) | QUIRKS §11 | court TBD | UNMAPPED |
| 65 | bytes in JSON | standard base64 with padding (encode.c:229-266); relaxed decode (unpadded ok, decode.c:610-647) | SURFACE_ATLAS §8 | court TBD | UNMAPPED |
| 66 | wrappers/Any/Timestamp/Duration/FieldMask/Struct/Value/ListValue | well-known-type special-casing (encode.c:342-562, jsonenc_msgfield encode.c:564-603; decode.c:1126-1564) | SURFACE_ATLAS §8 | court TBD | UNMAPPED |
| 67 | Timestamp bounds | 0001-01-01..9999-12-31 enforced on encode (encode.c:143-151); nanos 3/6/9-digit trimmed (encode.c:119-133) | SURFACE_ATLAS §8 | court TBD | UNMAPPED |

## E. Text format

| # | Behavior | What upstream does (file:line) | Documented in | Court | Parity |
|---|---|---|---|---|---|
| 68 | text map order | sorted by default; `UPB_TXTENC_NOSORT` = hash order (text/encode.c:139-164; options.h:18-19) | NONDETERMINISM §4 | court TBD | UNMAPPED |
| 69 | text unknown fields | printed after fields; unparseable segments dropped silently (text/encode.c:182; text/internal/encode.c:136-154) | NONDETERMINISM §4 | court TBD | UNMAPPED |

## F. Cross-cutting

| # | Behavior | What upstream does (file:line) | Documented in | Court | Parity |
|---|---|---|---|---|---|
| 70 | map iteration order (string keys) | ASLR-seeded wyhash ⇒ per-process random; slot scan (common.c:521-532, 285-293) | NONDETERMINISM §1 | court TBD | UNMAPPED |
| 71 | map iteration order (int keys) | unseeded hash; deterministic per construction history (common.c:89-97) | NONDETERMINISM §1 | court TBD | UNMAPPED |
| 72 | def-pool symbol storage | strtable/inttable (hash) but no public iteration API (def_pool.c:41-55) | NONDETERMINISM §8 | n/a | UNMAPPED |
| 73 | file-level def iteration | declaration-order arrays (file_def.c:31-58) | NONDETERMINISM §8 | court TBD | UNMAPPED |
| 74 | memory model (arena, aux_data) | arena bump alloc; aux_data tagged-ptr array with capacity growth (message.c:38-99; mem/arena.h:38-42) | MEMORY_MODEL.md | court TBD | MAPPED |
| 75 | error model | longjmp-based `upb_ErrorHandler`; status strings (error_handler.h:25; decode.c:1375-1392) | ERROR_MODEL.md | court TBD | MAPPED |

## Status rollup

- **ORACLE-TESTED:** varint/tag/size decode (rows 1-6) — `courts/wire-primitives` (PARITY.toml).
- **MAPPED:** fixed decode (7), invalid wire types (8), memory (74), error model (75).
- **UNMAPPED:** everything else (all court TBD).
- No surface is MODELED/IMPLEMENTED/RESIDUALS-OPEN/PARITY-SEALED at this time
  (`STATUS.md` "Current phase": Phase 0 archaeology + first Phase 2 court).
