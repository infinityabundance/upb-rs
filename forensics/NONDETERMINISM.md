# NONDETERMINISM.md — where upb's output order is (un)specified

Oracle: `third_party/protobuf` @ `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (37-dev).
All file:line citations are against that pin. Anything not verified in source is
marked **UNVERIFIED**.

Terminology: "slot order" = physical entry-array index order of an open-addressed
hash table. "aux order" = order of `upb_Message_Internal::aux_data[]` (the
message's extension/unknown record, `upb/message/internal/message.h:29-43`).

---

## 0. Surface inventory (what can vary, and its root cause)

| Surface | Can vary | Root cause | Upstream documents it? | Court strategy |
|---|---|---|---|---|
| String-keyed map iteration | order of entries | ASLR-seeded wyhash + slot scan | Yes, comment `upb/hash/common.c:523-528` | compare sorted-normalized forms |
| Int-keyed map iteration | order of entries (stable per construction sequence) | unseeded `upb_inthash` + slot scan; resize/replace changes layout | No comment | compare sorted-normalized forms (or `upb_Message_IsEqual`) |
| Wire encode, non-deterministic mode | map entry order; extension order | hash-order iteration (encoder.c:615-637) + aux-order extensions (encoder.c:722-762) | Yes, flag docs `upb/wire/encode.h:29-43`; extension comment `encoder.c:730-732` | byte-exact only in deterministic mode; else decode both sides |
| Wire encode, deterministic mode | nothing (fully ordered) | `_upb_mapsorter` sorts keys/extensions (encoder.c:602-614, 742-753) | Yes, flag docs | byte-exact |
| JSON encode | map entry order | `upb_Map_Next` hash order, no sort (`upb/json/encode.c:690-710`) | No | sort-normalize the JSON object |
| Text encode | map entry order | sorted by default; `UPB_TXTENC_NOSORT` opts out (`upb/text/encode.c:139-164`) | Yes, option doc `upb/text/options.h:18-19` | byte-exact (default) |
| Def-pool symbol iteration | N/A at this pin: no public iteration API | `syms`/`files` are strtables (`upb/reflection/def_pool.c:41-55`) | N/A | N/A |

The **only** nondeterminism upb deliberately engineers is the string-hash seed;
everything else that varies is an emergent consequence of hash layout or of
not sorting. There is no RNG in the hot path (seed is `&_upb_seed`, an address).

---

## 1. Map iteration order

### 1.1 The hash table (`upb/hash/common.c`)

- Table: open addressing, one `upb_tabent` per slot, linear-probing chains threaded
  through `upb_tabent_next()`; mask = size-1 (common.c:99-101). Load factor 0.875:
  `isfull()` = `count == size - (size>>3)` (common.c:103-107).
- Int hash, **unseeded, deterministic**: `upb_inthash` = XOR-fold of the key
  (common.c:89-97).
- String hash: wyhash (absl-derived, common.c:382-510) with fixed salt
  `kWyhashSalt` (common.c:512-515) and a seed from `_upb_Seed()` =
  `(uint64_t)&_upb_seed` — the address of a static variable, i.e. ASLR
  randomness (common.c:521-528). The comment is explicit:

  > "This does not provide high-quality randomness, but it should be enough to
  > prevent unit tests from relying on a deterministic map ordering. By
  > returning the address of a variable, we are able to get some randomness for
  > free provided that ASLR is enabled." (common.c:523-527)

  **Consequences:** (a) without ASLR, or with ASLR disabled, the seed is fixed
  and string-map order becomes reproducible; (b) the seed is constant within one
  process, so a table built twice in one process with identical insert
  sequences has identical layout; (c) hash **values** are per-process
  unpredictable, but the **order** is fully determined by (seed, key set,
  table size, insertion history).
- Resize doubles capacity when full (strtable: common.c:595-599 + `resize`
  common.c:566-591; inttable: common.c:818-835) and **rehashes everything** —
  iteration order after a resize is unrelated to order before it.
- Deletes compact the chain in place (common.c:235-283); `removeiter`
  explicitly moves a later element into the removed slot (common.c:314-361).
- Map key table selection (`upb/message/map.c:179-195`): keys whose size fits a
  `uintptr_t` (i.e. ≤8 bytes, all integer/bool keys) use `upb_inttable`
  (deterministic hash); string/bytes keys use `upb_strtable` (seeded hash).
  Note `UPB_MAPTYPE_STRING` (a size_t marker) is what makes string keys take
  the strtable path.
- Map replace = remove-then-insert (`upb/message/internal/map.h:172-203`):
  overwriting a key relocates that entry (and for string keys allocates a fresh
  key copy, common.c:593-611) — so even "just update one value" perturbs order.

### 1.2 Iteration is slot scan

`next()` scans `entries[i]` upward for the next non-empty slot
(common.c:285-291); `begin()` = first non-empty slot (common.c:293);
`upb_strtable_next2` / `upb_inttable_next` wrap it (common.c:662-671, 866-876).
`upb_Map_Next` dispatches to those (map.c:82-103). Hence iteration order is
hash-slot order, not insertion order and not key order.

> **Correction note (cross-atlas):** `forensics/SURFACE_ATLAS.md` §4 row for
> `upb/message/map.h` claims "iteration order is insert order (`kUpb_Map_Begin`
> = `(size_t)-1`, :84)". That is **incorrect** per the pinned source above:
> iteration is hash-slot order (seeded for string keys). `kUpb_Map_Begin` is
> only the sentinel start value `(size_t)-1` (map.h:84), not an insertion
> index. The SURFACE_ATLAS row should be reconciled to this document.

### 1.3 History (git)

- `26148bedc` 2025-01-29 "Hard-code a random constant as upb's hash seed".
- `066531df7` 2025-01-31 "Randomize upb's map ordering" — introduces the
  ASLR-address `_upb_Seed()` mechanism.
- `6bde8c417` 2025-02-03 "Revert upb map randomization", then same-day
  `8ef81fbd9` "Automated rollback of commit 6bde8c417…" — randomization is
  live at this pin. (Older upb history predates the protobuf-repo merge and is
  not reachable in this clone; earliest in-clone trace of the varint trick is
  `501ececd3` 2023-09-26 "Reorganize upb file structure".)

### 1.4 Invariants that remain

- Within one process and one construction sequence, layout is reproducible.
- Map **contents** are deterministic; only entry **order** varies.
- `upb_Message_IsEqual` and `upb_UnknownFieldsAreEqual` are order-independent
  for maps/unknowns (see §5), so equality never depends on hash order.

---

## 2. Wire encode ordering (`upb/wire/internal/encoder.c`)

The encoder writes **backwards** (back-allocator, `upb/wire/internal/back_alloc.c`)
and compensates:

- Base fields: emitted field-by-field from the last mini-table field to the
  first (encoder.c:800-812), so the output byte stream has fields in ascending
  field-number order (mini-tables are built in ascending order —
  `upb/mini_descriptor/decode.c:466-538`, field numbers advance by encoded
  deltas). Comment: "Iterate backwards because the encoder builds the buffer in
  reverse (from end to start)" (encoder.c:779-781).
- Unknowns + non-canonical extensions: iterated over `aux_data` **backwards**
  (encoder.c:782-797) so they are emitted in original forward order, after all
  base fields and interleaved by arrival order.
- Canonical extensions: `encode_exts` (encoder.c:722-762). Non-deterministic
  mode iterates `_upb_Message_NextExtensionReverse` (aux order, message.h:450-471).
  The upstream comment is the definitive statement on extension ordering:

  > "Encode all canonical extensions together. Unlike C++, we do not attempt to
  > keep these in field number order relative to normal fields or even to each
  > other." (encoder.c:730-732)

  Deterministic mode sorts extensions by extension number via
  `_upb_mapsorter_pushexts` (encoder.c:742-753; sorter cmp at
  `upb/message/map_sorter.c:157-184`).
- Maps: deterministic mode sorts entries by key type via `_upb_mapsorter_pushmap`
  (encoder.c:602-614); otherwise hash order (encoder.c:615-637).
- Map entry payload: **value first, then key** (encoder.c:579-592) — the
  canonical protobuf map-entry encoding.
- Length limit: a delimited length > INT32_MAX fails encode with
  `kUpb_EncodeStatus_MaxSizeExceeded` (encoder.c:282-288) — the 2 GB wire limit.

`kUpb_EncodeOption_Deterministic` documentation (encode.h:29-36):

> "If set, the results of serializing will be deterministic across all
> instances of this binary. There are no guarantees across different binary
> builds. If your proto contains maps, the encoder will need to malloc()/free()
> memory during encode."

So even deterministic mode is not byte-stable across toolchains/builds (qsort
comparators are stable-by-key, but the phrase scopes the guarantee to "this
binary"). A court may still byte-compare two deterministic encodes of the same
message in one binary/run.

---

## 3. JSON encode (`upb/json/encode.c`)

- Field order: `jsonenc_msgfields` (encode.c:741-763) uses `upb_Message_Next`
  (`upb/reflection/message.c:137-195`): base fields in ascending field-number
  order, then canonical extensions in aux order. With
  `upb_JsonEncode_EmitDefaults`, fields iterate in definition order with a
  presence filter (encode.c:746-755).
- Map order: `jsonenc_map` (encode.c:690-710) calls `upb_Map_Next` — **hash
  order, unsorted**. String-keyed maps therefore print in ASLR-randomized
  order; int-keyed maps print in deterministic-but-hash order.
- Extension keys print as `"[fullname]"` (encode.c:718-722).
- Int64/UInt64 print as JSON strings (encode.c:623-628); enums print as names
  unless `upb_JsonEncode_FormatEnumsAsIntegers` (encode.c:209-227);
  `google.protobuf.NullValue` prints as bare `null` (encode.c:212-213).

---

## 4. Text encode (`upb/text/encode.c`)

- Maps: **sorted by key** by default through the same `_upb_mapsorter`
  (encode.c:147-163); `UPB_TXTENC_NOSORT` switches to hash order
  (encode.c:141-146; option documented in `upb/text/options.h:18-19`:
  "maps are *not* sorted (this avoids allocating tmp mem)").
- Message fields: `upb_Message_Next` order (encode.c:166-183), then unknown
  fields parsed and printed (encode.c:182); unknown segments that fail to parse
  are silently dropped (text/internal/encode.c:136-154).

---

## 5. Comparison semantics (`upb/message/compare.c`, `internal/compare_unknown.c`)

- Maps: **order-independent**. `_upb_Map_IsEqual` iterates map2 and does a
  per-key `upb_Map_Get` on map1 (compare.c:65-93). Partial mode allows
  map1 ⊇ map2 (compare.c:74-78).
- Repeated fields: **order-dependent**, element-by-element (compare.c:44-63).
- Base fields: compared in the same mini-table iteration order for both
  messages; `f1 != f2` implies not equal (compare.c:143-190). Order itself is
  never the discriminator.
- Extensions: iterates msg2's extensions and looks each up in msg1
  (compare.c:192-239); maps cannot be extensions (compare.c:222).
- Unknown fields: **order-independent**. Parsed into per-tag records and sorted
  by tag with an in-order stable merge sort — "We have to implement our own
  sort here, since qsort() is not an in-order sort" (compare_unknown.c:101-102) —
  then compared element-wise, groups compared recursively, depth capped at 100
  (compare_unknown.c:321-354, 404-423). Same tag+value in different orders ⇒
  equal.

---

## 6. Unknown-field byte order — preserved everywhere

- Storage: segments appended to `aux_data` in parse order
  (`_upb_Message_AddUnknown` family, `upb/message/internal/message.h:380-384`,
  message.c:38-161). Message.h:48: "Iterates in the order unknown fields were
  parsed."
- Decode: unknowns are captured as contiguous spans and appended
  (`upb/wire/decode.c:1010-1081`, `_upb_Decoder_GetAddUnknownMode` decode.c:118-130;
  with `kUpb_DecodeOption_AliasString` adjacent spans are coalesced —
  `kUpb_AddUnknown_AliasAllowMerge`, common.c alias path message.c:38-99 — still
  in order). A truncated-parse edge case: `_upb_Decoder_DecodeEmptyMessage`
  captures the whole message as one unknown segment (decode.c:1205-1239).
- Re-encode: aux reversed while writing backwards ⇒ original byte order
  (encoder.c:776-798).
- Delete: `upb_Message_DeleteUnknown2` explicitly `memmove`s later entries so
  "unknown field ordering is preserved" (`upb/message/unknown_fields.c:137-141`);
  prefix-strip/truncate/split operations keep the remainder in place
  (unknown_fields.c:106-150).
- Copy/clone: iterates `aux_data` 0..size (copy.c:247-281); merge re-encodes
  src (order preserved per §2) and decodes into dst, appending src's unknowns
  after dst's (`upb/message/merge.c:14-38`).
- **Verified invariant:** byte order of unknown fields survives decode → encode
  → copy → delete round trips; it is not canonicalized anywhere. (Not verified:
  interaction of AliasString coalescing with interleaved non-canonical
  extensions — **UNVERIFIED** edge.)

---

## 7. Repeated-field element order — preserved

- Decode: `_upb_Decoder_DecodeToArray` appends in wire order for scalars,
  strings, and messages (decode.c:362-433); packed decoders append per-element
  in order (`_upb_Decoder_DecodeFixedPacked` decode.c:243-287,
  `DecodeVarintPacked` decode.c:289-312, `DecodeEnumPacked` decode.c:314-347 —
  note unknown enum values are skipped, not appended, and re-encoded to unknown
  fields, decoder.h:275-296).
- Encode: `encode_array` walks the array from the end while writing backwards,
  net effect = forward order (encoder.c:457-577). Packed/unpacked both preserve
  element order.
- Compare: order-dependent (§5).

---

## 8. Enum / extension / def-pool iteration

- Enum values: `upb_EnumDef_ValueCount`/`Value` index a declaration-order array
  (enum_def.c; **UNVERIFIED** — array layout asserted, definition order inferred
  from build path `_upb_EnumDef_BuildValues`). JSON/text lookup by number uses
  the same array; no hash involved.
- Extensions on a message: aux order (insertion/parse order), interleaved with
  unknowns (message.h:422-448); reverse accessor at message.h:450-471. No
  sorting outside deterministic encode (§2).
- Def pool: symbols live in `syms`/`files` strtables and extensions in an
  inttable (def_pool.c:41-55) — hash order. **There is no public iteration API
  over pool symbols at this pin** (grep of `upb/reflection/*.h` finds only
  lookup/getters), so this is not observable through the C API. File-level
  iteration (top-level messages/enums/exts/services) is over declaration-order
  arrays in `upb_FileDef` (file_def.c:31-58).

---

## 9. What a differential court may assume (invariants)

1. Map **membership**, not order, is the semantic state; `upb_Message_IsEqual`
   agrees with set equality (compare.c:65-93).
2. Unknown fields are an ordered byte sequence **per message**; order is
   preserved by decode/encode/copy/delete (citations in §6), but not by merge
   interleaving (merge appends, merge.c:14-38).
3. Repeated elements are ordered; element order is preserved end-to-end (§7).
4. Non-deterministic wire encode of the same message twice in one process with
   no intervening map mutation yields **identical bytes** (seed is process-constant).
   Across processes it may differ only in map/extension order — but extension
   order depends on aux order, which is parse-order, so it is stable per
   construction history.
5. Deterministic mode yields byte-stable output for a fixed binary (§2).

## 10. Court protocol that does not weaken

- **Wire bytes (any mode):** never compare raw non-deterministic outputs for
  byte equality. Decode both candidate outputs with the oracle
  (`upb_Decode`) and compare the decoded messages with `upb_Message_IsEqual`
  (include-unknowns variant, compare.c:248-252, which itself normalizes
  unknown order). This is equivalence without weakening: it is exactly the
  oracle's own equality.
- **Deterministic mode:** byte-exact comparison is valid (encode.h:29-36 scopes
  it to the binary; run both sides in the same process).
- **Maps:** normalize by sorting entries (mirror `_upb_mapsorter` comparators,
  map_sorter.c:28-105 — note string compare is `memcmp` on common prefix then
  length, and `-cmp` is returned on mismatch, a subtle inversion) before
  comparing.
- **Unknown fields:** parse into (tag,value) records, stable-sort by tag like
  compare_unknown.c:101-163, compare records recursively with depth cap 100 —
  or simply rely on `_upb_Message_UnknownFieldsAreEqual`.
- **JSON:** parse both outputs into an ordered map (or per-key lookups) instead
  of string comparison; or sort object keys of both and then byte-compare.
- **Text:** default mode is already sorted (encode.c:147-163); `NOSORT` outputs
  need map normalization.
- Guardrail: when a court needs *some* byte-level check in non-deterministic
  mode, restrict to messages with no maps and no extensions (order is then
  fully deterministic: fields ascending, unknowns in parse order).

## 11. Unverified / open

- Exact upstream documentation of map-order nondeterminism beyond
  common.c:523-528 and the encode.h deterministic-flag note: none found.
- Whether ASLR is disabled in the oracle build environment (affects whether
  string-map order is even random in CI): not checked.
- enum_def.c value-array ordering claim (§8): inferred, not read.

## 12. Sibling documents

Written in the same archaeological pass: `SURFACE_ATLAS.md` (surface
inventory), `MEMORY_MODEL.md`, `ERROR_MODEL.md`, `KERNEL_ATLAS.md`,
`PERFORMANCE_MODEL.md`, `SECURITY_HISTORY.md`, `QUIRKS.md` (behavior
catalog), `BEHAVIOR_ATLAS.md` (cross-cutting parity table), and
`OPEN_QUESTIONS.md` (work queue; notes `SOURCE_BASELINE.md` is still absent).
The court protocol in §10 feeds `tools/court-runner` and the phase plan in
`OPEN_QUESTIONS.md` §1.
