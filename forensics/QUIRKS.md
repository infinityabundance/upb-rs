# QUIRKS.md — non-obvious upstream behaviors a naive reimplementation gets wrong

Oracle: `third_party/protobuf` @ `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (37-dev).
Every claim below was verified against the pinned source; file:line citations
refer to that pin. "Introduced" = first commit reachable in this clone (upb
history before the protobuf repo merge is squashed; see NONDETERMINISM.md §1.3).
**UNVERIFIED** marks anything inferred.

---

## 1. Varint arithmetic trick: `val += (byte - 1) << (i*7)`, first byte raw

- **What:** `_upb_WireReader_ReadLongVarint` (`upb/wire/reader.c:19-31`) seeds
  `val` with the first byte raw and then *adds* `(byte - 1) << (i * 7)` per
  continuation byte. For a terminated varint this is exact:
  `byte_0 + Σ(byte_i - 1)·2^7i ≡ Σ(byte_i & 0x7F)·2^7i (mod 2^64)` — the `-1`
  terms cancel the 0x80 continuation bits byte-by-byte (verified by expanding
  the difference: `0x80 + Σ_{i=1..k-1} 0x7F·2^7i − 2^7k = 0` for a varint
  terminating at byte k).
  The fast single-byte path is `*val = byte; return ptr+1` (`upb/wire/internal/reader.h:41-53`).
- **Why:** branch-free accumulation; avoids masking every byte.
- **When introduced:** earliest reachable commit `501ececd3` (2023-09-26,
  "Reorganize upb file structure"); later touched by `5f1c06a28` (2025-08-27,
  bounds-asserts) and `be01da55a` (2025-12-11, longjmp layer).
- **What relies on it:** every decode path (`upb_WireReader_ReadVarint`,
  tag/size readers in the same file). Overlong encodings are **accepted** and
  decode to their mathematical value — there is no canonical-form rejection.
- **What would break if cleaned up:** a naive Rust `(byte & 0x7f) << 7i | acc`
  loop is *arithmetically equivalent for ≤9 bytes* but diverges on the 10th
  byte (see Q2) and changes nothing else observable — the divergence is the
  point of Q2, not the add itself.
- **Court:** `courts/wire-primitives` (PARITY.toml `wire.decode.varint`,
  oracle-tested) already pins the add-trick semantics.

## 2. 10-byte varint limit and 10th-byte semantics

- **What:** varints are read with a hard 10-byte bound (`ConsumeBytes(stream, 10)`,
  reader.h:43; loop `i < 10`, reader.c:22). A 10th byte still carrying the
  continuation bit ⇒ error. For the 10th byte, `(byte-1) << 63` wraps mod 2^64:
  **only bit 63 is reachable, and only via the LSB of `byte-1`** — the upper 6
  payload bits of the 10th byte are lost by wraparound.
- **Why:** 64-bit value, 9×7=63 bits + bit 63 from byte 10; the loop simply
  cannot represent more; the add-trick makes the loss silent instead of
  erroring (canonical 10-byte encodings use 0x01/0x02 as the 10th byte).
- **When introduced:** with the reader (see Q1).
- **What relies on it:** any 10-byte varint with non-canonical 10th byte (e.g.
  `0x82`) decodes with a *wrapped* value; a 10-byte varint whose 10th byte has
  the continuation bit set is rejected; 11-byte varints are rejected.
- **What would break if cleaned up:** rejecting overlong 10-byte encodings or
  computing the 10th byte "correctly" (bits 63..69) changes oracle statuses and
  values for hostile inputs; the conformance corpus has these.
- **Court:** `courts/wire-primitives` (varint bounds; keep 10-byte corpus
  cases, add hostile 10th-byte values 0x02..0xFF).

## 3. Tag read: 5-byte limit + `UINT32_MAX` check

- **What:** `upb_WireReader_ReadTag` consumes 5 bytes max; the long path checks
  `if (val > UINT32_MAX) break;` on the terminating byte and errors
  (`reader.c:33-46`, wrapper reader.h:55-67). Since a tag is `(field << 3) | wt`,
  this caps field numbers at `UINT32_MAX >> 3 == 2^29-1` — which coincides with
  `kUpb_MaxFieldNumber` in `upb/mini_descriptor/decode.c:67` and
  `upb/reflection/field_def.h:28`.
- **Why:** tags are `uint32_t`; one bounds check per field (slop-bytes design).
- **When introduced:** with the reader (Q1).
- **What relies on it:** decode rejects tags > UINT32_MAX; the field-number
  ceiling is enforced at *decode* time only via this arithmetic, not by an
  explicit 2^29-1 check in the reader (the mini-descriptor builder does check
  2^29-1 explicitly at decode.c:492-495, and extension numbers at decode.c:922-926).
- **What would break if cleaned up:** widening tags to u64 or adding an explicit
  2^29-1 check changes nothing for valid input but changes malformed-input
  statuses (fields 2^29..2^32/8 are *unknown fields* in upb, not errors —
  they route through `_upb_Decoder_FindField` miss ⇒ `kUpb_DecodeOp_UnknownField`).
- **Court:** `courts/wire-primitives` (`wire.decode.tag`, oracle-tested).

## 4. Size read: 5-byte limit + `INT32_MAX` check — sizes are signed 32-bit

- **What:** `_upb_WireReader_ReadLongSize` errors if the terminating value
  exceeds `INT32_MAX` (`reader.c:48-61`); the fast path stores into `int*`
  (`reader.h:69-81`). Sizes ≥ 2^31 are malformed. `upb_EpsCopyInputStream_CheckSize`
  asserts `size >= 0` (eps_copy_input_stream.h:211-215).
- **Why:** `int32_t` length fields; aligns with the 2 GB wire limit enforced on
  encode (`encode_longlength`, encoder.c:283-286).
- **When introduced:** with the reader (Q1).
- **What relies on it:** every delimited/string/message/packed field. 5-byte
  size boundary: 4 bytes give bits 0..27 (max 0x0FFFFFFF); the 5th byte's
  payload (bits 28..34) must keep the total ≤ INT32_MAX — i.e. 5th byte ≤ 0x07
  always accepted, 0x08 accepted only when the lower 4 bytes encode
  0x0FFFFFFF (exactly INT32_MAX), ≥ 0x09 always errors (reader.c:48-61).
  `upb_DecodeLengthPrefixed` adds its own `msg_len > INT32_MAX ⇒ Malformed`
  (decode.c:1340-1373).
- **What would break if cleaned up:** using u32 sizes would accept 2^31..2^32-1
  lengths the oracle rejects.
- **Court:** `courts/wire-primitives` (`wire.decode.size`, oracle-tested); add
  the 0x08/0x09 5th-byte boundary cases to the corpus.

## 5. EPS copy input stream: zero-padding means truncated inputs parse, then error

- **What:** `kUpb_EpsCopyInputStream_SlopBytes = 16` (eps_copy_input_stream.h:33);
  `patch` is 32 bytes (2× slop, h:53). `InitWithErrorHandler`: if
  `size <= 16`, the patch is `memset` to zero and the input copied in
  (h:69-75). The decoder therefore *reads past the logical end of a truncated
  input as zero bytes* (varint continuation stops, "length 0" strings, etc.),
  and only later detects truncation via `IsDone`. `IsDoneFallback` copies the
  tail into the patch when `overrun < limit`, else errors
  (`upb/wire/eps_copy_input_stream.c:25-47`).
- **Why:** one bounds check per field; the patch guarantees 16 readable bytes;
  zero-padding makes overreads safe (no OOB) while truncation is caught by the
  stream's done/limit machinery.
- **When introduced:** `be01da55a` (2025-12-11) reworked error handling;
  slop/patch design predates (see reader.h:23-27 doc comment).
- **What relies on it:** the entire decoder's "no per-field bounds checks"
  fast path; capture/alias (`GetInputPtr`, h:220-229) maps patch addresses back
  to the original buffer.
- **What would break if cleaned up:** a Rust reimplementation that bounds-checks
  *before* reading would produce identical *outcomes* (both error) but the
  *sequence* of bytes consumed differs — irrelevant unless a court compares
  error provenance; what matters is **status equality** (Malformed) and that no
  valid input depends on patch contents (it can't: valid inputs never read past
  `end+limit`).
- **Court:** none yet — court TBD (proposed: `courts/eps-input-stream`,
  truncated-input corpus asserting `kUpb_DecodeStatus_Malformed`).

## 6. `SkipValue` rejects field number 0

- **What:** `_upb_WireReader_SkipValueForceInline` errors when `(tag >> 3) == 0`
  (`upb/wire/reader.h:131-133`). The decoder independently errors on
  `field_number == 0` in `_upb_Decoder_DecodeUnknowns` (decode.c:1014-1016) and
  `_upb_Decoder_CanSkipUnknownField` (decode.c:989-991).
- **Why:** field number 0 is invalid in protobuf; the check is cheap and
  centralizes the guard for skip paths (including nested groups).
- **When introduced:** reader.h at this pin; era **UNVERIFIED**.
- **What relies on it:** all skip paths (unknown fields, group skipping,
  message-set non-item fields).
- **What would break if cleaned up:** tag 0 (bytes `00 00`) would be silently
  skipped instead of Malformed.
- **Court:** none yet — court TBD (extend `wire-primitives` with tag-0 cases).

## 7. Default depth limit 100; SkipGroup recursion counts down

- **What:** `kUpb_WireFormat_DefaultDepthLimit 100` (`upb/wire/internal/constants.h:11`);
  effective-depth helpers in decode.h:75-83 / encode.h:60-79. `_upb_WireReader_SkipGroup`
  does `if (--depth_limit < 0) error` (reader.c:63-68) — so *skipping* a group
  consumes depth too, and unknown-field group nesting beyond the limit errors
  even though no message is being built. The decoder's message recursion does
  the same (`_upb_Decoder_RecurseSubMessage`, decode.c:191-205). Unknown-field
  comparison caps at 100 (compare_unknown.c:404-423) and promotion at 100
  (promote.c:137).
- **Why:** stack-overflow protection; single knob shared across decode/encode.
- **When introduced:** constants.h at this pin; era **UNVERIFIED**.
- **What relies on it:** recursion in decode, encode, skip, compare, promote;
  note encode depth counts *message fields* while skip depth counts *groups*.
- **What would break if cleaned up:** a Rust port with a different limit (or
  depth accounting that ignores skipped groups) flips statuses on deep inputs.
- **Court:** none yet — court TBD (depth-corpus court).

## 8. `upb_CType` vs `upb_FieldType` and the packability mask

- **What:** two parallel enums — `kUpb_CType_*` (storage/accessor types, 11
  values, `upb/base/descriptor_constants.h:18-30`) and `kUpb_FieldType_*`
  (wire/descriptor types, 18 values, h:39-59). The conversion table is
  lossy-by-design: **Fixed64 → CType_UInt64, Fixed32 → CType_UInt32,
  SFixed32/SInt32 → CType_Int32, SFixed64/SInt64 → CType_Int64, Group →
  CType_Message** (h:68-92). Packability is a *FieldType* bitmask — String,
  Bytes, Message, Group are unpackable (h:94-103).
- **Why:** generated code and accessors want a small set of storage types;
  wire handling wants the 18 descriptor types; "integer encoding" (sint vs
  int) is a wire-only concern.
- **When introduced:** descriptor_constants.h at this pin; era **UNVERIFIED**.
- **What relies on it:** accessors (`upb_Message_Get*`/`Set*` dispatch on
  CType), map size tables (`_upb_Map_CTypeSizeTable`, map.c:30-42), encoder
  ctype switch (encoder.c:369-455), sorter comparators (map_sorter.c:85-105 —
  note Fixed64 sorts as *unsigned* while SFixed64 sorts as signed).
- **What would break if cleaned up:** unifying the enums loses the
  wire-vs-storage distinction (e.g. sint32 is CType_Int32 but needs zigzag on
  the wire; fixed64 is CType_UInt64 but is *not* varint-encoded).
- **Court:** none yet — court TBD (field-type matrix court).

## 9. `kUpb_FieldType_SizeOf = 19` sentinel

- **What:** `#define kUpb_FieldType_SizeOf 19` (descriptor_constants.h:61) —
  one past the highest FieldType (SInt64=18). It is used to size the sorter
  comparator table `compar[kUpb_FieldType_SizeOf]` (map_sorter.c:85) and the
  decode op tables (decode.c:764-789, 811-859), and collides conceptually with
  the fake type `kUpb_FakeFieldType_MessageSetItem = 19` (decode.c:61-65).
- **Why:** sentinel for array sizing; the fake MessageSetItem type reuses 19 as
  an out-of-band marker.
- **When introduced:** descriptor_constants.h at this pin; era **UNVERIFIED**.
- **What relies on it:** any table indexed by FieldType; a Rust port must keep
  the sentinel (or use enum-with-array discipline) or tables overflow.
- **What would break if cleaned up:** nothing user-visible; internal only.
- **Court:** none needed (structural), but the MessageSetItem=19 collision
  should be preserved in decode op tables.

## 10. MessageSet wire constants

- **What:** `kUpb_MsgSet_Item = 1, kUpb_MsgSet_TypeId = 2, kUpb_MsgSet_Message = 3`
  (`upb/wire/internal/constants.h:21-25`), documented as the classic
  `repeated group Item = 1 { required int32 type_id = 2; required bytes message = 3; }`
  (h:13-19). The decoder's item tags are built from these (decode.c:594-599) and
  the MessageSet decode state machine tolerates **out-of-order** type_id/message
  (preserving the payload then completing, decode.c:664-719), ignores duplicate
  payloads (`if (state_mask & kUpb_HavePayload) break; // Ignore dup.`,
  decode.c:701), and drops unexpected fields inside items (decode.c:712-714).
  MessageSet *as extendee* is treated as extendable for delimited fields
  ("compatibility with encoders that are unaware of message sets",
  decode.c:724-744). Extensions of MessageSet must be non-repeating messages
  (mini_descriptor/decode.c:943-949).
- **Why:** legacy Google-internal format still on the wire.
- **When introduced:** constants.h at this pin; earliest reachable
  `501ececd3` (2023-09-26).
- **What relies on it:** MessageSet decode/encode (`encode_msgset_item`,
  encoder.c:695-708), compare, and `upb_Message_Convert`; unknown-item
  preservation (decode.c:625-649).
- **What would break if cleaned up:** dropping the out-of-order tolerance or
  dup-ignoring changes MessageSet acceptance on hostile inputs.
- **Court:** none yet — court TBD (MessageSet court with shuffled items).

## 11. JSON decode/encode quirks (`upb/json/decode.c`, `encode.c`)

1. **Duplicate JSON keys: accepted, last wins.** No duplicate detection in
   `jsondec_object`/`jsondec_field` (decode.c:1025-1033, 957-1023) — each key
   re-sets the field. Map keys likewise overwrite (`upb_Map_Set` via
   `jsondec_map`, decode.c:913-933).
2. **Number grammar:** no leading zeros ("number cannot have leading zero",
   decode.c:301-304); exponent optional; parsed with `strtod` (a superset —
   decode.c:326-343). `errno == ERANGE` check is **commented out** (decode.c:345-352);
   only `val > DBL_MAX || val < -DBL_MAX` errors (decode.c:354-356).
3. **64-bit ints from JSON numbers go through double:** `jsondec_int` bounds
   at `9223372036854774784.0` (2^63-1024) / `-9223372036854775808.0`, casts
   through double, and errors "JSON number was not integral" if the cast
   doesn't round-trip (decode.c:697-711). UInt similarly at
   `18446744073709549568.0` (2^64-2048) (decode.c:735-749). **As quoted
   strings, 64-bit ints parse exactly** (`jsondec_strtoint64/64`, decode.c:651-682,
   via `upb_BufToUint64`, atoi.c:13-28 — decimal only, no hex/underscore/sign
   beyond a leading `-` for int64).
4. **-0:** `strtod("-0")` yields -0.0; for float/double it round-trips (printed
   back as `-0` by `%g`); for int fields it becomes 0 (cast, decode.c:706).
5. **NaN/Infinity:** accepted as quoted strings "NaN"/"Infinity"/"-Infinity"
   (decode.c:785-790); encoded as quoted strings (encode.c:315-326). A quoted
   number with trailing garbage is a *non-fatal* error:
   "Non-number characters in quoted number … This will be an error in a future
   version." (decode.c:792-801) — same pattern for empty-string numbers
   (decode.c:684-692).
6. **Empty string for double** decodes to 0.0 with the same soft error
   (decode.c:782-784).
7. **`null` = default:** JSON null on any field means "don't set"
   (decode.c:991-995); `NullValue` enum accepts bare `null` → 0 (decode.c:849-856)
   and encodes as `null` (encode.c:212-213).
8. **Float overflow:** a double that overflows float (to ±inf) errors "Float out
   of range" unless already ±Infinity (decode.c:808-813).
9. **Boolean map keys** must be the quoted strings "true"/"false"
   (decode.c:864-877); other scalar map keys print as quoted decimal
   (encode.c:644-672).
10. **Oneofs:** a second member of an already-set oneof errors "More than one
    field for this oneof." (decode.c:997-1000).
11. **Enums:** decoded by JSON name first (`upb_EnumDef_FindByJsonNameWithSize`,
    decode.c:829-862), numbers otherwise; unknown names error unless
    `upb_JsonDecode_IgnoreUnknown`; unknown numeric values on encode print as
    integers (encode.c:209-227).
12. **Extensions in JSON** use `"[fullname]"` keys and are rejected if they
    extend a different message (decode.c:967-977; encode.c:718-722).
13. **Double formatting** uses `%.*g` with `DBL_DIG`/`FLT_DIG` + fallback
    `+2`/`+3` digits and a locale comma→dot fix ("Arguably a hack",
    `upb/lex/round_trip.c:20-57`); `nan` prints as "nan" only in the raw
    round-trip helper — JSON layer intercepts via `HandleSpecialDoubles`
    (encode.c:315-326).
- **Court:** none yet — court TBD (JSON court; assert these 13 cases).

## 12. `upb/message/accessors.c` / `accessors_split64.h`

- `accessors.c` is just `upb_Message_SetMapEntry` (map-entry message → map
  set, accessors.c:20-38).
- `accessors_split64.h` exists for JS interop: "JavaScript doesn't directly
  support 64-bit ints so we must split them." — `upb_Message_GetInt64Hi/Lo`,
  `SetInt64Split`, and UInt64 twins, all thin wrappers over the 64-bit
  accessors (accessors_split64.h:25-61).
- **UNVERIFIED:** the charter's claim that accessor paths special-case unknown
  fields — no such path found at this pin; unknown handling lives in
  decode/promote (`upb_Message_GetOrPromoteExtension`, promote.c:118-200, which
  scans unknowns to synthesize extension values; note the hardcoded
  `depth_limit = 100` at promote.c:137).
- **Court:** none yet — court TBD.

## 13. `UPB_UNLIKELY`/`UPB_ASSUME` behavior changes and notable comments

- `UPB_ASSUME(!key.ignore)` — map keys can never be enums (decode.c:925);
  `UPB_ASSUME(field->descriptortype == kUpb_FieldType_Bytes)` before the
  utf8-op switch (decode.c:805). These are compiler hints, not behavior.
- **Behavioral branches gated on `UPB_UNLIKELY` are still ordinary branches** —
  no behavior change; the notable *behavioral* comments are:
  - "hackery" — encoder keeps `*buf = NULL` on error for callers that ignore
    status (encoder.c:824-827, b/235839510).
  - "QUITE an ugly hack" — `UPB_ARENA_SIZE_HACK` sizing the inlined arena in
    the decoder (`upb/mem/internal/arena.h:21-34`).
  - "Arguably a hack" — locale fix (round_trip.c:23).
  - "we hack it with exchanges" — `upb/port/atomic.h:68` (atomic ops fallback).
  - "compat" — MessageSet-as-extendable (decode.c:728), `upb/mini_table/compat.h`,
    `upb/message/compat.h` ("still used by some existing users so for now we
    make them", compat.h:17-20).
  - "Disabled for now" — fasttable path (`upb/wire/decode_fast/cardinality.h:530`).
  - "for the moment, we consider this an error" — strings spanning buffer
    boundaries (eps_copy_input_stream.h:260-264, 277-281).
  - "TODO: add overwrite operation to minimize number of lookups" — map
    replace does remove+insert (internal/map.h:187).
  - "Omit carry bit, for mixing we do not care" — `upb_umul128` fallback
    (common.c:420).
- **Court:** n/a (documents intent; no court needed).

## 14. `upb/lex/atoi.c` and `round_trip.c`

- `upb_BufToUint64`: decimal digits only; overflow checked as
  `u64 > UINT64_MAX/10 || u64*10 > UINT64_MAX - ch` (atoi.c:13-28). **No hex,
  no underscores, no leading `+`.** Stops (returns partial pointer) at the
  first non-digit — callers decide whether that's an error
  (JSON `jsondec_buftouint64` errors: "Non-number characters in quoted
  integer", decode.c:666-682).
- `upb_BufToInt64`: optional leading `-`; range check `u64 > INT64_MAX + neg`
  (atoi.c:30-48). `-9223372036854775808` parses (neg=true, u64=2^63).
- `_upb_EncodeRoundTripDouble/Float`: NaN → "nan"; else `%.*g` with
  DBL_DIG/FLT_DIG, re-checked with strtod, bumped to +2/+3 digits if not exact
  (round_trip.c:31-57). **Locale-dependent** (hence `upb_FixLocale`,
  round_trip.c:20-29): a court must set `LC_ALL=C` on the oracle, or the same
  binary gives different JSON in different locales.
- **Court:** none yet — court TBD (JSON number court must fix the locale; the
  oracle build/run docs should pin `LC_ALL=C`).

## 15. Extra finds (not in the charter list)

- **Map entry with unknown fields is preserved as unknown bytes**: decode
  re-encodes the whole entry (tag+length+payload) via
  `_upb_Encoder_AddMapEntryUnknown` (encoder.c:48-70, called decode.c:523-527)
  rather than inserting the entry — so a map entry carrying unknown fields
  round-trips byte-identically as an unknown field.
- **Map entry with missing message value** is created empty and *required*
  fields of the value message are checked against it (decode.c:508-521).
- **Packed enum with unknown values**: skipped and re-encoded as unknown
  varint field with the field's tag (decoder.h:275-296); the tag is rebuilt
  from the field number because "the tag could be arbitrarily far in the past".
  Extension fields route the unknown to the *original* message
  (`d->original_msg`, decoder.h:284-286).
- **proto3 enums are lowered to int32 in the minitable** (`kUpb_EncodedType_OpenEnum`
  → `kUpb_FieldType_Int32`, mini_descriptor/decode.c:128-135), so open-enum
  fields never hit the closed-enum value check (decode.c:891-900); closed enums
  keep `kUpb_FieldType_Enum`.
- **proto2 string = bytes + IsAlternate**; `FlipValidateUtf8` modifier promotes
  it to a real String (mini_descriptor/decode.c:242-254; flag at
  mini_table/internal/field.h:58). UTF-8 validation then keys off
  `descriptortype == String` (decoder.h:231-242) — see BEHAVIOR_ATLAS §utf8.
- **`upb_Message_Clear` zeroes the message and just resets `in->size = 0`**
  (internal/accessors.h:876-885) — aux memory (extensions, unknowns) is leaked
  to the arena by design; the array slots remain but are dead.
- **`upb_Map_Insert` returns Replaced on duplicate key and relocates the entry**
  (internal/map.h:172-203) — affects iteration order (§NONDETERMINISM 1.1).
- **`_upb_Decoder_Munge` zigzag for SInt32/64** and bool `!= 0` normalization
  happen before storage (decode.c:139-161); note int32 keeps the raw u64
  truncated (MungeInt32, decode.c:132-137) — a varint > 32 bits on an int32
  field truncates silently (low 32 bits).
- **Groups in oneofs/unlinked messages** degrade to unknown-field ops
  (`_upb_Decoder_CheckUnlinked`, decode.c:791-800; `_VerifyOneofUnlinked`,
  decoder.h:204-218).

## 16. Closed-enum specifics (sealed in decode-submsg-v1, 259/259)

- **Invalid scalar/unpacked closed-enum values keep the raw wire span**: the
  value is captured byte-for-byte as an unknown field, so overlong encodings
  round-trip unchanged (decode.c:889-901 + `_upb_DecodeUnknowns`,
  decode.c:1010-1081). Packed invalid values instead get *re-encoded* as
  `[minimal varint tag][minimal varint]` via
  `_upb_Encoder_AddEnumValueToUnknown` (decode.c:315-347) — an overlong
  `85 00` in a packed payload round-trips as `08 05`, not `08 85 00`. This
  asymmetry (raw for unpacked, minimal for packed) is oracle-verified.
- **CheckValue truncates the wire varint to u32** (`upb_MiniTableEnum_CheckValue`
  takes `uint32_t`, mini_table/internal/enum.h:26-27): a 10-byte
  sign-extended `-1` on the wire matches a table holding `0xFFFFFFFF`, and
  the stored value is the low 32 bits (MungeInt32 semantics).
- **Enum descriptor arithmetic wraps** like C `uint32_t`: `base += skip` and
  `base++` in build_enum.c:105,114 and `last_written_value += delta` in
  encode.c:289,310 are wrapping, and an out-of-alphabet mask char
  (`_upb_FromBase92` returning -1) becomes an all-ones mask (all 5 values
  added) rather than an error.
- **Map-value enums must include 0**: `upb_MiniTable_SetSubEnum` returns
  false for a map entry whose enum lacks 0 (link.c:110-119, "Enum value in
  map must define 0 as the first value" — protoc guarantees it). The oracle
  reports `link_failed`; the DUT refuses the schema (classified together in
  the court as a build/link failure, exact oracle code preserved in
  residuals).
- **Unlinked closed enums are NOT courtable**: decoding through a NULL sub
  table is UB upstream (dereference in `upb_MiniTable_GetSubEnumTable`); the
  DUT refuses such schemas defensively (§49), covered by a DUT unit test
  (`closed_enum_unlinked_rejected`) — deliberately not in the differential
  corpus.
- **Packed varints overrunning the payload limit are malformed**: a packed
  element whose varint terminates past the declared size pushes the stream
  position past the limit, and the next `IsDone` raises an error
  (decode.c:298). Corpus case `cep-trunc-varint` (payload `0A 01 85`)
  caught the DUT's missing classification.
- **Build/link failure classification**: the oracle's
  `minitable_build_failed` / `enum_build_failed` / `link_failed` / `oom`
  codes and the DUT's `Unsupported` refusal are the same observable class
  (schema rejected before decoding) and are compared as such in the court;
  the exact oracle code is retained in residual records for audit.

## 17. Encoder specifics (sealed in encode-v1, 3129/3129)

- **`encode_shouldencode` is not `field_present`**: presence-less
  (proto3-singular/map/array) fields encode iff the stored value is
  non-zero / the collection non-empty, hasbit fields iff the bit is set,
  oneof members iff the case matches (encoder.c:642-678). In particular a
  MAP field built from a singular message descriptor keeps a hasbit the
  decoder never sets (`_upb_Decoder_DecodeToMap`, decode.c:474-535, sets
  no presence), so such maps decode but are SKIPPED on encode — while
  protoc-generated map fields (repeated message + link, presence-less)
  encode normally. Both shapes are in the corpus (`mp-*` skipped,
  `enpm-*` encoded).
- **Deterministic map output is the REVERSED sorted order**: the mapsorter
  sorts entries (int keys ascending by uintptr; string keys bytewise
  DESCENDING — the negated memcmp in `_upb_mapsorter_cmpstr`,
  map_sorter.c:76-83 — with ascending-size tie-break) and the encoder
  iterates the sorted map forward while building the buffer backwards, so
  the emitted bytes come out reversed (encoder.c:594-640). The inttable
  comparator ignores signedness (ascending uintptr always); the signed
  comparators in `compar[]` are dead code for int maps.
- **Encode/decode depth off-by-one**: the decoder errors at
  `--depth < 0` (decode.c:196) so D nested levels decode at max depth D;
  the encoder errors at `--depth == 0` (encoder.c:426, 441, 539, 556) so
  D nested levels FAIL to encode at max depth D. A message that decodes at
  exactly the boundary does not re-encode.
- **The packed flag selects the encoded form**: a packed wire input for a
  field whose descriptor lacks the packed flag re-encodes UNPACKED, and
  vice versa (encode_array, encoder.c:460) — the flag is a serialization
  preference, not a decode constraint.
- **Unknowns emit after fields** in the forward output (written first into
  the backward buffer → high addresses; encoder.c:776-798); SkipUnknown
  drops them (encode.h:38-39).
- **Map entries always emit key and value** (`encode_mapentry`,
  encoder.c:579-592) regardless of zero values, wrapped as
  `[map-tag][len][key][val]` — unlike the AddMapEntryUnknown re-encode,
  which applies the entry's own hasbit presence.
