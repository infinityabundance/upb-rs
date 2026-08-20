# PERFORMANCE_MODEL.md — upb performance architecture (pinned pin)

Oracle pin: `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`. File:line citations
are against the pinned working tree. The performance *plan* (§5) contains no
numbers: courts/benches do not exist yet.

---

## 1. Decode architecture

### 1.1 The two paths
upb has two decoders, both driven by a `upb_MiniTable`:

1. **Generic decoder** (`upb/wire/decode.c` + `upb/wire/internal/decoder.c/h`):
   a per-field op-table interpreter. Field/wire-type pairs are compiled into
   `kUpb_DecodeOp_*` ops (`decode.c:61-90`); the per-field loop is
   `_upb_Decoder_DecodeField` → `_upb_Decoder_TryDecodeMessageFast` (fast path
   attempt) → `_upb_Decoder_DecodeFieldNoFast` (generic) (`decode.c:1126-1203`).
   Generic dispatch via `_upb_Decoder_DecodeFieldTag`/`_upb_Decoder_DecodeFieldData`
   (`decode.c:1083-1119`) with `_upb_Decoder_FindField` (`decode.c:746-762`)
   doing the tag→field lookup. Unknown fields use
   `_upb_Decoder_DecodeUnknowns` (`decode.c:1010-1081`) and the
   can-skip-fast predicate `_upb_Decoder_CanSkipUnknownField` (`decode.c:968-1008`).
   Message-level driver: `_upb_Decoder_DecodeMessage` (`decode.c:1255-1276`),
   with a dedicated empty-message fast exit `_upb_Decoder_DecodeEmptyMessage`
   (`decode.c:1205-1239`) that captures whole unknown regions as a single
   string view.
2. **Fasttable decoder** (`upb/wire/decode_fast/`): per-message, per-slot
   function pointers. Selected per field at table-build time; dispatched
   through a 32-slot mask-indexed table (below).

Both share the decoder state (`upb/wire/internal/decoder.h:50-70`), the EPS
input stream (§2.3 of SECURITY_HISTORY), the error handler, and the inlined
temporary arena (`decoder.h:59-62`; `UPB_ARENA_SIZE_HACK`, `upb/mem/internal/arena.h:21-34`).

### 1.2 How the fast table is selected and built
- Build-time (minitable construction): `upb_DecodeFast_BuildTable`,
  `decode_fast/select.c:227-295`. Eligibility per field
  (`upb_DecodeFast_TryFillEntry`, `select.c:208-225`):
  - encoded tag fits 1–2 bytes ⇒ field number < 2048 (`select.c:58-74`);
  - not a map field (`select.c:80-81`), not a group (`select.c:106-107`);
  - type in the supported set: bool, open/closed enum, int32/uint32/int64/uint64,
    fixed32/64, sfixed32/64, float/double, sint32/64, string, bytes, message
    (`select.c:115-133`; `UPB_DECODEFAST_COMBINATION_IS_ENABLED`,
    `combinations.h:206-222`);
  - presence constraints: oneof presence = field number; hasbit index must be
    < 32 (`select.c:153-167`); field offset, oneof offset, presence, suboffset,
    tag all ≤ 16 bits (`decode_fast/data.h:32-44`);
  - no extension fields (`select.c:212`); not a map-entry message
    (`select.c:229`).
- Slot layout: tag → slot = `(tag & 0xf8) >> 3` (`data.h:66-69`); collisions
  degrade per-slot (`select.c:257-264`); empty slots get a fast unknown handler
  when all 1–2-byte-tag fields are compatible and the message is not extendable
  (`select.c:268-292`); the resulting size is rounded to a power of two and
  stored as `table_mask` (`select.c:266`, `select.c:297-299`).
- Runtime dispatch: `upb_DecodeFast_Dispatch` reads 2 tag bytes, packs the
  mask, tail-calls `_upb_FastDecoder_TagDispatch` which indexes
  `table->fasttable[ofs >> 3]` (`decode_fast/dispatch.h:39-86`); fallback on
  end-of-message/buffer: `upb_DecodeFast_MessageIsDoneFallback`
  (`decode_fast/dispatch.c:20-51`).
- The 120 specialized functions (4 cardinalities × 11 types × 2 tag sizes,
  14 impossible combos): `combinations.h:19-25`; generated macro set
  `UPB_DECODEFAST_FUNCTIONS` (`combinations.h:161-162`); pointer array
  `decode_fast/function_array.c:20-41` with `_upb_FastDecoder_DecodeGeneric`
  fallback for disabled combos.
- Gating: `UPB_FASTTABLE` needs x86-64/ARM64-le + `preserve_none` + `musttail`
  (`upb/port/def.inc:500-507`); forced by `UPB_ENABLE_FASTTABLE`, opportunistic
  with `UPB_TRY_ENABLE_FASTTABLE`, off otherwise (`def.inc:509-528`); Bazel
  `//upb:fasttable_enabled` flag, default False, with a 64-bit-only
  `config_setting` (`upb/BUILD:48-68`). Runtime opt-out:
  `kUpb_DecodeOption_DisableFastTable` (`upb/wire/decode.h:64-67`) and
  `table_mask == -1` (`decode.c:1153-1158`). `AlwaysValidateUtf8` also forces
  the generic path (`upb/wire/internal/decoder.h:96-99`).
- What limits the fast path: 64-bit platforms; no groups/maps/extensions/
  MessageSet; 1-2-byte tags only; 16-bit offsets; hasbit < 32; table build is
  *per-minitable* so the same schema may be fast or slow depending on layout
  and platform.

### 1.3 Perf-relevant decode details
- One bounds check per field via the 16-byte slop invariant
  (`eps_copy_input_stream.h:25-33`); debug-only consumption accounting
  (`eps_copy_input_stream.h:121-152`).
- Varint hot path: single-byte fast exit in `upb_WireReader_ReadVarint`
  (`upb/wire/internal/reader.h:41-53`), long path via
  `_upb_WireReader_ReadLongVarint` (`upb/wire/reader.c:19-31`).
- Packed fixed arrays decode in place with `_upb_Decoder_DecodeFixedPacked`
  (`decode.c:243-287`); packed varints pre-count then fill
  (`decode_fast/field_varint.c:109-176`).
- String handling: alias-vs-copy chosen by `kUpb_DecodeOption_AliasString`
  (`decoder.h:244-263`); fasttable strings via `ReadStringAlwaysAlias` +
  arena copy (`decode_fast/field_string.c`).
- Trace events (`_upb_Decoder_Trace`, `decoder.h:169-197`) exist for debug
  profiling: 'D','F','<','M','U' etc.

---

## 2. Encode architecture

### 2.1 One-pass backwards encoder (not two-pass at this pin)
- **Correction to the two-pass model**: the pinned tree encodes **backwards in
  one pass** — "We encode backwards, to avoid pre-computing lengths (one-pass
  encode)" (`upb/wire/encode.c:8`). The switch landed in `a7864c77b`
  "Backwards allocation for encode." (2026-05-07). The historical two-pass
  (byte-size pass then forward write) is what older upb did
  [INFERRED from pre-`a7864c77b` encode.c history; not re-verified
  blob-by-blob]; do not assume it here.
- `upb_Encode` = `_upb_Encode(..., prepend_len=false)` (`encode.c:25-29`);
  `upb_EncodeLengthPrefixed` prepends the length varint (`encode.c:31-36`,
  `encoder.c:831-833`).
- `upb_ByteSize` is now a *convenience wrapper that actually encodes to a
  scratch arena*: `upb_ByteSize` (`upb/wire/byte_size.c:24-33`). It is not a
  separate pass.

### 2.2 The buffered writer (back-alloc)
- `upb_BackAlloc` (`upb/wire/internal/back_alloc.h:23-84`): writes grow
  downward from a buffer that lives at the *back* of an arena. First grow
  tries to steal the arena's current block (`back_alloc.c:96-114`); later
  grows allocate exponentially-sized blocks and copy the tail
  (`upb_BackAlloc_Realloc`, `back_alloc.c:56-94`; block-size calculus
  `back_alloc.c:24-54` — power-of-two with −128 for allocator metadata).
- Fast path: `upb_BackAlloc_HasBytes` (`back_alloc.h:63-67`) and
  `encode_reserve` (`encoder.c:94-102`) — most writes never call the
  allocator. The "buffer is large enough" fast path is therefore in
  `back_alloc.h`/`encoder.c`, not `encode.h`; `encode.h` at this pin carries
  only options and status enums (`encode.h:29-79`).
- Varint encode hot path: single byte if `val < 128` and space exists
  (`encode_varint`, `encoder.c:271-280`); long path with an arch-specific
  BTI/arm64 variant (`encode_longvarint`, `encoder.c:155-258`); length varints
  capped at INT32_MAX (`encode_longlength`, `encoder.c:282-288`).
- Field writers: scalars reserve the worst-case `5+10` bytes then write
  unchecked (`encode_scalar`, `encoder.c:369-455`); arrays write per element
  with reserve-on-demand (`encode_array`, `encoder.c:457-577`); packed arrays
  back-patch the length after writing (`encoder.c:571-575`); maps sort when
  `kUpb_EncodeOption_Deterministic` via `_upb_mapsorter` (`encoder.c:594-640`,
  `encoder.c:857`).
- Ordering: fields iterate backwards over `mt->fields` (`encode_message`,
  `encoder.c:802-812`); unknown fields iterate `aux_data` in reverse to emit
  original forward order (`encoder.c:776-798`); extensions via `encode_exts`
  (`encoder.c:800`).
- Depth: `--e->depth == 0` ⇒ `kUpb_EncodeStatus_MaxDepthExceeded` for
  group/message/array-of-message recursion (`encoder.c:426,441,539,556`);
  budget seeded from `upb_EncodeOptions_GetEffectiveMaxDepth`
  (`encode.h:68-71`, `encoder.c:855`).
- Error channel: setjmp/longjmp in `upb_Encoder_Encode`
  (`encoder.c:818-844`); `*buf = NULL` on failure (b/235839510 compatibility
  note, `encoder.c:824-841`).

---

## 3. Arena allocation cost model

Sources: `upb/mem/internal/arena.h`, `upb/mem/arena.c`, `upb/port/def.inc`.

- **Bump path**: `_upb_Arena_Malloc_Unchecked` (`arena.h:74-92`) —
  `span = UPB_ALIGN_MALLOC(size) + kUpb_Asan_GuardSize` (`arena.h:59-61`);
  if `end - ptr >= span`, return `ptr` and advance `ptr += span`. No free list,
  no per-object metadata, no zeroing. Alignment: `UPB_MALLOC_ALIGN`
  (`arena.h:70-72`); the initial user pointer is aligned up (`arena.c:559-565`).
  ASan/HWASan: allocation is unpoisoned (`arena.h:91`), freed regions poisoned
  (`arena.c:425`, `arena.h:166-167`); `kUpb_Asan_GuardSize` = 32 with ASan,
  0 without (`upb/port/sanitizers.h:51-53`).
- **Block sizing**: `UPB_DEFAULT_MAX_BLOCK_SIZE` = 32768 (non-Android) / 8192
  (Android) (`upb/port/def.inc:409-413`). First block hint 128
  (`arena.c:585-586`); `_upb_Arena_InitSlow` minimum block 256 + state reserve
  (`arena.c:518-520`). Growth doubles `last_block_size` up to the max
  (`_upb_Arena_NextBlockSize`, `arena.c:437-462`); "one-off" oversized
  allocations use a `size_hint` heuristic so outlier sizes don't poison
  doubling (`arena.c:464-476`, `arena.c:446-458`). Each block carries a
  `upb_MemBlock` header (`arena.c:37-43`) and is linked for
  free-at-arena-free (`arena.c:598-633`); `space_allocated` is tracked
  relaxed-atomically (`arena.c:403-414`).
- **Growth strategy interplay**: `_upb_Arena_WouldReduceFreeSpace`
  (`arena.c:428-435`) demotes an exponential block to one-off when the 
  current block's remaining free space would exceed the future block's free
  space — this keeps the *working set* tight but means the last block is
  frequently under-utilized.
- **memset cost**: the arena bump path does **no memset** — new memory is
  uninitialized (callers like `_upb_Message_ReserveSlot`/
  `_upb_Array_ResizeUninitialized` zero explicitly where needed,
  `upb/message/array.c:150-160`). The only decoder-path zeroing is the EPS
  patch buffer `memset(&e->patch, 0, 32)` for small inputs
  (`eps_copy_input_stream.h:69-71`). [The prompt's "memset cost" is therefore
  about these explicit zero fills, not the arena itself.]
- **Decoder integration**: the decoder inlines a `upb_Arena` into itself
  (`decoder.h:59-62`) and swaps it in/out with the caller's arena
  (`_upb_Arena_SwapIn/SwapOut`, `arena.c:1016-1028`; `decoder.h:114-127`) —
  zero-init of a full arena is avoided per decode.
- **Cost model summary for the Rust port**: per-malloc cost = one compare +
  pointer bump (~2 ops) in the common case; block allocation amortized;
  alignment rounding wastes ≤ `UPB_MALLOC_ALIGN-1` bytes/alloc (+32 under
  ASan); tail waste from one-off/`WouldReduceFreeSpace` decisions; free cost
  is deferred entirely to arena destroy.

---

## 4. Benchmark infrastructure upstream

- `upb/wire/decode_benchmark.cc` — `BM_Decode` over single-field minitables
  per field type (one per wire type), payload sizes {8, 64, 512} bytes,
  `initial_block` arena vs. fresh arena, reports bytes-processed
  (L34-79). Uses `upb/wire/test_util/{field_types,make_mini_table,wire_message}`.
- `upb/mini_table/message_benchmark.cc` — `BM_FindFieldByNumber` over
  field counts {0,1,2} (L12-47).
- `benchmarks/` — dataset + datarace benchmarks; upb participates via
  `gen_upb_binary_c.py` (upb C codegen) and the datarace bench harness
  (`benchmarks/BUILD`, `benchmarks/benchmark.cc`); `gen_synthetic_protos.py`
  generates synthetic schemas.
- Conformance performance: `upb/conformance/conformance_upb_failures_performance.txt`
  exists but is **empty (0 bytes)** and the perf test is disabled
  ("segvs with recursion limit test … --config=asan", `upb/conformance/BUILD:158-183`).
- Fuzz (correctness, not perf): `upb/json/fuzz_test.cc`,
  `upb/message/{convert,compare}_fuzz_test.cc`, `upb/util/def_to_proto_fuzz_test.cc`,
  `upb/test/fuzz_util.{h,cc}`.

---

## 5. upb-rs performance plan

Correctness precedes optimization — charter §29, one line: *no performance
work is evidence of parity; courts are the evidence, and courts come first.*
[Charter file is not present in the repo; §29 referenced via project README
ground rules. INFERRED location.]

To measure (once courts exist):
1. **Decode throughput** (bytes/ns) on both generic and fasttable-equivalent
   paths — in Rust there is one kernel; the *selection criteria* from §1.2
   still need modeling so behavior matches for the same schema.
2. **Encode throughput** (backwards writer equivalent; reallocation-free
   fast path).
3. **Allocations per op** (arena bump hits vs. block allocations; count via
   fault-injection harness mirroring `c0a57498c`).
4. **Peak RSS** (arena block growth strategy §3 — tail waste is observable).
5. **Binary size** (upb's core selling point: "order of magnitude smaller in
   code size", `upb/README.md:19-20`).

Schema classes (all must appear in benches + courts):
`tiny` (1-2 fields), `small` (≤16 fields, 1-byte tags), `medium` (16-2047
fields, 2-byte tags), `large` (≥2048 fields), `wide` (many scalar fields),
`deep` (nested chains near depth 100), `map-heavy`, `repeated-heavy`
(packed + unpacked), `string-heavy` (alias vs copy), `bytes-heavy`,
`unknown-heavy` (aliased unknowns, coalescing).

Rules: no numbers in this document — the courts do not exist yet; every
benchmark that claims a *parity* property must pair with a differential court
receipt; benches/ is comparative (upb-rs vs oracle-linked C), never the
parity evidence itself.

---

## 6. Representation divergence notes (charter §8: semantic vs representation parity)

A pure-Rust kernel may legitimately differ in representation while matching
observable behavior:
- **No byte-layout contract** for in-memory messages: hasbit placement
  (`upb_Message` internal layout, `upb/message/internal/message.h`), field
  offset tables, and the 64-byte message header are C-ABI details — the Rust
  kernel only needs *observational* equivalence (field get/set, serialize).
- **Maps/arrays**: C uses open-addressing `upb_strtable`/`upb_inttable`
  (hash/), Rust may use `HashMap`/`Vec`; deterministic encode tie-breaking
  (mapsorter) must still match byte-for-byte.
- **Arena**: Rust doesn't need the inline-arena size hack
  (`UPB_ARENA_SIZE_HACK`) or the tag-pointer tricks
  (`upb_TaggedAuxPtr`, `upb/message/internal/message.h`); it does need the
  *allocation-failure contract* (§4 of SECURITY_HISTORY) and observable
  `SpaceAllocated`-style accounting if exposed.
- **Alias strings**: `kUpb_DecodeOption_AliasString` semantics are observable
  (lifetimes of returned views) — must be honored, though safe Rust will
  express it as borrows rather than raw aliasing.
- **Error model**: setjmp/longjmp → `Result`; status values and precedence are
  the parity surface (see OPEN_QUESTIONS §3.6).
- **MiniTable/MiniDescriptor**: internal C struct layouts are representation;
  the *accepted/rejected* contract of the builder is semantic and must match
  (SECURITY_HISTORY §1.6, §4).
- The C ABI (later `abi/`) is a separate surface with its own layout
  constraints — do not conflate it with kernel representation.
