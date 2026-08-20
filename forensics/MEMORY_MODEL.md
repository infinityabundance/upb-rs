# MEMORY_MODEL.md — upb memory model at pin 2de70d710

Scope: arena, message storage, mini tables, arrays/maps, unknown fields, strings,
ownership. All citations are to `third_party/protobuf/` at commit
`2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (v36-dev-400, 2026-08-19).

Legend: **[S]** semantic (must match in Rust), **[R]** representation (may
differ in Rust), **[A]** ABI/layout (only needed for the C-compat phase),
**[VERIFIED-ABSENT]** searched and confirmed not present at this pin.

---

## 1. Arena

### 1.1 Struct layout — split "fast head" vs "body"

- The public/opaque struct is only the allocation hot state:
  `struct upb_Arena { char* ptr; const char* end; }` plus a sanitizer member
  (`upb/mem/internal/arena.h:38-42`). The `ptr`/`end` window is the current
  block's bump region.
- The real state lives immediately after the head in `upb_ArenaState { head;
  body }` where `body` is `upb_ArenaInternal` (`upb/mem/arena.c:120-124`).
  `upb_Arena_Internal()` recovers it by casting the head pointer
  (`arena.c:141-143`).
- `upb_ArenaInternal` fields (`arena.c:56-118`): `block_alloc` (L59, `upb_alloc*`
  with low bit = "has initial block", `arena.c:208-220`); `blocks` (L62,
  free/cleanup list); `refs` (L67, debug-only); `last_block_size` (L71) /
  `size_hint` (L77, growth state); `space_allocated` (L83, atomic);
  `upb_alloc_cleanup` (L87); `parent_or_count` (L96) / `next` (L100) /
  `previous_or_tail` (L109) — fused-arena list/refcount, union-find forest with
  low-bit tags (`arena.c:145-206`).
- The decoder inlines a `upb_Arena` on its stack; the header-size hack
  `UPB_ARENA_SIZE_HACK` (9 pointers + 2×u32; 10 in debug) is static-asserted
  against `sizeof(upb_ArenaState)` (`upb/mem/internal/arena.h:21-34`,
  `arena.c:554-556`). Decoder swap: `upb/wire/internal/decoder.h:114-127`.

### 1.2 Block representation and constants

- `upb_MemBlock { next; size; /* data follows */ }` (`arena.c:37-43`); a
  `size == 0` block is an arena-ref record (`upb_ArenaRef`, `arena.c:45-54`)
  used only by `upb_Arena_RefArena`. Each block reserves
  `kUpb_MemblockReserve = UPB_ALIGN_MALLOC(sizeof(upb_MemBlock))` header bytes
  (`arena.c:131-132`, alloc at `arena.c:376-384`).
- `UPB_DEFAULT_MAX_BLOCK_SIZE`: **32768** normally, **8192** on Android
  (`upb/port/def.inc:409-413`); stored in atomic `g_max_block_size`
  (`arena.c:30`), changeable via `upb_Arena_SetMaxBlockSize` (`arena.c:32-35`).
- Alignment: `UPB_MALLOC_ALIGN` = **8**, or **16** under HWASAN
  (`def.inc:183-190`); `UPB_ALIGN_MALLOC(x) = UPB_ALIGN_UP(x, UPB_MALLOC_ALIGN)`
  (`def.inc:216-218`). ASAN adds a 32-byte guard per alloc span
  (`kUpb_Asan_GuardSize`, `upb/port/sanitizers.h:49-55`); an alloc's span is
  `ALIGN_MALLOC(size) + guard` (`upb/mem/internal/arena.h:59-61`).

### 1.3 Fast path, fallback path, growth

- Fast path `_upb_Arena_Malloc_Unchecked` (`internal/arena.h:74-92`): if
  `end - ptr >= span`, return `ptr`, bump `ptr += span`, assert both pointers
  stay `UPB_MALLOC_ALIGN`-aligned (L88-89). `upb_Arena_Malloc` is the
  allocation-count-guarded wrapper (`internal/arena.h:94-99`; count machinery
  `upb/mem/internal/alloc.h:25-45`, thread-local OOM injection
  `upb/mem/alloc.h:112-121`).
- Fallback `_upb_Arena_SlowMalloc` (`arena.c:480-509`): if the arena has no
  block allocator (`block_alloc == 0`), return NULL (L482); compute block size,
  alloc block, add to list, then either use it as the new bump region or
  return the whole block as a one-off. **Returns NULL on allocation failure** —
  at this pin the arena itself has no error-handler variant (see §8/ERROR_MODEL).
- Growth is exponential doubling capped at the max block size, with a
  one-off escape hatch:
  - `_upb_Arena_NextBlockSize` (`arena.c:437-462`): `block_size =
    MIN(last_block_size * 2, max)`; if `span > block_size` retry with
    `size_hint * 2`; if still too small, `one_off = true` and block = span
    exactly; also one-off when `_upb_Arena_WouldReduceFreeSpace` (L428-435).
  - `_upb_Arena_UpdateGrowthState` (`arena.c:464-476`): one-off bumps
    `size_hint` by `span/2`; otherwise `last_block_size = size_hint =
    block_size`.
- First block: with a user block, growth state starts at 128/128
  (`arena.c:585-586`); without one, `_upb_Arena_InitSlow` allocates
  `kUpb_ArenaStateReserve + MAX(256, ALIGN_MALLOC(first_size) + guard)` and
  seeds `last_block_size = size_hint = block_size` (`arena.c:511-552`, esp.
  L518-520, L528-529).

### 1.4 Init / Free / Reset

- `upb_Arena_Init(mem, n, alloc)` (`arena.c:554-596`): aligns `mem` up
  (L560-564); if `n < sizeof(upb_ArenaState)` or `mem == NULL`, falls into
  `_upb_Arena_InitSlow` (L566-572) — the **initial block is inline** in the
  user buffer when big enough (state is placed at `mem`, bump region starts at
  `ALIGN_MALLOC(a + 1)`, L574-595). Initial-block arenas are fixed-size unless
  `alloc` is non-NULL and grows from `alloc`; a NULL alloc with an initial
  block means the arena cannot grow (`upb/mem/arena.h:41-48`).
- `upb_Arena_Free` (`arena.c:635-669`): decrements the fused-group refcount
  (CAS on `parent_or_count`); the arena that reaches refcount 1 runs
  `_upb_Arena_DoFree` (`arena.c:598-633`): walk fused list, free every
  `upb_MemBlock` (sized-frees, L624), release arena refs for `size==0` blocks
  (L618-622), then invoke `upb_alloc_cleanup` (L628-630).
- `upb_Arena_Reset`: **[VERIFIED-ABSENT]** — no `upb_Arena_Reset` exists at
  this pin (grep over the whole `upb/` tree: 0 hits). Reset is done by
  Free + re-Init. **[R]**

### 1.5 Fuse, refs, lifetime extension

- `upb_Arena_Fuse(a, b)` (`arena.c:878-906`) merges lifetimes: no arena in the
  transitive fuse group is freed until all reach zero refcount
  (`upb/mem/arena.h:59-63`). It refuses arenas with initial blocks (cannot
  lifetime-extend them, `arena.c:888-893`); the actual merge is
  `_upb_Arena_DoFuse` (`arena.c:789-850`): find roots, always fuse into the
  lower-address root (L807-812), move `r2`'s refs onto `r1` (L827-833), reparent
  (L837-844), append to the fused list (L848). `upb_Arena_IsFused`
  (`arena.c:908-920`). Thread-safe; allocation is not (`arena.h:14-15`).
- `upb_Arena_IncRefFor` / `DecRefFor` (`arena.c:922-950`) and `RefArena`
  (`arena.c:952-994`) implement refs between *unfused* arenas: a
  `upb_ArenaRef` block (size==0) is malloc'd on the referencing arena; on free
  it releases the ref (`arena.c:618-622`). Cycles are UB (checked in debug)
  (`arena.h:76-108`).
- `upb_Arena_ShrinkLast` / `upb_Arena_TryExtend` / `upb_Arena_Realloc`
  (`internal/arena.h:101-170`): in-place shrink/extend when the alloc is the
  last one from the current block; otherwise realloc = malloc + memcpy + poison
  old region. These power array/unknown-field growth.

### 1.6 Pointer-stability guarantee

- Bump allocation means an arena alloc never moves after return; the only
  way storage changes is an explicit `upb_Arena_Realloc`/`TryExtend` call, and
  `TryExtend` is strictly in-place (`internal/arena.h:123-139`); realloc only
  copies when in-place is impossible (`internal/arena.h:141-170`).
  `_upb_Message_AddUnknownSlowPath` exploits this to coalesce adjacent unknown
  data (`message.c:59-69`). **[S]** — pointer identity observable; Rust must
  not relocate live allocations.

### 1.7 Court verification (Phase 1)

- The Rust model (`upb-rs-core::arena::ArenaPool` — handles over boxed,
  8-aligned blocks, zero unsafe) is **PARITY-SEALED** against the real
  `upb_Arena` by `courts/arena` (arena-v1, 61/61 equal, 0 residuals) over the
  pinned oracle binary. The oracle's controlled exact-size allocator (OOM
  injection via `fail_after_bytes`) makes block growth, one-off blocks, and
  `space_allocated` accounting byte-observable; the DUT reproduces
  `_upb_Arena_NextBlockSize`, `WouldReduceFreeSpace` (unsigned **wrapping**
  subtraction), `UpdateGrowthState`, `_upb_Arena_SlowMalloc`, realloc
  in-place/copy identity, shrink/try-extend last-alloc discipline, cleanup
  registration, and fused-lifetime free. Fused cleanup ORDER is
  representation (upstream fuses into the lower-address root; the court
  compares sorted).

---

## 2. Message storage

### 2.1 The message struct — this pin's layout is NOT the classic one

- `struct upb_Message` is a **single tagged word** (`upb/message/internal/
  types.h:25-30`): `union { uintptr_t internal; /* low bit == frozen */
  double d; /* forces 8 bytes on 32/64-bit */ }`. Low bit 0x1 = frozen
  (`types.h:36-43`); the rest points to a `upb_Message_Internal`
  (`types.h:45-49`).
- **There are no separate "unknown-fields pointer" and "extensions pointer"
  fields at this pin.** The old two-pointer layout was replaced by one pointer
  to `upb_Message_Internal` (`upb/message/internal/message.h:226-232`):
  `{ uint32_t size; uint32_t capacity; upb_TaggedAuxPtr aux_data[]; }` — every
  unknown chunk and every extension is one tagged entry, allocated out-of-line
  on the arena. **[R]** — the Rust kernel can use a different internal
  representation as long as observable iteration order (wire order of unknown
  data, `message.h:402-420`) and `upb_Message_HasUnknown` semantics
  (`upb/message/message.h:59-70`) match.
- Tag encoding of `upb_TaggedAuxPtr` (`internal/message.h:46-84`):
  bits 0-1: format/known; bit 2: aliased. Tags: `000` unknown data, `100`
  aliased unknown data, `001` non-canonical extension, `011` canonical
  extension (`types.h:18-23`; predicates `internal/message.h:86-120`).
  Non-aliased unknown data has guaranteed layout `[upb_StringView][data]`
  (`internal/message.h:63-74`).

### 2.2 Size class system — **[VERIFIED-ABSENT]**

- No `kUpb_Message_MiniTableSizeClass`, no UPB_SIZE-based size classes, no
  12-byte/16-byte minimum message sizes at this pin (searched
  `upb/message/*`, `upb/message/internal/*`: 0 hits). Messages are plain arena
  allocations of exactly `m->size` bytes. The 12/16-byte minimums and size
  classes are a property of older upb; do not port them.

### 2.3 Allocation and alignment

- `_upb_Message_New(m, a)` (`internal/message.h:296-311`):
  `upb_Arena_Malloc(a, m->size)` then `_upb_Message_AlignedMemsetZero` (ARM
  MOPS-optimized zeroing, L249-292). Public `upb_Message_New`
  (`upb/message/message.c:34-36`).
- Message alignment claim: **[VERIFIED-ABSENT]** — there is no 16-byte
  `kUpb_Message_Alignment`. The constant is `kUpb_Message_Align = 8`
  (`upb/mini_table/internal/message.h:62-64`), and minitable sizes are aligned
  up to 8 at construction time ("Since messages are always allocated on arenas,
  we can save repeatedly realigning by doing alignment at minitable
  construction time", `upb/mini_descriptor/decode.c:699-705`). Invariants:
  `UPB_MALLOC_ALIGN >= kUpb_Message_Align` and `size % kUpb_Message_Align == 0`
  (`mini_table/internal/message.h:101-106`). So message alignment is 8 (16 only
  coincidentally under HWASAN where `UPB_MALLOC_ALIGN` is 16).
- Hasbits (presence bitmap) live **inside the message body**, immediately after
  `struct upb_Message`: `kUpb_Reserved_Hasbytes = sizeof(struct upb_Message)`
  (= 8) are reserved so hasbit 0..63 are unused (`mini_descriptor/decode.c:
  53-57`); required fields get the lowest hasbits starting at 64
  (`AssignHasbits`, `decode.c:623-659`, esp. L627-643); the size starts at
  `ceil((last_hasbit+1)/8)` bytes for the bitmap (L657-658). The bitmap is
  read as a big-endian 64-bit word at `msg + 1`
  (`upb/message/internal/accessors.h:148-154`).
- Oneof case slots are 4-byte words placed in the layout
  (`kUpb_OneOf_CaseFieldRep`, `decode.c:61-62`, `AssignOffsets` L681-697); a
  field's `presence` is `~case_offset` for oneof members (`field.h:24`,
  `internal/accessors.h:102-115`).

### 2.4 Field data layout

- Field values are stored at `(char*)msg + f->offset`
  (`internal/accessors.h:156-165`); representation size comes from the field's
  rep (1/4/8/16 bytes; StringView is 8/16 by platform) and offsets are
  assigned in alignment-grouped regions (`mini_descriptor/decode.c:303-344`
  size/align tables, `CalculateAlignments` L581-617, `AssignOffsets` L668-706).
  **[R]** (offsets must match only if Rust must read C-layout messages, i.e.
  ABI phase).

---

## 3. Mini table layout

### 3.1 `upb_MiniTable` (`upb/mini_table/internal/message.h:71-94`)

| field | type | note |
|---|---|---|
| `fields` | `const upb_MiniTableField*` | L72 |
| `size` | `uint16_t` | message byte size, aligned to `kUpb_Message_Align` (L74-76) |
| `field_count` | `uint16_t` | L78 |
| `ext` | `uint8_t` | `upb_ExtMode` (L80) |
| `dense_below` | `uint8_t` | dense-array fast path for `FindFieldByNumber` (L81, L288-297) |
| `table_mask` | `uint8_t` | fasttable mask (L82) |
| `required_count` | `uint8_t` | low hasbits are required (L83) |
| `full_name` | `const char*` | tracing only (L85-87) |
| `fasttable[]` | `_upb_FastTable_Entry[]` | flexible array, `UPB_FASTTABLE` only (L89-93) |

`upb_ExtMode` (L41-55): NonExtendable=0, Extendable=1, IsMessageSet=2,
IsMessageSet_ITEM=3, IsMapEntry=4 (build-time only), AllFastFieldsAssigned=8.
Lookup: dense index then binary search (`internal/message.h:288-314`);
unknown-gap finding L345-393; required mask helper L432-437.

### 3.2 `upb_MiniTableField` (`upb/mini_table/internal/field.h:21-35`)

```c
struct upb_MiniTableField {
  uint32_t number;          // field number (must be first; L213-215)
  uint16_t offset;          // byte offset in message
  int16_t  presence;        // >0: hasbit index; <0: ~oneof_index
  uint16_t submsg_ofs;      // offset (in u32 units) to MiniTableSub; kUpb_NoSub if none
  uint8_t  descriptortype;  // upb_FieldType
  uint8_t  mode;            // FieldMode | LabelFlags | (FieldRep << 6)
};
```

- `kUpb_NoSub = 0xFFFF`, `kUpb_SubmsgOffsetBytes = 4` (L37-38); sub is at
  `field + submsg_ofs * 4` (`mini_table/internal/message.h:144-151`). Struct is
  12 bytes; `sizeof(upb_MiniTableField) == sizeof(uint32_t) * 3` is
  static-asserted for the ARM lookup (L192-193).
- `mode` layout: mode mask 3 (`upb_FieldMode` L40-47: Map=0, Array=1,
  Scalar=2); label flags L50-59 (IsPacked=4, IsExtension=8, IsAlternate=16);
  rep shift 6 (L73), reps L62-71 (1Byte=0, 4Byte=1, StringView=2, 8Byte=3,
  NativePointer=platform pick). Presence semantics: hasbit bit/byte math
  L135-152, oneof L159-162/L189-193, `HasPresence` L170-177.
  "Alternate" type rewrites (enum→int32, string→bytes) L104-128.

### 3.3 `upb_MiniTableSub` (`upb/mini_table/internal/sub.h:14-19`)

```c
union upb_MiniTableSub { const struct upb_MiniTable* submsg;
                         const struct upb_MiniTableEnum* subenum; };
```
Pointer-sized (asserted at `mini_table/internal/message.h:319-320`). Subs are
allocated in a zeroed block right after the field array during minitable build
(`mini_descriptor/decode.c:566-578`); "linked" means submsg != NULL
(`mini_table/internal/message.h:161-164`), and unlinked message fields are
treated as unknown-field gaps (`_upb_MiniTable_GapIfUnlinked`, L316-337).

### 3.4 Fast table

- `_upb_FastTable_Entry { uint64_t field_data; _upb_FieldParser*
  field_parser; }` (`mini_table/internal/message.h:31-34`); parser signature
  L26-29 (takes decoder, ptr, msg, table, hasbits, data, data2).
- Built by `upb_DecodeFast_BuildTable` into a 32-entry table
  (`upb/wire/decode_fast/select.h:24-51`); "the lower a field number, the
  hotter the field" assumption (L43-45); `upb_DecodeFast_GetTableMask`
  produces `table_mask` (L49-51); table size folded into minitable at build
  time (`mini_descriptor/decode.c:825-833`). **[R]** — the Rust decoder may
  implement dispatch differently, but the semantic surface (option
  `kUpb_DecodeOption_DisableFastTable`, `upb/wire/decode.h:64-67`) must exist.

---

## 4. Arrays and maps

### 4.1 `upb_Array` (`upb/message/internal/array.h:32-44`)

```c
struct upb_Array { uintptr_t data;  // bits 0-1 elem-size lg2, bit 2 frozen
                   size_t size;     // element count
                   size_t capacity; };  // element count
```
Elem sizes 1/4/8/16 via lg2 encoding `bits + (bits != 0)` (L33-40, L54-67);
mask constants L19-21. Default initial capacity **4**
(`_UPB_ARRAY_DEFAULT_INITIAL_SIZE`, L27; `upb/message/array.c:25-28`). The
element buffer is usually the same allocation as the struct (data right after
the header, `internal/array.h:78-95`) — a fast-path constructor
(`_upb_Array_TryFastNew`, L103-107) avoids the slow alloc when the arena window
is too small (used by the decoder).

Growth (`_upb_Array_Realloc`, `array.c:163-192`): capacity doubles
(`new_capacity = MAX(capacity, 4)`; `upb_ShlOverflow` loop L170-176; SIZE_MAX
is a hard failure L178-180), then `upb_Arena_Realloc` (in-place via
`TryExtend` when the array was the last alloc, else copy). Fast in-place path:
`_upb_Array_TryFastRealloc` via `upb_Arena_TryExtend` (L114-123). `Resize`
zeroes the grown region (`array.c:147-161`).

> **Phase 1 court:** the Rust `Array` (header+data single arena allocation,
> interior data-region realloc modeled as a sub-alloc) is PARITY-SEALED by
> `courts/collections` (collections-v1, 52/52, 0 residuals): new/append/set/
> resize/get with per-op data hex and space accounting. `upb_Array_Set` has
> `UPB_ASSERT(i < size)` which NDEBUG builds compile out — upstream writes
> regardless of `size`; the DUT mirrors this within capacity and REFUSES
> `i >= capacity` (upstream heap overflow, §49 divergence). String arrays
> (lg2=4, pointer-valued StringView content) are out of court scope.

### 4.2 `upb_Map` (`upb/message/internal/map.h:33-47`)

```c
struct upb_Map { char key_size; char val_size;  // UPB_MAPTYPE_STRING(0) sentinel
                 bool is_frozen; bool is_strtable;
                 union upb_Map_Table t; };  // upb_strtable | upb_inttable
```
Creation (`map.c:179-195`): int table when `key_size <= sizeof(uintptr_t)`
and not a string, else string table (`upb_strtable_init(t, 4, a)`).
CType→size table: `map.c:30-42` (bool=1, float/i32/u32/enum=4, msg=ptr, dbl/
i64/u64=8, string/bytes=0 sentinel).

Entry storage: open-addressed chained hash tables (`upb_table`/`upb_tabent`,
`upb/hash/common.h:123-140`; mask+1 buckets, `kUpb_NoNextTabent=1` chaining).
String keys are **copied into the arena** as `upb_SizePrefixString` on insert
(`upb/hash/common.c:593-611`, `upb_SizePrefixString_Copy`); table resize
doubles (`upb_strtable_resize`, `common.c:566-591`). String **values** are
stored as arena-allocated `upb_StringView*` (`_upb_map_tovalue`,
`internal/map.h:91-101`); non-string values are packed into the 8-byte
`upb_value` (L44-46). Insert is remove-then-insert and reports
Inserted/Replaced/OutOfMemory (`internal/map.h:172-203`, statuses L25-29).
`upb_MapEntry` (message-shaped layout) exists only for parsing
(`upb/message/internal/map_entry.h:17-39`). **[R]** — the Rust map can be any
structure preserving iteration/insert/delete semantics; map *order* is defined
by hash layout, so iteration order is **not** part of the wire contract (only
deterministic encode via `kUpb_EncodeOption_Deterministic` sorts separately,
`upb/wire/encode.h:29-36`).

> **Phase 1 court:** the Rust `Map` (content semantics only) is PARITY-SEALED
> by `courts/collections` (collections-v1, 52/52, 0 residuals) over
> insert/get/delete/iterate with bool/uint32/double/string keys and values
> including hostile bit patterns; iteration is compared as a sorted set. The
> oracle emitter initially started its iteration state at 0 instead of
> `kUpb_Map_Begin` ((size_t)-1) — entries hashing to slot 0 were silently
> skipped (hash/common.c `next()` increments before scanning); fixed and
> regression-covered.

---

## 5. Unknown fields

- **Not a chunked linked list at this pin.** Unknowns are entries in
  `upb_Message_Internal.aux_data` — each a `upb_TaggedAuxPtr` pointing at a
  `upb_StringView` (`internal/message.h:46-84`; "Unknown data may be stored
  non-contiguously. Each segment stores a block of unknown fields",
  `message.h:40-48`; iteration order = parse order).
- Non-aliased chunk layout `[upb_StringView][data]` in one arena alloc
  (`internal/message.h:63-74`; `_upb_Message_AddUnknownSlowPath`,
  `message.c:80-92`); the view may point into the middle of the buffer after
  prefix deletion (`internal/message.h:72-74`, `unknown_fields.c:109-114`).
- Coalescing: `kUpb_AddUnknown_AliasAllowMerge` merges into the previous
  chunk with a pointer-bump (`internal/message.h:333-361`); the copy path
  extends in place via `upb_Arena_TryExtend` when the chunk was the last arena
  alloc (`message.c:48-73`), else appends a new aux entry. Multi-segment API:
  `_upb_Message_AddUnknownV` (`message.c:101-161`).
- `aux_data` growth: `_upb_Message_ReserveSlot` (`upb/message/internal/
  message.c:56-86`) — first alloc capacity 4; then round up to next power of
  two (`upb_RoundUpToPowerOfTwo(in->size + 1)`), realloc'ing the internal
  block; capacity/size are `uint32_t`, so `UINT32_MAX` is the hard cap
  (L69-72).
- Iteration: `upb_Message_NextUnknown` (`internal/message.h:402-420`).
  Deletion supports whole-chunk, prefix strip, truncate, and middle split
  (`upb/message/unknown_fields.c:82-154`); non-canonical extensions delete by
  nulling the slot (L92-100).
- Limits: no `kUpb_UnknownFields_*` constants at this pin
  ([VERIFIED-ABSENT] — searched `upb/message/`). Bounds are `UINT32_MAX` aux
  entries, overflow-checked sizes (`upb_AddOverflow`, `message.c:62, 86,
  108-112, 142`), and the arena window.

---

## 6. String/bytes data

- `upb_StringView { const char* data; size_t size; }`
  (`upb/base/string_view.h:23-26`) — the inline field value in the message
  body is a StringView (rep `kUpb_FieldRep_StringView`, 8 bytes on 32-bit,
  16 on 64-bit, `mini_descriptor/decode.c:303-344`).
- The bytes live: (a) in the arena (copied by default), or (b) aliased from
  the caller's input buffer under `kUpb_DecodeOption_AliasString`
  (`upb/wire/decode.h:31-33`). Read path: read-ephemeral then
  `upb_Arena_Malloc` + `memcpy` unless aliasing
  (`upb/wire/internal/decoder.h:244-263`). Unknown fields alias the input
  buffer under the same option, with buffer-start boundary tracking to avoid
  bad coalescing (`upb/wire/decode.c:118-130`, `internal/message.h:363-372`).
- "Hot string" optimization: **[VERIFIED-ABSENT]** at this pin. Grep for
  `hot` across all of `upb/` yields only the fasttable comment about hot
  *fields* (`upb/wire/decode_fast/select.h:43-45`). (The hot-string cache
  landed in later upstream commits; do not assume it.)

---

## 7. Ownership / lifetime

- **Arena-owned:** message bodies, `upb_Message_Internal` blocks, unknown
  chunk buffers, `upb_Extension` records, arrays, map objects, map key copies,
  map string values, submessage bodies, copied string data. Nothing in a
  message graph owns memory of its own; the graph is a tree of pointers into
  one or more fused arenas. Children own no memory; no destructors run
  (`upb/mem/arena.h:8-12`).
- **Pointer-aliased:** string bytes and unknown-field bytes when decoding with
  `kUpb_DecodeOption_AliasString` (aliasing unknowns are tagged `100`). The
  caller must keep the input buffer alive until the arena dies.
- **Message-owned on clear:** `upb_Message_Clear` zeroes the body (`memset`,
  `upb/message/internal/accessors.h:876-885`) and empties the aux array
  (`in->size = 0`) — the internal block and the unknown buffers remain
  allocated (arena semantics: nothing is returned), but entries are dropped.
  `upb_Message_ClearBaseField` zeroes field storage + presence
  (L887-900); `_upb_Message_DiscardUnknown_shallow` drops unknown entries but
  keeps canonical extensions (`message.c:163-176`).
- **Frozen messages:** `upb_Message_Freeze` sets the low bit and recurses into
  submessages/arrays/maps (`upb/message/message.c:191-259`); array/map frozen
  bits at `internal/array.h:46-52`, `internal/map.h:53-59`. All mutation APIs
  assert `!IsFrozen` (e.g. `internal/array.h:128`, `message.c:43`). **[S]**
- **Cross-message pointers:** submessage fields are `upb_Message*` pointing at
  arena allocations in the same (possibly fused) arena; arrays hold
  element-sized copies of values (for message elems, pointers);
  `upb_Extension.data` is a `upb_MessageValue` copy (`upb/message/internal/
  extension.h:33-36`).

---

## 8. Parity classification

| Topic | Class | Rust constraint |
|---|---|---|
| Arena bump alloc, stable pointers, never move without explicit realloc | **S** | must hold — **COURTED**: arena-v1 (61/61) |
| Arena growth doubling / 128 start / 32768 cap / one-off blocks | **R** | observable via `upb_Arena_SpaceAllocated` + allocator call counts — **COURTED** (arena-v1 keeps these numbers equivalent) |
| `UPB_MALLOC_ALIGN`=8, ASAN guard, block header reserve | **R** | sanitizer-specific; not part of Rust kernel ABI |
| Fuse/ref semantics (lifetime union, no initial-block fuse, refs between unfused arenas) | **S** | must hold (affects free-ordering observability) — **COURTED**: arena-v1 (fuse refusal, fused free, cleanup sets) |
| Message = single tagged internal pointer; aux_data of tagged ptrs | **R** | internal repr free; iteration order of unknowns/extensions is **S** (wire order) |
| Presence bitmap in message body; hasbits required-first; oneof case words | **R** (**A** for C-compat) | offsets/bits matter only if Rust reads C-laid-out messages (ABI phase); `required` behavior is **S** |
| `kUpb_Message_Align` = 8; minitable size aligned at build | **S** (size) / **R** (mechanics) | messages must be ≥8-aligned if C ABI |
| No size classes, no 12/16-byte minimums | — | do not reintroduce |
| MiniTable/Field/Sub/fasttable layouts | **R** | **A** only for C-compat phase; Rust may use its own schema repr |
| Array/Map layouts, doubling growth, initial 4 | **R** | semantics (reserve/append/insert statuses, OOM on growth) are **S** — **COURTED**: collections-v1 (52/52) |
| Unknown fields as StringView segments, coalescing | **R** | chunk boundaries after parse are **S** (visible via `upb_Message_NextUnknown` / `DeleteUnknown2`) |
| String alias-vs-copy under `kUpb_DecodeOption_AliasString` | **S** | pointer identity of decoded strings observable; must alias when set |
| Freeze bit and recursion | **S** | must match |
| No `Arena_Reset`, no arena err-handler, no `MallocAligned`, no hot-string | — | verified absent; do not add |

## 9. Unverified / explicitly-verified-absent items

- Verified absent (grep, whole `upb/` tree): `upb_Arena_Reset`;
  `upb_Arena_MallocAligned`; `upb_Arena_HasErrHandler` (only a sketch in a
  comment, `upb/base/error_handler.h:35`); `kUpb_Message_MiniTableSizeClass`;
  `kUpb_Message_Alignment` (16-byte); `kUpb_UnknownFields_*`; any "hot string"
  machinery.
- Not verified: exact `upb_MiniTableExtension` byte layout vs generated code
  consumers (only the header was read; see `upb/mini_table/internal/
  extension.h:21-33`); 32-bit-platform behavior of `upb_Array` elem sizes
  (16-byte elems on 32-bit were not exercised); the effect of ASAN/HWASAN
  builds on block-size accounting (guards change spans, `sanitizers.h:49-55`);
  behavior of `upb_Arena_SpaceAllocated` under racing fuses (documented
  monotonic by code comment only, `arena.c:294-298`).
