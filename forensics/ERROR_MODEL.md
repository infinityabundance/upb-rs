# ERROR_MODEL.md — upb error model at pin 2de70d710

Scope: error taxonomy, observable error surfaces, partial-state semantics, OOM,
depth limits, and the upb-rs compatibility claim. All citations are to
`third_party/protobuf/` at commit `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`
(v36-dev-400, 2026-08-19).

Legend: **[S]** semantic (must match in Rust), **[R]** representation,
**[VERIFIED-ABSENT]** searched and confirmed not present at this pin.

---

## 1. Error taxonomy

### 1.1 `upb_ErrorCode` and `upb_ErrorHandler` (longjmp base)

`upb/base/error_handler.h:55-65`:

```c
typedef enum {
  kUpb_ErrorCode_Ok = 0,
  kUpb_ErrorCode_OutOfMemory = 1,
  kUpb_ErrorCode_Malformed = 2,
  kUpb_ErrorCode_MaxDepthExceeded = 3,
} upb_ErrorCode;

typedef struct {
  int code;
  jmp_buf buf;
} upb_ErrorHandler;
```

Mechanics: `upb_ErrorHandler_Init` sets `code = Ok` (L67-69);
`upb_ErrorHandler_ThrowError(e, code)` stores the code then `UPB_LONGJMP`
(L71-76). The code is carried out-of-band because setjmp's return value is not
storable (L20-23). longjmp-based handling is for C parse paths; the header
explicitly documents that C++-compatible consumers need a return-based
mechanism (L25-30), and sketches the dual style with `upb_Arena_HasErrHandler`
(L32-50) — **that function does not exist at this pin** ([VERIFIED-ABSENT];
grep over `upb/mem` + `upb/base`: 0 hits). Error-handler propagation lives at
call sites instead (see §1.3, §4).

### 1.2 Return-based statuses: decode and encode

`upb_DecodeStatus` (`upb/wire/decode.h:86-100`) — values are aliases of
`kUpb_ErrorCode` for the first four, then private extensions:

| constant | value | meaning |
|---|---|---|
| `kUpb_DecodeStatus_Ok` | 0 | `= kUpb_ErrorCode_Ok` |
| `kUpb_DecodeStatus_OutOfMemory` | 1 | `= kUpb_ErrorCode_OutOfMemory` ("Arena alloc failed", L88-89) |
| `kUpb_DecodeStatus_Malformed` | 2 | `= kUpb_ErrorCode_Malformed` (L90-91) |
| `kUpb_DecodeStatus_MaxDepthExceeded` | 3 | `= kUpb_ErrorCode_MaxDepthExceeded` (L92-93) |
| `kUpb_DecodeStatus_BadUtf8` | 10 | string field had bad UTF-8 (L95) |
| `kUpb_DecodeStatus_MissingRequired` | 11 | `kUpb_DecodeOption_CheckRequired` failed (L97-99) |

Decode options that shape errors: `kUpb_DecodeOption_AliasString=1`,
`kUpb_DecodeOption_CheckRequired=2`, `kUpb_DecodeOption_AlwaysValidateUtf8=8`,
`kUpb_DecodeOption_DisableFastTable=16` (L30-68). Depth is packed in the top 16
bits: `upb_DecodeOptions_MaxDepth` (L71-73), effective max
`upb_DecodeOptions_GetEffectiveMaxDepth` (decode.c:1306-1309) defaults to 100.
The decoder statically asserts the first three decode statuses equal the
error-code values (`upb/wire/internal/decoder.h:88-94`).

`upb_EncodeStatus` (`upb/wire/encode.h:46-57`):

| constant | value | meaning |
|---|---|---|
| `kUpb_EncodeStatus_Ok` | 0 | `= kUpb_ErrorCode_Ok` |
| `kUpb_EncodeStatus_OutOfMemory` | 1 | `= kUpb_ErrorCode_OutOfMemory` (L48-49) |
| `kUpb_EncodeStatus_MaxDepthExceeded` | 3 | `= kUpb_ErrorCode_MaxDepthExceeded` (L52) |
| `kUpb_EncodeStatus_MissingRequired` | 10 | only with `kUpb_EncodeOption_CheckRequired` (L50-51, 54) |
| `kUpb_EncodeStatus_MaxSizeExceeded` | 11 | message exceeds 2GB limit (L55-56) |

Note the **class-extension values collide across surfaces by design but mean
different things**: decode 10=BadUtf8 / 11=MissingRequired vs encode
10=MissingRequired / 11=MaxSizeExceeded. Encode options: Deterministic=1,
SkipUnknown=2, CheckRequired=4 (L29-43).

### 1.3 The classic `upb_Status` (string error channel)

`upb/base/status.h:16-21`: `upb_Status { bool ok; char msg[511]; }` —
`_kUpb_Status_MaxMessage = 511`. Setters (status.c:19-61): `Clear` (ok=true,
empty msg), `SetErrorMessage` (strncpy, truncating), `SetErrorFormat`/
`VSetErrorFormat` (vsnprintf into the 511-byte buffer), and
`VAppendErrorFormat` (appends to the current message; used for the
prefix+detail pattern). All are no-ops when `status == NULL` (L30). **There is
no standard error-string prefix for binary decode** — `upb_Decode` takes no
`upb_Status`; its error string surface is `upb_DecodeStatus_String`
(`upb/wire/decode.c:1375-1392`):

- `Ok` → `"Ok"`
- `kUpb_DecodeStatus_Malformed` → `"Wire format was corrupt"`
- `kUpb_DecodeStatus_OutOfMemory` → `"Arena alloc failed"`
- `kUpb_DecodeStatus_BadUtf8` → `"String field had bad UTF-8"`
- `kUpb_DecodeStatus_MaxDepthExceeded` → `"Exceeded upb_DecodeOptions_MaxDepth"`
- `kUpb_DecodeStatus_MissingRequired` → `"Missing required field"`
- default → `"Unknown decode status"`

`upb_EncodeStatus_String` (`upb/wire/encode.c:38-51`): `"Ok"`,
`"Missing required field"`, `"Max depth exceeded"`, `"Arena alloc failed"`,
default `"Unknown encode status"`.

### 1.4 Decode path: longjmp-into-return translation

`upb_Decode` installs a stack `upb_ErrorHandler` and translates longjmp to a
return value (`upb/wire/decode.c:1311-1323`); the translation is in
`upb_Decoder_Decode`:

```c
if (UPB_SETJMP(decoder->err->buf) == 0) {
  decoder->err->code = _upb_Decoder_DecodeTop(decoder, buf, msg, m);
} else {
  UPB_ASSERT(decoder->err->code != kUpb_DecodeStatus_Ok);
}
return upb_Decoder_Destroy(decoder, arena);
```
(decode.c:1288-1300; `upb_Decoder_Destroy` swaps the inlined arena back out and
returns `err->code`, `upb/wire/internal/decoder.h:123-127`). Every internal
error is a `ThrowError(d->err, kUpb_DecodeStatus_*)` call — e.g. OOM at
decode.c:97, 169, 186, 332, 355, 467, 526, 531, 607, 647, 950, 1076, 1235;
Malformed at 202, 226, 251, 254, 699, 718, 934, 990, 1015; MaxDepthExceeded at
196-198, 614-616. `_upb_Decoder_DecodeTop` adds the return-only statuses:
unterminated group → Malformed, `d->missing_required` → MissingRequired
(decode.c:1278-1286).

---

## 2. Observable error surfaces

| Surface | OK signal | Error signal | Error string? | Position? |
|---|---|---|---|---|
| `upb_Decode` / `upb_DecodeLengthPrefixed` | `kUpb_DecodeStatus_Ok` (0) | enum status (see §1.2) | via `upb_DecodeStatus_String` only; not passed by the API | no |
| `upb_Encode` / `upb_EncodeLengthPrefixed` | `kUpb_EncodeStatus_Ok` (0) | enum status | via `upb_EncodeStatus_String` | no |
| `upb_Message_MergeFrom` | `true` | `false` (both directions collapsed) | no | no |
| `upb_JsonDecode` (inline, decode.h:37-46) | `true` | `false`; `upb_JsonDecodeDetectingNonconformance` returns `kUpb_JsonDecodeResult_Error` (2; decode.h:27-30) | **yes** — `upb_Status` | **yes** — `@line:col` |
| `upb_JsonEncode` | return `< size` (snprintf semantics, encode.h:32-39) | truncated output (`>= size`) and/or `upb_Status` | **yes** — `upb_Status` | no |
| `upb_DefPool_New` | non-NULL | NULL on OOM (def_pool.c:66-100) | no | no |
| `upb_DefPool_SetFeatureSetDefaults` | `true` | `false` + status | yes | no |
| `upb_DefPool_AddFile` | non-NULL FileDef | NULL + status | yes | no |
| `upb_MiniTable_Build` / `upb_MiniTableExtension_Build` | non-NULL | NULL + status | yes — `"Error building mini table: "` prefix | no |
| `_upb_MiniTable_BuildWithBuf` | non-NULL | NULL + status | same | no |

### 2.1 Stable error strings — JSON decode (with position)

Prefix (both the `jsondec_err` plain and `jsondec_errf` printf variants):

- `"Error parsing JSON @%d:%d: %s"` — line, column (`d->ptr - d->line_begin`),
  message (`upb/json/decode.c:88-91`).
- `"Error parsing JSON @%d:%d: "` + appended detail (`decode.c:104-113`).

Messages passed to these (stable; quote verbatim from source):
`"Out of memory"` (L100), `"Recursion limit exceeded"` (L228), `"Integer
overflow"` (L662), `"Non-number characters in quoted integer"` (L670, L679),
`"Empty string is not a valid number (field: %s). This will be an error in a
future version."` (L688-691), `"JSON number is out of range."` (L704, L742),
`"JSON number was not integral (%f != %" PRId64 ")"` (L708-709),
`"Expected number or string"` (L720, L758, L805), `"Integer out of range."`
(L726, L763), `"Non-number characters in quoted number (field: %s). This will
be an error in a future version."` (L796-800), `"Object must start with
string"` (L267), `"unexpected trailing characters"` (L1580). Trailing-input
check at `upb_JsonDecoder_Decode` (L1577-1582); JSON depth default **64**
(L1602) — distinct from the wire default of 100.

### 2.2 Stable error strings — JSON encode

`jsonenc_err` / `jsonenc_errf` set `upb_Status` directly, no prefix, no
position (`upb/json/encode.c:58-70`). Samples: `"Out of memory"` (L77, L397),
`"error formatting timestamp as JSON: invalid nanos"` (L124),
`"error formatting timestamp as JSON: minimum acceptable value is
0001-01-01T00:00:00Z"` (L143-146), `"...maximum acceptable value is
9999-12-31T23:59:59Z"` (L147-150), `"bad duration"` (L188), `"Tried to encode
Any, but no symtab was provided"` (L357), `"Couldn't find Any type: %.*s"`
(L376), `"Bad type URL: ..."` (L382), `"Error decoding message in Any"`
(L403), `"No value set in Value proto"` (L533).

### 2.3 Stable error strings — mini descriptor decode

All failures go through `upb_MdDecoder_ErrorJmp`
(`upb/mini_descriptor/internal/decoder.h:26-36`), which sets
`"Error building mini table: "` via `upb_Status_SetErrorMessage` then appends
the format detail via `VAppendErrorFormat`. Examples (mini_descriptor/
decode.c): `"Invalid field type: %d"` (L216, L223), `"Empty oneof"` (L286),
`"Submessage offset overflow"` (L459), `"Invalid field number: %" PRIu32`
(L493), `"Extensions cannot have oneofs."` (L507), `"Invalid skip value: 0"`
(L521), `"Field number overflow"` (L524), `"Invalid char: %c"` (L529),
`"MiniDescriptor is too large"` (L549), `"Too many required fields"` (L638),
`"Too many fields with presence"` (L651), `"Message size exceeded maximum size
of %zu bytes"` (L613-614), `"map %s cannot have type %d"` (L734), `"%hu fields
in map"` (L745), `"Map entry cannot have oneof"` (L751), `"Invalid message set
encode length: %zu"` (L769), `"Invalid message version: %c"` (L818). OOM:
`"Out of memory"` via `upb_MdDecoder_CheckOutOfMemory` (decoder.h:38-41).

### 2.4 Stable error strings — def pool / def builder

`upb/reflection/def_pool.c`: `"Failed to parse defaults"` (L136), `"Feature
set defaults can't be changed once the pool has started building"` (L140-142),
`"Invalid edition range %s to %s"` (L148), `"Invalid edition UNKNOWN
specified"` (L161), `"Feature set defaults are not strictly increasing, %s is
greater than or equal to %s"` (L165-167), `"duplicate symbol '%s'"` (L191),
`"out of memory"` (L195, lowercase), plus `_upb_DefPool_AddFile` paths at
L444-473 (e.g. L451). `upb_DefPool_New` itself is silent NULL-on-OOM
(L66-100).

### 2.5 Tests that pin these surfaces

- decode_test.cc asserts statuses by value, e.g.
  `EXPECT_EQ(result, kUpb_DecodeStatus_MaxDepthExceeded)` (wire/decode_test.cc:
  625-626) and Malformed for truncated MessageSet (L934-938); the
  `<< upb_DecodeStatus_String(result)` pattern is pervasive (L139-625), so the
  *strings* are only used in failure diagnostics, not asserted.
- `upb_MiniTable_Build` failures assert `upb_Status_IsOk` and print
  `upb_Status_ErrorMessage` (wire/decode_test.cc:954-958).
- No `*_test.cc` in the tree asserts the exact JSON error strings
  (grep over `upb/json/*_test.cc`: 0 hits on `ErrorMessage`/`status.msg`).

---

## 3. Partial-state semantics

### 3.1 Failed binary decode leaves a partially-populated message

`upb_Decode` decodes **into the caller's message in place** (decode.c:1311-
1323); there is no staging copy and no rollback. Errors are thrown mid-parse
(§1.4), so everything parsed before the failure remains: field values are
written as fields are encountered, arrays are appended incrementally
(`_upb_Decoder_Reserve`, decode.c:92-100), submessages are created and filled
(`_upb_Decoder_NewSubMessage2`, decode.c:166-171), and unknown fields are
appended (decode.c:625-648). On longjmp the partial state is simply returned
to the caller with a non-Ok status. Rust must reproduce: **on Malformed/OOM/
MaxDepthExceeded/BadUtf8, the target message contains the prefix of the input
that was successfully parsed** (including partial submessages and unknowns).
The `kUpb_DecodeOption_CheckRequired` caveats are documented in
decode.h:41-51 (a false-positive failure when an incomplete submessage is later
completed; a false success when decoding into a message with pre-existing
submessage fields — so `MergeFromString` semantics need a post-parse check).

### 3.2 Failed merge

`upb_Message_MergeFrom` is encode-then-decode at this pin (merge.c:14-38):
serialize `src` into a temp arena, then `upb_Decode(buf, ..., dst, ..., arena)`.
On encode failure → `false` with **dst untouched**; on decode failure → `false`
with **dst left in the same partial state as §3.1** (a prefix of `src`'s
serialization merged in). `dst`'s prior contents are *not* reverted.

### 3.3 Failed JSON decode

Same in-place pattern: `upb_JsonDecoder_Decode` setjmp-returns Error
(json/decode.c:1566-1583) after `jsondec_tomsg` has been writing into `msg`
directly — partial message content persists. Nonconformance-only warnings
("This will be an error in a future version.") set `result =
kUpb_JsonDecodeResult_Error` *without* longjmp, so parsing continues and the
message is fully populated (decode.c:684-692, 794-801).

### 3.4 Failed mini table build / def pool add

`upb_MiniTable_Build` on failure returns NULL and the arena may hold garbage
sub-table state (caller discards; documented contract "returns NULL and sets a
status message", `upb/mini_descriptor/decode.h:41-47`). `upb_DefPool_AddFile`
on failure leaves the pool without the file; symbol insertion is
check-then-insert so duplicate symbols fail before mutation (def_pool.c:186-
198).

---

## 4. OOM semantics

- **Without an error handler:** arena allocation fails by returning NULL —
  `_upb_Arena_SlowMalloc` returns NULL when the block allocator is absent or
  allocation fails (arena.c:482, 488); `_upb_Arena_InitSlow` returns NULL when
  the first block cannot be allocated (arena.c:512-522). Callers must check.
- **In the decode path (the only longjmp-using path at this pin):** every
  NULL-propagating allocation site converts to a thrown status. The decoder
  checks `upb_Message_New` results (`_upb_Decoder_NewSubMessage2`,
  decode.c:167-170), array growth (decode.c:92-100), extension creation
  (decode.c:604-608), unknown appends (decode.c:646-648), and string copies
  (`_upb_Decoder_ReadString`, decoder.h:255-260) — all throwing
  `kUpb_DecodeStatus_OutOfMemory`. The setjmp at decode.c:1293 converts this
  into the return value.
- **Arena itself does not throw at this pin.** The
  "`upb_Arena_MallocFallback` with err handler throws `kUpb_ErrorCode_
  OutOfMemory`" design from older upb is [VERIFIED-ABSENT]: `_upb_Arena_SlowMalloc`
  never touches an error handler, and there is no err field on
  `upb_Arena`/`upb_ArenaInternal` (arena.c:56-118). The sketch in
  error_handler.h:32-50 is documentation of a pattern, not this pin's code.
  The longjmp-based error code used by the decoder is exactly
  `kUpb_ErrorCode_OutOfMemory` (== `kUpb_DecodeStatus_OutOfMemory` == 1,
  decoder.h:88-91).
- **Thread-local OOM injection** for testing: `upb_AllocationCount_FailOn(n)`
  (`upb/mem/alloc.h:112-121`; counter machinery `upb/mem/internal/alloc.h:
  25-45`) forces the n-th allocation in the thread to fail; arena/alloc
  fast-path checks `upb_AllocationCount_IncrementAndCheck` before every alloc
  (internal/arena.h:94-99). Relevant for reproducing upstream allocation-
  failure tests (e.g. the pin commit itself adds unknowns/defbuilder
  allocation-failure tests).
- **JSON decode OOM:** `jsondec_checkoom` → `jsondec_err(d, "Out of memory")`
  (decode.c:98-102); encode OOM via `jsonenc_err(e, "Out of memory")`
  (encode.c:72-80).

---

## 5. Depth-limit errors

- Wire default: `kUpb_WireFormat_DefaultDepthLimit = 100`
  (`upb/wire/internal/constants.h:11`). Decoder depth initialized from
  options/effective-max (decoder.h:102; effective-max computation decode.c:
  1302-1309). Enforced:
  - `_upb_Decoder_RecurseSubMessage`: `if (--d->depth < 0) throw
    kUpb_DecodeStatus_MaxDepthExceeded` (decode.c:196-198) — every nested
    submessage/group consumes one level.
  - MessageSet item path: `if (d->depth <= 1) throw
    kUpb_DecodeStatus_MaxDepthExceeded` before recursing into the item
    (decode.c:613-616).
  - Unknown-field skipping also carries depth: `_upb_WireReader_SkipValue`
    with `d->depth` (decode.c:714, 1034, 1061, 1225).
- Fast-table path: `kUpb_DecodeStatus_MaxDepthExceeded` can be produced by
  the fast decoders' generic failure path (e.g. UPB_DECODEFAST_ERROR usage in
  `upb/wire/decode_fast/field_string.c:38` for BadUtf8; depth via the slow
  fallback). **[partially verified]** — the fasttable's depth bookkeeping was
  not traced end-to-end.
- JSON decode: hardcoded `d.depth = 64` (json/decode.c:1602);
  `jsondec_push`: `if (--d->depth < 0) jsondec_err(d, "Recursion limit
  exceeded")` (L226-229).
- Unknown-field promotion (`upb/message/promote.c`): `depth_limit = 100`
  default (L137, L224), applied via `_upb_WireReader_SkipValue` (L170, L187,
  L243, L252) and to nested `upb_Message_PromoteMessage` via
  `upb_DecodeOptions_GetEffectiveMaxDepth` (L285, L338, L383). Promotion
  failures surface as parse errors, not statuses.
- Encode: depth is enforced inside `upb/wire/internal/encoder.c` (encode.h:52
  exposes `kUpb_EncodeStatus_MaxDepthExceeded`; enforcement sites in
  encoder.c were not individually catalogued — [unverified]).

---

## 6. Compatibility claim for upb-rs

1. **Error class taxonomy — must always match [S].** `Ok=0, OutOfMemory=1,
   Malformed=2, MaxDepthExceeded=3` (`error_handler.h:55-60`), and the
   surface-specific extensions with their exact values: decode
   `BadUtf8=10, MissingRequired=11`; encode `MissingRequired=10,
   MaxSizeExceeded=11`. Rust should expose one error type whose discriminants
   equal these; do not rename or reorder.
2. **Error strings — preserve where stable and relied upon [S, subset].**
   The JSON decode `"Error parsing JSON @%d:%d: ..."` prefix with line:col is
   the only positional, user-visible string contract; the JSON encode
   well-known-type messages ("error formatting timestamp as JSON: ...",
   "bad duration", Any messages) and the mini-descriptor
   `"Error building mini table: "` prefix are stable and may be asserted by
   downstream tests (none in-tree at this pin, §2.5, but treat as
   semi-stable). Binary-decode/encode strings (`upb_DecodeStatus_String`,
   `upb_EncodeStatus_String`) are diagnostic helpers — match them for
   drop-in C-compat, but they are not part of the return contract. Def-pool
   strings ("duplicate symbol '%s'", "out of memory", edition errors) are
   stable and cheap to match.
3. **Position info — required for JSON decode only [S].** line:col relative
   to the JSON input; wire decode has no positions.
4. **Partial-state — semantic [S].** failed decode/merge leaves the prefix
   (see §3); Rust must not clear or roll back the target message.
5. **OOM behavior — semantic [S].** allocation failure inside decode must
   surface as `OutOfMemory` (1), never as Malformed; without an arena
   allocator, allocations return NULL. Rust's allocator API has no err
   handler; emulate by checked allocation + status mapping at the kernel
   boundary, and mirror `upb_AllocationCount_FailOn` injection if the fault-
   injection tests are ported.
6. **Depth limits — semantic [S].** wire default 100, JSON default 64,
   promotion default 100; user override via the top-16-bits options encoding
   (`upb_DecodeOptions_MaxDepth`, decode.h:71-73; `upb_Decode_LimitDepth`
   L78-83) with 0 → default.
7. **longjmp vs return [R].** The setjmp/longjmp mechanism is an internal
   implementation detail; Rust uses `Result`-style returns. Only the
   *mapping* (error codes, partial state, OOM class) is observable.

## 7. Unverified

- Fasttable decode's exact depth accounting and whether
  `MaxDepthExceeded` can originate there directly (only the slow-path sites
  are cited with confidence; see §5).
- Encode depth-limit enforcement sites in `upb/wire/internal/encoder.c` were
  not individually catalogued.
- Whether any out-of-tree consumer (Rust/other) asserts on
  `upb_DecodeStatus_String`/`upb_EncodeStatus_String` text — none in-tree.
- `upb_MiniTable_BuildWithBuf` failure behavior beyond the documented
  "returns NULL + status" (mini_descriptor/decode.h:104-113).
- Exact `upb_Message_MergeFrom` behavior under OOM of the internal temp
  arena (`upb_Arena_New()` returning NULL, merge.c:25) — code returns false
  only via the encode status path; a NULL temp arena would crash before that
  check ([flagged] — potential upstream bug, not asserted).
