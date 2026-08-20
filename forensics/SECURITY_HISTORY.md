# SECURITY_HISTORY.md — upb security archaeology

Oracle pin: `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (37-dev, 2026-08-19),
see `third_party/PIN.md`. All commit SHAs below are full SHAs as
resolved by `git log` in `third_party/protobuf`; file:line citations are
against the pinned working tree. Method notes: `git log --grep` was run
case-insensitively over commit subjects, scoped to `-- upb/` unless stated;
commits whose subjects are uninformative ("Internal change", "Auto-generate
files after cl/…") are called out as *opaque* and may hide fixes — the class
list is therefore not exhaustive. Anything inferred is marked **[INFERRED]**.

---

## 1. Known historical bug classes

### 1.1 Varint edge cases
- `9abf8e043` (2020-11-14) — "Clamp 32-bit varints to 5 bytes to fix a fuzz failure." A 32-bit varint with 64-bit sign extension could exceed 5 bytes; the clamp is the ancestor of the current 5-byte tag/size reader bound (`upb/wire/reader.c:33-61`) [INFERRED lineage — the causal chain is not documented in commit messages].
- `1380653e4` — "Reduce oversized stack buffers — 32 bit unsigned varints … can only take up 5 bytes." Stack-buffer sizing derived from wire limits.
- `f520cf3db` — "upb:decode initialize int inside loop for upb_DecodeLongVarintReturn."
- `b697882fb` — "Fixed varint length when buffer is reallocated." Buffer-refresh/realloc interaction.
- `4c65b25da` — "Handle long varints, now 2GB/s!" Perf work, but it is the origin of the long-varint fast/slow split still visible in `reader.c:41-81`.
- `ab3fb8469` — "Document backwards varint parsing implementation in unknown fields."
- Current semantics to preserve: `_upb_WireReader_ReadLongVarint` uses `val += (byte - 1) << (i * 7)` (`reader.c:24`), so the 10th byte of a 10-byte varint contributes only when `byte >= 2`, wrapping into bit 63; `0xFF ×10` (continuation bit on byte 10) is an error. **Oracle verification required — see OPEN_QUESTIONS §3.1.**

### 1.2 Recursion depth bypass
- `d1e231d4b` (2026-05-19) — "Fasttable: Fix recursion depth check." Fasttable used `--d->depth == 0` instead of `< 0`, an off-by-one that failed on messages *at* the maximum supported depth. Current code: `decode_fast/field_message.c:105-107`.
- `3d065d1ce` — "Fixed depth limit check by comparing effective depth limits." Depth 0 now means "use default" (`decode.c:1306-1309`).
- `95af41ec9` — "Fixed a few edge cases around depth limits in encode, decode, and compare."
- `565c8fe66` — "copy the wire decode recursion-depth-checking code to the wire encoder." Depth limit migrated from decode-only to encode.
- `e9551022c` — "Added depth limit checking to upb_encode()."
- `8ceca4cb5` (2026-05-29) — "Adds a new error code `kUpb_ErrorCode_MaxDepthExceeded`." Error surface split out from generic Malformed.
- `f9c91e3a1` / `c1727b730` — recursion limits tightened on fuzzer tests.
- `b4c3fecb8` — recursion guards for map fields and message_set extensions (Python runtimes, issue #25335).

### 1.3 Stack overflow / unbounded recursion (non-wire surfaces)
- `b72ed3b97` (2015-06-12) — "Fix for stack overflow for cyclic defs." Descriptor/symtab cycles.
- `0c7eb664f` — "JIT bugfix: align stack properly on getbytes_slow."
- `a5e6a7b02` — "Fix stack alignment on OS X."
- Wider-repo evidence that recursion DoS is a recurring class across protobuf runtimes (not upb itself): `35371e7ac` (2026-04-13) "Fix unguarded recursion DoS in Protobuf Lite skipField"; `8ae555223` (2026-05-26) "Add recursion depth check for TYPE_GROUP in UntypedMessage::Decode()"; `d2b001626` "Fix Any recursion depth bypass in Python json_format.ParseDict". These mark the class as live; upb-rs must treat depth accounting as a parity surface, not a style choice.

### 1.4 Integer overflow / OOM-adjacent arithmetic (the dominant recent class)
- `452153d35` (2026-06-04) — **"Fix integer overflow in upb_Arena_Malloc for near-SIZE_MAX allocations"** — the most important recent fix for us. `UPB_ALIGN_MALLOC(SIZE_MAX)` wraps to 0; on 32-bit/WASM32 reachable from untrusted wire input via packed bool fields whose array-capacity doubling overflows to `SIZE_MAX`. Guard now in `upb/message/array.c:171-185`; see §2.5.
- `c6b856d78` (2026-08-17, two days before the pin) — "Introduce overflow checking functions for add and multiply in upb to replace error-prone manual checks." This is `upb/port/overflow.h`; the pin therefore contains a *brand-new* helper API with limited call-site coverage — the audit of which call sites use it vs. still use raw arithmetic is **not complete upstream** [INFERRED from commit date].
- `b22d59765` — "Detect overflow in upb_Array_Realloc()."
- `6a3bcdaca` (2026-03-11) — "overflow checks in unknown field realloc" (touches `upb/base/internal/log2.h`, `upb/message/internal/message.c`, `upb/message/message.c`, `upb/wire/encode.c`).
- `40ad7ae2a` — "Check upb reflection allocations for size_t overflow."
- `cf7705065` — "Overflow checks for attempting to insert massive strings into strtable."
- `3fe820ce6` — "Overflow check math in build_enum.c."
- `ba511fd42` — "Added a size overflow check for mini-table building."
- `08b43e787` — "Fix potential integer overflow in upb_StringView_Compare."
- Mini-table/meta-schema overflow guards: `65fccf3b0` (2026-07-13) "reject mini_tables whose presence index overflows int16_t (#28231)"; `78d8c10dc` (2026-05-05) "Check for uint16_t field_count overflow in upb_MtDecoder_Parse() (#27133)"; `cfa9acc18` (2026-06-10) "fix: validate lower bound for dependency indices in upb file_def (#26562)"; `085b305c2` (2026-08-12) "check sub array bounds before indexing in upb_MiniTable_Link (#28553)".
- `c4e07ae40` (2026-07-01) — "Harden against size_t overflow in upb json decode" (2-line fix in `upb/json/decode.c`).
- `58edfa50c` (2026-05-13) — "upb/json: fix sign-extended index in jsondec_base64_tablelookup (#27215)." Out-of-bounds table read class.
- `4215bc82e` — "fix the json parser to handle floats very near overflow."

### 1.5 Untrusted-length / preallocation / delimited-size discipline
- `d8a1f8cf7` — "Optimized and refined bounds checking for delimited fields."
- `e028049e7` — "Merge bounds checks for scalar encode." / `ab7ec2887` — "Avoid NULL - NULL UB on the first bounds check of encoding a proto."
- `5f1c06a28` / `b32b101ba` — debug asserts for scalar-op bounds; fast decoder asserts.
- `48689df72` — "Eliminated bounds checks inside parsing a field." [INFERRED: this is the historical point where the slop-bytes discipline (SECURITY_HISTORY §2.3) replaced per-field bounds checks — the connection is an inference from the two commits' contents.]
- `d46a6ff07` — "Enable FastTable for non-opt builds." / `857623168` rollback — fasttable default-flip churn; performance-relevant, correctness-relevant (only 64-bit, §PERFORMANCE_MODEL).
- Related historical fixes: `beb01ec89` (2026-07-24) — "Fix upb wire decoder accepting field number 0" (missing `(tag >> 3) == 0` check in `_upb_WireReader_SkipValueForceInline`, now `reader.h:131`); `668f9d6a7` (2026-07-30) — "Catch groups with large tags during unknown dispatch" (now `decode_fast/field_unknown.c:69-82`); `9dc766d05` — "Make ExtensionRegistry reject field numbers that are out of range."

### 1.6 Descriptor / minitable / "schema" bombs
- `6e1cbdfe0` — "Added fuzzer for descriptor parsing/serialization, and fixed several bugs." (The modern `upb/util/def_to_proto_fuzz_test.cc` is its descendant.)
- `83078b027` — "Added field number validation to MiniDescriptor parsing."
- `0a2b39bfd` — "Fixed a fuzz bug by properly rejecting MiniTables with improper map fields at schema creation time."
- `62e07e367` / `eebcd59a9` — negative `oneof_index` fuzz bugs.
- `6795ec13b` — "Fixed fuzz bug in MiniDescriptor parsing for extensions."
- `9bb1787f2` — "Added fuzzing of symtab build, and fixed a handful of minor bugs."
- `9c66da89e` — "fix: [upb] roll back extensions after failed file addition (#28900)." Partial-state cleanup on failed file add.
- Threat-model context: SECURITY.md L228-254 puts *DynamicMessage on untrusted descriptors* outside the CVE model but documents inherent O(N·M) memory amplification; SECURITY.md L386-401 states minitables/minidescriptors are **trusted types** — misused-API behavior is not a security topic. The Rust port's minitable *builders* sit at this trust boundary.

### 1.7 Unknown-field size limits
- No total-size cap exists on unknown-field accumulation (they append into `aux_data` with power-of-2 growth, `upb/message/internal/message.c:56-103`); hardening is arithmetic-only (`6a3bcdaca`, `message.c:62,86,109,124`). Delimited *declared* sizes are capped at INT32_MAX (`reader.c:55`). Note SECURITY.md L125-146: binary parsing is the only proactively-hardened surface; in-memory serialization is *not* in the threat model.

### 1.8 Allocation-failure (OOM) handling — the pin HEAD itself
- `2de70d710` — **the pinned commit**: "Add allocation failure tests for unknowns and defbuilder."
- `c0a57498c` — "Allocation fault injection tests for upb encode and decode."
- `2a3652039` — "fix missed oom handling in unset required."
- `cfe0723d8` — "Handle alloc failure in field_message."
- `05ff89ea9` — "Don't ignore upb_Arena_Malloc-fail in 0-sized allocation."
- `89081325d` / `ad6a7e8b6` — ignored-return-value cleanups.
- Upstream posture: OOM is a *status* (`kUpb_DecodeStatus_OutOfMemory`), not UB; the Rust port must decide the same (see §4).

### 1.9 Miscellaneous / VRP
- `377a52d9e` (2026-06-25) — "Remove unused upb `_upb_NoLocaleStrtod` (Google Bug Hunters VRP) (#26377)." A VRP-triggered removal — evidence of active external adversarial review.
- `0e436a47e` (2026-08-02) — "Update conformance tests with updated relaxed duplicate key handling in ProtoJSON." ProtoJSON duplicate-key semantics changed/relaxed; relevant to JSON parity (OPEN_QUESTIONS §3.2).
- Cross-runtime context (C++/Python, not upb): `7c51e5b58` (2025-08-04) "Restore compatibility of runtime with pre-3.22.x gencode impacted by CVE-2022-3171" — CVE-2022-3171 was the C++ `ParseFromArray` overflow family; `3a48173d7` "Harden SIMD UTF-8 tail-copy bounds checks"; `0e28fcf09` "Harden Cord append size accounting in MessageLite serialization."

### 1.10 Documented limits (repo guidance)
- `third_party/protobuf/SECURITY.md` — threat tiers (L62-122), primary surface = binary wire decode (L125-146), ProtoJSON parsing also hardened (L147-155), text format has no default depth limit (L164-174), Lite DoS posture (L176-188), DynamicMessage O(N·M) (L228-254), depth-cap edge cases are "simple bugs" not security issues (L338-354), no canonical serialization (L356-375), upb is an implementation-detail API (L386-401).
- `upb/README.md` — upb feature list; notably "deep descriptor verification: not as exhaustive as protoc" (L43-44).
- `upb/wire/internal/constants.h:11` — `kUpb_WireFormat_DefaultDepthLimit 100`.

---

## 2. Current hardening mechanisms (pinned source, file:line)

### 2.1 Depth limit — binary decode
- Constant: `kUpb_WireFormat_DefaultDepthLimit 100`, `upb/wire/internal/constants.h:11`.
- Options packing: max depth in the top 16 bits, `upb_DecodeOptions_MaxDepth`, `upb/wire/decode.h:71-73`; 0 ⇒ default, `upb_DecodeOptions_GetEffectiveMaxDepth`, `upb/wire/decode.c:1306-1309`.
- Decoder state: `d->depth` initialized from options, `upb/wire/internal/decoder.h:102` and reset per message at `decoder.h:135-143`.
- The check: `_upb_Decoder_RecurseSubMessage` decrements before recursing and throws `kUpb_DecodeStatus_MaxDepthExceeded` when `< 0`, `upb/wire/decode.c:191-205`. Groups use the same helper (`decode.c:220-241`). The top-level message does not consume depth.
- Fasttable equivalent: `decode_fast/field_message.c:105-107` (`--d->depth < 0` — the `d1e231d4b` fix).
- Unknown-group skipping inside unknown data: `_upb_WireReader_SkipGroup` with a hard-coded `depth_limit` of 100, `upb/wire/reader.c:63-80`, `reader.h:121-126,181-184` — a separate, non-option depth budget.
- Promotion/re-parse paths reuse the effective max depth: `upb/message/promote.c:283-285,336-338,381-383`; skip-value depth 100 defaults at `promote.c:137,224`.

### 2.2 Length/size limits
- Delimited size varint: 5-byte bound with `INT32_MAX` rejection, `_upb_WireReader_ReadLongSize`, `upb/wire/reader.c:48-61`; interface `upb_WireReader_ReadSize`, `reader.h:75-76`.
- Tag varint: 5-byte bound with `UINT32_MAX` rejection, `_upb_WireReader_ReadLongTag`, `reader.c:33-46`.
- `upb_DecodeLengthPrefixed` re-checks `msg_len > INT32_MAX` ⇒ Malformed, `decode.c:1368-1370`.
- Encode side: delimited lengths > INT32_MAX ⇒ `kUpb_EncodeStatus_MaxSizeExceeded`, `upb/wire/internal/encoder.c:282-288`; status enum `encode.h:54-56` (introduced by `2293d51b4` "Return an error if asked to serialize a proto larger than 2gb").

### 2.3 EPS copy-stream slop discipline
- `kUpb_EpsCopyInputStream_SlopBytes 16` with the invariant rationale (one bounds check per field; 5-byte tag + 10-byte varint = 15 ⇒ 16 for aligned copies), `upb/wire/internal/eps_copy_input_stream.h:25-33`.
- Init splits input: `size <= SlopBytes` ⇒ copy into a 32-byte zeroed `patch` buffer (`eps_copy_input_stream.h:64-84`); otherwise the tail SlopBytes are readable past `end`.
- The read-ahead budget is *enforced in debug builds*: `guaranteed_bytes` accounting, `ConsumeBytes`, `BoundsHit/BoundsChecked`, `eps_copy_input_stream.h:121-152`.
- `ReadStringAlwaysAlias` refuses strings that would extend into slop bytes *when parsing from the patch buffer* (`eps_copy_input_stream.h:249-269`) — this is the "no fake bytes escape" rule; `upb_EpsCopyCapture_End` bounds-checks captures (`eps_copy_input_stream.h:237-247`).
- Submessage limits: `PushLimit`/`PopLimit` (`eps_copy_input_stream.h:292-317`), fast delimited path `TryParseDelimitedFast` (`eps_copy_input_stream.h:322-342`).

### 2.4 Arena OOM behavior
- Bump path returns the next aligned span; on insufficient space, `_upb_Arena_SlowMalloc` allocates a new block and **returns NULL on allocation failure** (`upb/mem/arena.c:480-509`); `upb_Arena_Malloc` propagates NULL (`upb/mem/internal/arena.h:94-99`).
- Callers must convert NULL ⇒ status: decoder throws `kUpb_DecodeStatus_OutOfMemory` (e.g. `decode.c:169,186-188,292-295,1234-1236`); encoder longjmps with `kUpb_EncodeStatus_OutOfMemory` (`encoder.c:79-92, 85-91`). The setjmp/longjmp error channel is `UPB_SETJMP/UPB_LONGJMP` (`def.inc:415+`, `decode.c:1293`).
- Allocation counting `upb_AllocationCount_IncrementAndCheck` gates both `Malloc` and block alloc (`arena.h:95`, `arena.c:512,482`).

### 2.5 Fasttable path and bounds discipline
- Selection/build: `upb_DecodeFast_BuildTable`, `decode_fast/select.c:227-295`; per-field eligibility `TryFillEntry` (`select.c:208-225`): tag must be 1-2 bytes (`GetEncodedTag`, `select.c:58-74`, field number < 2048), no maps (`select.c:80-81`), no groups (`select.c:106-107`), presence/hasbit index < 32 (`select.c:153-167`), all offsets ≤ 16 bits (`decode_fast/data.h:32-44`), no extension fields (`select.c:212`), not a map-entry message (`select.c:229`).
- Function indexing: `type << 3 | cardinality << 1 | tag_size` (`select.c:149`); 120 combinations enumerated in `decode_fast/combinations.h:19-25,161-222` (14 impossible); `function_array.c:20-41` maps index → pointer, with generic fallback `_upb_FastDecoder_DecodeGeneric`.
- Dispatch: tag masked into a 32-slot table, tail-call to the specialized parser, `decode_fast/dispatch.h:39-86`; the table lives in the minitable (`fasttable[ofs >> 3]`).
- Bounds: specialized parsers consume from the EPS slop budget (e.g. `field_varint.c:71` → `ReadVarint`, which pre-accounts 10 bytes); packed varints pre-count elements with a pessimistic per-byte scan and reject a trailing continuation byte (`field_varint.c:109-133`); array growth goes through `_upb_Array_Realloc` with `upb_ShlOverflow` guards and `SIZE_MAX` rejection (`upb/message/array.c:163-192`).
- Unknown/extension handling in the fast path validates field numbers and wire types before capture (`field_unknown.c:62-110,112-218`; field number 0 rejected at `field_unknown.c:90-91,172-173`).
- Gating: `UPB_FASTTABLE` requires x86-64/ARM64-le + `preserve_none` + `musttail` (`upb/port/def.inc:500-507`); `UPB_ENABLE_FASTTABLE` forces, `UPB_TRY_ENABLE_FASTTABLE` opportunistically enables, else 0 (`def.inc:509-528`); Bazel flag `//upb:fasttable_enabled` default False plus 64-bit constraint (`upb/BUILD:48-68`). Runtime opt-out: `kUpb_DecodeOption_DisableFastTable` (`decode.h:64-67`) and `table_mask == -1` (`decode.c:1153-1158`).

### 2.6 Overflow helpers
- `upb/port/overflow.h`: `upb_AddOverflow_*` / `upb_MulOverflow_*` for size_t×size_t, size_t×uint32_t, uint32_t×size_t (L25-85), compiled down to `__builtin_add_overflow`/`__builtin_mul_overflow` where available with manual fallbacks; C11 `_Generic` dispatch macro (L87-115). Introduced by `c6b856d78` (2026-08-17) — recent, coverage incomplete.
- Shift overflow: `upb_ShlOverflow`, `upb/base/internal/log2.h:50-56`; `upb_RoundUpToPowerOfTwo` saturates at `SIZE_MAX` (`log2.h:41-48`).

### 2.7 JSON decode depth
- `jsondec.depth` starts at hard-coded **64** (`upb/json/decode.c:1602`) — not the wire default 100; `jsondec_push` decrements and errors "Recursion limit exceeded" (`decode.c:226-231`). Only one entry point: `upb_JsonDecodeDetectingNonconformance` (`decode.c:1585-1610`), `upb_JsonDecode` wrapper (`decode.h:37-46`).

---

## 3. Security regression corpus plan (lives under `security/`)

Corpus entries are raw byte payloads + a declared schema (minitable) + expected oracle statuses. Oracle ops: `decode`, `decode_length_prefixed`, `encode_roundtrip`, `json_decode`, `promote` (see tools/oracle protocol). "Boundary" entries assert **accepted/rejected** and, where deterministic, **exact output bytes**.

| Class | Required input shapes | Oracle operation |
|---|---|---|
| 1.1 varint edges | 10-byte varints: `0xFF×9+{0x00..0x02}`, `0xFF×10`; 5-byte sizes with 6th continuation; 64-bit sign-extension patterns on 32-bit fields; all-byte positions `0x80`-heavy | `read_varint`, `decode` (field + unknown), `encode_roundtrip` |
| 1.2 depth | nested delimited messages at depth 99/100/101; groups at same depths; depth mixed with unknown-field groups (SkipGroup budget); map/message-set recursion | `decode` (default & `MaxDepth` options), `encode` |
| 1.4 overflow | declared sizes `0x7FFFFFFF`, `0x80000000`; `SIZE_MAX`-ish packed lengths; packed bool arrays with declared size forcing capacity doubling past 2^31 on 32-bit target | `decode` (OOM/Malformed status) |
| 1.5 untrusted length | delimited length larger than buffer; length exactly at limit; `PushLimit` crossing; patch-buffer strings reaching into slop (small total buffers) | `decode` with `AliasString` on/off |
| 1.6 descriptor bombs | descriptor chains with deep dependency graphs, negative oneof indices, >2^16 fields, presence index ≥ 32, map-entry minitables with >2 fields, field numbers ≥ 2^29 (and ≥ INT32_MAX for MessageSet) | minitable build, `mini_descriptor` decode, symtab build |
| 1.7 unknowns | large unknown runs; many tiny unknowns (coalescing paths); unknown groups nested past 100; unknown field number 0 (now rejected) | `decode`, `merge`, `encode_roundtrip` |
| 1.8 OOM | same as 1.4 under alloc-fault injection (fault at each N-th alloc) | `decode`/`encode` with injected faults |
| 2.7 JSON | nesting at depth 63/64/65; duplicate keys; huge numbers near float overflow; base64 edge indices; unknown fields in JSON | `json_decode` |

## 4. Must-reproduce vs. must-NOT-reproduce

**Must reproduce (accepted/rejected input contract — the parity surface):**
- Size/tag rejection boundaries: 5-byte sizes with `> INT32_MAX` ⇒ Malformed; 5-byte tags with `> UINT32_MAX` ⇒ Malformed; field number 0 ⇒ Malformed (`reader.c:33-61`, `reader.h:131`, `field_unknown.c:90`).
- 10-byte varint value semantics including the `(byte-1)<<63` wrap behavior (`reader.c:24`) — **pin exact values by oracle first** (OPEN_QUESTIONS §3.1).
- Depth accounting: effective depth 100 default, options override, top-level does not consume depth, fasttable off-by-one parity, encode-side depth, JSON 64.
- Unknown-field round-trip byte order (encode iterates `aux_data` in reverse, `encoder.c:778-798`) and merge ordering.
- UTF-8 validation triggers (`decoder.h:231-242`), `AlwaysValidateUtf8` disables fasttable (`decoder.h:96-99`).
- Error-status taxonomy: Ok / Malformed / OutOfMemory / MaxDepthExceeded / BadUtf8 / MissingRequired / MaxSizeExceeded, including *error precedence* when several apply (needs oracle experiments).
- OOM ⇒ clean status, never abort (Rust: `Result`/`try_reserve` equivalents).

**Must NOT reproduce unsafely (charter §1/§6: eliminate unsafe consequences, document divergence, keep the oracle witness):**
- Any C memory-unsafety under hostile input, e.g. the pre-`452153d35` arena `SIZE_MAX` wrap (the bug's *behavior* — returning a bogus pointer — must NOT be reproduced; the *fix's* contract — allocation fails cleanly — must be).
- `setjmp`/`longjmp` control flow — becomes `Result` in Rust; the observable contract is the resulting status, not the mechanism.
- UB on minitable misuse (`SECURITY.md:398-401`): upstream declares minitables trusted; a safe-Rust port should still refuse to construct invalid minitables rather than invoke UB, and document the trust boundary divergence.
- `NULL - NULL` arithmetic class (`ab7ec2887`), sign-extended base64 index class (`58edfa50c`), SIMD tail-copy class (`3a48173d7`) — all become ordinary bounds-checked code.

**Known open/unpatched items in the pin:**
- The upb conformance *performance* test is disabled upstream: "The upb performance test has segvs with recursion limit test … with --config=asan" (`upb/conformance/BUILD:177-183`); `conformance_upb_failures_performance.txt` is empty (0 bytes). **A recursion-limit + ASan segv is an unpatched upstream observation** — upb-rs must not inherit the underlying assumption; investigate when the conformance court lands.
- Overflow-helper adoption is recent (`c6b856d78`) and not exhaustive [INFERRED]; audit raw `+`/`*` in size math during the Rust port rather than assuming upstream is complete.
- VRP-driven removals (`377a52d9e`) indicate externally discovered issues; treat upb as under active adversarial review and re-pin frequently (OPEN_QUESTIONS §4).
