# OPEN_QUESTIONS.md — living work queue

This is a living document: the queue is consumed by tools/court-runner and
replenished by forensic work. Entries are concrete, citable, and
falsifiable. `[OPEN]` marks items awaiting oracle evidence.

**Important**: the charter document itself is **not present in this
repository** (referenced as `§1..§50` in README.md, Cargo.toml, PIN.md,
PARITY.toml, but no charter file exists anywhere in the tree — verified by
`find_path`/grep). Section 1's phase table is therefore marked `[INFERRED]`
and must be reconciled against the authoritative charter text when it is
located. See Risks §5.

---

## 1. Current phase

**Phase 0 (archaeology + court infrastructure)** is live, with the first
court — **wire primitives** — already producing evidence: `varint`, `tag`,
`size` are ORACLE-TESTED with 0 residuals (`PARITY.toml` `[wire.decode.*]`,
`STATUS.md`), meaning the oracle protocol (tools/oracle) and the
court-runner skeleton exist in some form. The forensic atlas set was
populated on 2026-08-19 (this deliverable plus the sibling atlases
SURFACE_ATLAS, MEMORY_MODEL, ERROR_MODEL, KERNEL_ATLAS, BEHAVIOR_ATLAS,
QUIRKS, NONDETERMINISM, written concurrently in the same minute window;
SOURCE_BASELINE.md is still absent, see Risks §5.3).

Phase sequence `[INFERRED — charter absent; reconstructed from STATUS.md
surface order, README layout, and the phase-0/phase-2 numbering already
used in the repo. Verify against the charter when located.]`:

| Phase | Deliverable |
|---|---|
| 0 | Archaeology + court infrastructure; first court (wire primitives) live. **current** |
| 1 | Wire decode scalars: fixed32/64 court; varint/tag/size hardening corpus folded into security/ |
| 2 | Message-level decode: generated minitables, message court, merge semantics |
| 3 | Mini tables / mini descriptors: builder parity, fasttable-selection model, schema-synthesis engine |
| 4 | Wire encode: byte-exact round-trip court (incl. deterministic maps, unknown order) |
| 5 | Arena / memory: Rust arena semantic model, allocation-failure contract, RSS accounting |
| 6 | Reflection / def pool: descriptor loading, symtab build, error taxonomy |
| 7 | JSON: decode/encode courts, duplicate keys, well-known types, depth 64 |
| 8 | Text format: parse/serialize (upb's text serializer exists; parser is NOT in upb — `upb/README.md:42`) |
| 9 | Conformance: upstream suite (binary + JSON), performance list unblocked after §5-risk item |
| 10 | Unknown fields / extensions / MessageSet: promotion courts, alias semantics |
| 11 | Kernel integration & C ABI: `abi/` manifests, integration patch series, forbidden-linkage CI |

## 2. Immediate work queue (next 20)

1. **Build the oracle protocol op `read_varint`** (tools/oracle) — status +
   value for arbitrary byte strings; needed by 2/3.
2. **Generate varint boundary corpus** (`corpus/`): 10-byte patterns
   `0xFF×9+{0x00,0x01,0x02}`, `0xFF×10`, continuation-bit combos, 32-bit vs
   64-bit encodings of same value.
3. **Differential court for fixed32/64** (STATUS: MAPPED → ORACLE-TESTED):
   endianness, buffer-boundary splits at every byte offset, slop-boundary
   placement.
4. **Message-level decode court with generated minitables**: nested
   delimited messages, groups, empty messages, unknown-heavy payloads —
   needs minitable construction in Rust (item 5 feeds it).
5. **Schema synthesis engine** (tools/schema-synth): emit
   mini-descriptor/minitable pairs + wire payloads from a seed;
   supports the depth/wide/map classes of PERFORMANCE_MODEL §5.
6. **Arena semantic model in Rust**: bump path, alignment, block growth
   (32768 default), one-off heuristic, allocation-failure → Result
   (SECURITY_HISTORY §2.4).
7. **Error-model mapping**: setjmp/longjmp → Result with status precedence
   rules; reconcile with the concurrently written `forensics/ERROR_MODEL.md`
   and extend it with the precedence court once it exists.
8. **EPS-copy-stream semantic model**: slop=16, patch buffer, PushLimit,
   debug accounting; property tests that reads never exceed guaranteed
   bytes.
9. **Unknown-fields court**: order across `MergeFrom`/`decode`/`promote`,
   coalescing, alias-vs-copy, round-trip byte order (SECURITY_HISTORY §4).
10. **Encode court**: byte-exact round-trip against oracle for all schema
    classes; reverse-iteration order; packed back-patch lengths.
11. **Depth-limit boundary court**: decode 99/100/101 nested; encode depth;
    unknown-group SkipGroup budget (100); JSON 64 — all as separate
    surfaces.
12. **JSON duplicate-key court**: last-wins vs merge vs error across field
    kinds; reconcile with `0e436a47e` conformance relaxation.
13. **Descriptor-bomb corpus**: deep dependency chains, huge field counts,
    negative oneof indices, presence ≥ 32 — for the minitable-builder court.
14. **Fasttable-selection model in Rust**: mirror `select.c` criteria
    (SECURITY_HISTORY §2.5) so schemas behave identically with/without a
    fast path; verify against `UPB_ENABLE_FASTTABLE`-built oracle.
15. **Arena growth accounting test**: `SpaceAllocated` and block sequence vs
    oracle for identical allocation traces.
16. **UTF-8 validation court**: proto3 string default-on, editions
    `utf8_validation=NONE`, `AlwaysValidateUtf8` (and its fasttable
    disable), bytes-field alternate-label interplay.
17. **MessageSet court**: item/type_id/payload handling, unknown items,
    large type_id tags (post-`668f9d6a7`), depth counting.
18. **Map court**: packed-vs-unpacked enum maps, unknown fields inside map
    entries spanning buffers (`df850c821` regression), deterministic sort.
19. **Oneof court**: case-offset semantics, last-field-wins, presence
    handling, unlinked-submessage oneofs.
20. **Security corpus runner**: `security/` + receipts; wire the §3 corpus
    table of SECURITY_HISTORY.md into court-runner with alloc-fault
    injection.

## 3. Open behavioral questions (need oracle evidence)

1. **[PARTIALLY RESOLVED] 10-byte varint value semantics at message level.**
   `reader.c:24` computes `val += (byte - 1) << (i * 7)` for i up to 9; for
   the 10th byte the shift is 63 and byte ≥ 2 wraps into bit 63 (e.g.
   `0xFF×9 + 0x02` ⇒ `0x8000_0000_0000_0000`), while `0xFF×10` errors.
   The *primitive* level is already ORACLE-TESTED (QUIRKS §1-2;
   PARITY.toml `wire.decode.varint`), so the residual question is the
   message-level application: which munging (int32 truncation, bool `!=0`,
   zigzag, enum open/closed) a wrapped 10-byte value hits on each field
   type (`decode.c:139-161`, `decode.c:764-789`), and how such values
   round-trip through encode. Why it matters: accepted-value parity for
   hostile inputs; SECURITY.md:304-307 says such sequences "may
   successfully parse". How: oracle `decode` into each scalar field kind +
   re-encode byte comparison.
2. **[OPEN] JSON duplicate-key handling.** Conformance was relaxed in
   `0e436a47e` (2026-08-02); does upb's `jsondec` apply last-value-wins,
   merge, or error per field kind (scalar/message/map)? Why: JSON is a
   hardened surface (SECURITY.md:147-155) and gateway differential parsing
   is an explicit risk (SECURITY.md:287-337). How: oracle `json_decode` on
   duplicate-key payloads; cross-check `upb/json/decode_test.cc` and the
   conformance JSON suite.
3. **[OPEN] Unknown-field ordering across merge.** Unknowns append to
   `aux_data` (`upb/message/internal/message.c:56-103`) and encode iterates
   in reverse (`encoder.c:778-798`); merging two messages interleaves
   unknowns and fields — the exact final byte order (and where new unknowns
   go relative to a previously parsed field region) is observable and not
   derivable from source alone. How: oracle `merge` + `encode` byte
   comparison on interleaved payloads.
4. **[OPEN] Fasttable selection completeness.** `select.c` criteria are
   readable, but the *observable* question is whether any schema/input
   combination produces different decode output (or different error status)
   with fasttable on vs off (e.g. the two-byte-encoded-one-byte-tag slot
   collision handled in `field_unknown.c:69-82`). Why: the Rust kernel has
   no fasttable but must not diverge. How: oracle built with
   `UPB_ENABLE_FASTTABLE` vs default on the §1.2 corpus; diff receipts.
5. **[OPEN] UTF-8 validation triggers.** `_upb_Decoder_FieldRequiresUtf8Validation`
   (`decoder.h:231-242`) keys off `descriptortype == String` plus
   alternate-label bytes under `AlwaysValidateUtf8`; editions
   `utf8_validation` plumbing and mini-descriptor encoding of the
   string/bytes "alternate" marker (`select.c:99-103` comments) need exact
   pinning. How: oracle decode with/without the option over crafted
   minitables + payloads.
6. **[OPEN] Error precedence.** When a payload contains multiple faults
   (truncated varint + invalid UTF-8 + missing required + depth exceeded),
   which status wins? Upstream order is an emergent property of
   `ErrorHandler` + longjmp points (`decode.c:1278-1300`). Why: courts
   compare status, not just accept/reject. How: exhaustive small-fault
   combinator corpus through oracle `decode` and `decode_length_prefixed`.
7. **[OPEN] Alias-string observable semantics.** With `AliasString`,
   decode of a buffer whose lifetime ends ⇒ dangling views in C; the Rust
   kernel must decide borrow semantics; the *behavioral* contract (which
   regions alias vs copy, incl. `AddUnknown` coalescing rules
   `_upb_Decoder_GetAddUnknownMode`, `decode.c:118-130`) needs oracle
   pinning via `upb_Message_NextUnknown2` + address equality, which the
   oracle protocol must expose.
8. **[OPEN] Packed-enum unknown ordering.** `_upb_Decoder_AddEnumValueToUnknown`
   (`decode.c:276-296`, `field_varint.c:40-60`) re-encodes tag+value;
   where do these synthesized unknowns land relative to pre-existing
   unknown regions? How: oracle decode of packed closed-enum with
   out-of-range values interleaved with unknowns; byte-compare re-encode.
9. **[OPEN] Deterministic map ordering tie-break.** `_upb_mapsorter`
   (`encoder.c:594-640,857`) sorts; the exact comparison key for
   equal-first-bytes string keys (secondary sort) is implementation detail
   — observable in output bytes. How: oracle `encode` with
   `kUpb_EncodeOption_Deterministic` over crafted collision keys; mirror
   upstream `mapsorter` tests.
10. **[OPEN] Required-field false-positive semantics.** `CheckRequired`
    documents false positives on wire-incomplete-then-completed messages
    and merge (decode.h:39-52). The exact acceptance boundary needs a
    court, not prose.
11. **[OPEN] Depth accounting for MessageSet items and groups.** Which
    constructs consume depth (group recursion `decode.c:220-241`,
    MessageSet item payload `decode.c:664-719`, unknown-group skip
    `reader.c:63-80` with its separate hard-coded 100) — pin with the
    depth-boundary corpus before implementing.
12. **[OPEN] `upb_ByteSize`/size-edge behaviors.** `upb_ByteSize`
    (`byte_size.c:24-33`) swallows encode status (ignores return); does it
    return 0 or garbage on >2GB messages? Observable via oracle
    `byte_size` op; affects `SizeOf`-style APIs in the Rust port.

## 4. Continuous upstream tracking procedure (charter §50)

Workflow (mirrors `third_party/protobuf/PIN.md:27-36`; §50 referenced,
charter text absent `[INFERRED]`):

1. **Record** old/new SHAs in `third_party/protobuf/PIN.md` (also update
   `PARITY.toml [meta] upstream` and `updated`).
2. **Fetch new upstream**: `git -C third_party/protobuf fetch origin`, hard
   move to the new SHA (partial clone fetches blobs on demand).
3. **Build the oracle** from the new pin
   (`tools/oracle/README.md` build recipe; cmake flags in PIN.md:42-45).
4. **Regenerate atlases**: re-run the archaeology greps
   (SECURITY_HISTORY §1), re-cite file:line in all forensics docs whose
   citations moved.
5. **Rerun all courts** against the new oracle; retain old-oracle receipts
   in `receipts/` for the transition window.
6. **Classify behavior changes**: new residuals → casefiles; changed
   accept/reject boundaries → parity claims updated; new hardening commits
   → SECURITY_HISTORY classes and security/ corpus additions.
7. **Create migration casefiles** (`casefiles/`) for every surface whose
   oracle witness changed; surfaces stay PARITY-SEALED only if unchanged or
   re-courted.

## 5. Risks and unknowns (honest list)

1. **The charter is absent from the repo.** README/Cargo/PARITY/PIN cite
   §§1-50, but no charter file exists. All phase summaries and section
   attributions (§8, §29, §50) in this and the sibling docs are
   reconstructions. *Mitigation*: locate the authoritative charter
   (external doc? sibling repo? zed context?) and reconcile before Phase 2
   courts depend on phase gates.
2. **Partial clone dependency**: `git show` of old blobs hits the network
   (observed during this archaeology); offline archaeology is only
   commit-message-deep. Pin drift or network loss stalls atlases.
3. **Atlas provenance race.** STATUS.md lists SOURCE_BASELINE.md,
   SURFACE_ATLAS.md, MEMORY_MODEL.md, ERROR_MODEL.md, KERNEL_ATLAS.md;
   the latter four (plus BEHAVIOR_ATLAS, QUIRKS, NONDETERMINISM) appeared
   in `forensics/` while this deliverable was being written (timestamps
   2026-08-19 23:01-23:05, interleaved with these three documents) — a
   concurrent author is populating the set. **SOURCE_BASELINE.md is still
   missing** despite being cited by README.md:61 and PIN.md:5. Before any
   court cites an atlas, verify it exists, is pinned to the same SHA, and
   does not duplicate/contradict SECURITY_HISTORY.md §2 (hardening) or
   PERFORMANCE_MODEL.md §1-3 (decode/encode/arena) — dedupe ownership:
   hardening details live in SECURITY_HISTORY, perf architecture in
   PERFORMANCE_MODEL.
4. **Unpatched upstream observations**: upb conformance *performance* test
   disabled due to segv under ASan with the recursion-limit test
   (`upb/conformance/BUILD:177-183`; empty failures list). The Rust kernel
   must not inherit whatever assumption that violates; investigate before
   conformance Phase 9.
5. **32-bit behavior gap**: fasttable is 64-bit-only
   (`def.inc:500-507`); several overflow fixes are only reachable on
   32-bit/WASM32 (`452153d35`). The Rust port needs an explicit
   32-bit test matrix or the divergence must be documented.
6. **Opaque commits**: many security-relevant changes are hidden behind
   "Internal change" / "Auto-generate files after cl/…" subjects; grep-based
   archaeology undercounts. The corpus plan compensates by being
   behavior-driven, but the history section will need periodic re-audit on
   each re-pin.
7. **Error-status precedence is unverified** (§3.6) and courts currently
   compare statuses — until the precedence court exists, residual-free
   status claims are provisional.
8. **Fasttable on/off divergence** (§3.4) means the oracle binary must be
   built in both modes for the message courts; single-build oracle evidence
   is incomplete for the fast path.
9. **Benchmark courts do not exist** — PERFORMANCE_MODEL §5 is a plan with
   no numbers by design; parity claims must not be inferred from the C
   benchmarks' existence.
10. **Frozen-message assertions**: `upb_Decode` asserts non-frozen
    (`decode.c:1315`); Rust's ownership model makes the frozen state
    (upb_Message_Freeze) a real API surface (message/array freeze paths
    exist, `array.c:194+`) that is currently UNMAPPED in the Rust port.
11. **Liveness**: this document is a work queue, not a record. Entries
    must be moved to casefiles/receipts as they resolve, or it rots into
    generic prose.
