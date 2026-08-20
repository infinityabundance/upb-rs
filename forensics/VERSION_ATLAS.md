# VERSION_ATLAS.md — upb history, behavior-relevant commits, feature matrix

Built from the pinned repo's git history (`third_party/protobuf`, partial
clone: `git log` works offline; `git show <sha>:<path>` fetches blobs over the
network). All SHAs below were verified with `git log`/`git ls-tree` on
2026-08-19 against pin `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`. Companion:
SOURCE_BASELINE.md (authority hierarchy), SECURITY_HISTORY.md (hardening
details — this doc only flags security-significant commits, it does not
re-describe them).

**Repository topology (verified — corrects the "squashed history" assumption
in the archaeology brief):** the upb history is *fully present*, not squashed.
The protobuf repo has five roots (`git rev-list --all --max-parents=0`):
`40ee55171` 2008-07-10 (protobuf "Initial checkin."), `f92c545f4` 2008-08-14
(C#), `35be73bfe` 2008-10-21, `d29a54fc9` 2009-02-01 (**the upb root**,
"Initial commit." — pbstream-era files), `c2da35d61` 2023-01-19 (utf8_range
subtree). The standalone upb history (2009→2023, **3023 commits** per
`git rev-list --count 100e9d3ab --not 0ef08bdd0`) was merged into the
monorepo on 2023-08-25 via PR #13686 (merge commit `81242c57c`). The
brief's suggested check `git log --all --oneline | tail` shows protobuf's own
2008 roots, not an upb trace; the earliest commit touching the *current*
`upb/` path is `10265aa56` (2011-07-15 "Directory restructure."), and
`501ececd3` (2023-09-26 "Reorganize upb file structure") is the post-merge
layout reorganization, **not** the earliest trace. 2,407 commits touch `upb/`
in the path-limited view (2011→2026, year counts: 47/2011 … 405/2023, 282/2024,
284/2025, 218/2026).

---

## 1. Timeline of major architectural transitions

| Date | SHA | Event |
|---|---|---|
| 2009-02-01 | `d29a54fc9` | upb standalone repo root ("Initial commit."; `pbstream.c`). Standalone era = protocolbuffers/upb (originally jhaberman/upb). |
| 2011-07-15 | `10265aa56` | "Directory restructure." — files moved under `upb/`; earliest commit matched by `git log -- upb/`. |
| 2011–2013 | — | Early C89-era core: tables (`e2840a4aa` 2015-05-17 "Restructure tables for C89 port"), defs (`e9d79d244` 2016-03-16 `upb::FileDef`), amalgamation tool (`b3f6daf83` 2014-12-11). |
| 2015-06-12 | `b72ed3b97` | "Fix for stack overflow for cyclic defs." — first recursion-hardening trace (see §5). |
| 2017-07-08 | `1aafd4111` | "A good start on upb_encode and upb_decode." — the binary encode/decode API lineage of today's `upb/wire/encode.c`, `decode.c`. |
| 2019-05-15 | `a8f719c98` | "Added checks for OOM conditions." — arena-failure handling begins (SECURITY_HISTORY §2.4). |
| 2020-02-04 | `ce1a399a1` | "Text format serializer for upb_msg (#242)" — text format **encode** exists; parsing is still absent at pin (upb/README.md:42). |
| 2020-02-23 | `d49c1db6c` | "New JSON decoder, string->msg using reflection." — `upb/json/decode.c` lineage. |
| 2020-10-18 | `a345af988` | Fasttable era opens: "Added a codegen parameter for whether fasttables are generated or not." |
| 2020-10-28 | `e8f9eac68` | "Added #defines UPB_ENABLE_FASTTABLE and UPB_TRY_ENABLE_FASTTABLE." |
| 2020-12-18 | `3c9ae7837` | "The fasttable parser works on ARM64!" |
| 2021-01-10 | `f5d2d5500` | "Deleted the legacy 'Handlers' APIs. upb can finally be deserving of its name." (merged `ed5b4108e` 2021-02-22, PR #363) — pre-minitable decoder paradigm removed. |
| 2022-02-20 | `2dad1f94a` | "MiniTable builder is successfully working on all files!" — minitable-api branch. |
| 2022-03-14 | `b79b8b3f4` | **Mini tables replace descriptors in the runtime**: "Merge pull request #550 from haberman/minitable-api" (upb standalone main). The `upb_MiniTable`-driven decoder/accessor era. |
| 2022-12-10 | `68d1d9147` | "Separated out buffering code into upb_EpsCopyInputStream." — EPS copy-stream born (slop=16, OPEN_QUESTIONS §3.8). |
| 2023-01-19 | `163e31a41` | utf8_range vendored into the protobuf repo as a subtree (needed by the upcoming upb merge). |
| 2023-03-06 | `3dc546daf` | "Implement a minimal, internal, experimental rust_proto_library rule." — Rust protobuf support begins (in protobuf repo, pre-merge). |
| 2023-03-16/17 | `ab9f1ab58` / `aaa338b28` | "Configure the build for the Rust UPB backend" / "…for the C++ backend" — **kernel-selection mechanism** (upb vs cpp) introduced in `rust/defs.bzl`. |
| 2023-08-25 | `81242c57c` | **Merger into the protobuf monorepo**: "Merge pull request #13686 from protocolbuffers/merge-upb" (upb side tip `100e9d3ab`; file content landed via `6fc87fe3f`). |
| 2023-09-07 | `bad2f5c90` | "Migrate upb from edition strings to enums." |
| 2023-09-26 | `501ececd3` | "Reorganize upb file structure" (Adam Cozzette) — everything in `upb/` moved up one level; the current layout (upb/{base,hash,json,lex,mem,message,mini_descriptor,mini_table,port,reflection,text,util,wire}). |
| 2023-10-09 | `55fb27df2` | "Enable editions support for rust." |
| 2023-10-11 | `3813b6622` | "Implement proto2/proto3 with editions" — editions 2023 feature resolution; ships in v25.0 (2023-11-01). |
| 2025-05-01 | `7cd3d4e60` | "Moved and split fasttable decoder into the `decode_fast` directory." — `upb/wire/decode_fast/` becomes a directory; fasttable fuzzing enabled 2025-05-25 (`80645c794` "Disabled all fast parsing functions and enabled fuzzing of fasttable"). |
| 2026-03-20 | `2b3058dcf` | "Refactor: Split upb and cpp backends into submodules" — `rust/upb_kernel/` + `rust/cpp_kernel/` split from single-file `rust/upb.rs`/`rust/cpp.rs`. |
| 2026-05-07 | `a7864c77b` | **Backwards one-pass encoder**: "Backwards allocation for encode." — adds `upb/wire/internal/back_alloc.{c,h}`, rewrites `encode.c`/`arena.c` (buffer allocated from the end; no two-pass size-then-encode for the main path). |
| 2026-08-17 | `c6b856d78` | "Introduce overflow checking functions for add and multiply in upb…" — `upb/port/overflow.h` introduced. |
| 2026-08-19 | `2de70d710` | **Pin HEAD**: "Add allocation failure tests for unknowns and defbuilder". |

Era note: history 2009→2023-08-25 is the standalone upb repo spliced in as a
merged root; dates/subsjects above in that range come from the upb side.

---

## 2. Recent behavior-relevant commits (`git log -30 -- upb/`)

| SHA | Date | Subject | Relevance |
|---|---|---|---|
| `2de70d710` | 2026-08-19 | Add allocation failure tests for unknowns and defbuilder | Evidence-relevant (pin HEAD) |
| `d21931d39` | 2026-08-19 | Remove C23 requirement from FastTable | Toolchain/build (C23 removal widens compilers) |
| `2256d8f02` | 2026-08-18 | Support converting non-canonical extensions in upb message conversion | **Behavior**: conversion path |
| `6165c5279` | 2026-08-18 | Validate tag match before treating unlinked submessages as unknown fields | **Behavior/security**: unknown-dispatch guard |
| `d068b54ba` | 2026-08-18 | Internal | Opaque (OPEN_QUESTIONS §5.6) |
| `6e4f4ca54` | 2026-08-18 | Fix UPB_FASTTABLE declaration… recursive C macro expansion | Build/fasttable correctness |
| `86c32b72d` | 2026-08-18 | Fix fasttable support in Kotlin UPB | Integration |
| `857623168` | 2026-08-17 | Automated rollback of commit d46a6ff07… | Rollback (see next row) |
| `c6b856d78` | 2026-08-17 | Introduce overflow checking functions… | **Hardening** (overflow.h; §1 timeline) |
| `d46a6ff07` | 2026-08-17 | Enable FastTable for non-opt builds | Fasttable build-default change — **rolled back** same day by `857623168` |
| `085b305c2` | 2026-08-12 | check sub array bounds before indexing in upb_MiniTable_Link (#28553) | **Hardening**: OOB guard |
| `9c66da89e` | 2026-08-12 | fix: [upb] roll back extensions after failed file addition (#28900) | **Behavior**: transactional def-pool |
| `22677ce80` | 2026-08-12 | upb/message/compare: Add support for partial equality comparisons | **Behavior**: `IsEqual` partial option |
| `05ff89ea9` | 2026-08-12 | Don't ignore upb_Arena_Malloc-fail in 0-sized allocation | **Hardening**: OOM on 0-size path |
| `0fff4dec5` | 2026-08-11 | protobuf: improve staleness test regeneration | Tooling |
| `86dfa627b` | 2026-08-10 | Migrate upb tests to upb_Message_NextUnknown2 | API migration (unknowns iteration) |
| `89081325d` | 2026-08-10 | Handle more ignored return values in upb | **Hardening** (OOM/status swallowing) |
| `3ad6d39df` | 2026-08-07 | Internal change | Opaque |
| `c0a57498c` | 2026-08-06 | Allocation fault injection tests for upb encode and decode | Evidence-relevant (OOM contract courts) |
| `bff6c119b` | 2026-08-06 | Public `upb_MessageUnknown_Encode` API | **Behavior**: serializes extensions→bytes |
| `817d6b1fa` | 2026-08-05 | Internal | Opaque |
| `1a486b330` | 2026-08-04 | Fix extension existence check in GetOrCreateExtensionWithTag | **Behavior/hardening** |
| `42c88bf5c` | 2026-08-04 | DefPool Find methods take absl::string_view | Refactor/API |
| `0e436a47e` | 2026-08-02 | Conformance: relaxed duplicate key handling in ProtoJSON | **Behavior**: JSON dup-key policy (OPEN_QUESTIONS §3.2) |
| `77f5b6bd0` | 2026-07-31 | Expose `upb_Extension` struct as public API in unknown_fields.h | API surface |
| `668f9d6a7` | 2026-07-30 | Catch groups with large tags during unknown dispatch | **Hardening** (MessageSet/group tag bounds) |
| `8baed752c` | 2026-07-30 | Auto-generate files after cl/956632937 | Generated-code churn |
| `8111a7473` | 2026-07-30 | json/upb: Implement json EnumValueName for upb | **Behavior**: JSON enum name output |
| `2a3652039` | 2026-07-30 | fix missed oom handling in unset required | **Hardening**: OOM in required-check |
| `cfe0723d8` | 2026-07-29 | Handle alloc failure in field_message | **Hardening**: OOM in submessage decode |

Roughly 2/3 of the last 30 are behavior- or hardening-relevant; "Internal
change" / "Auto-generate files" subjects (5 of 30) are opaque (OPEN_QUESTIONS
§5.6).

---

## 3. Version feature matrix

Verified columns via `git ls-tree <tag>` (presence of `upb/json`,
`upb/wire/decode_fast*`, `rust/upb_kernel`|`rust/upb.rs`, `upb/text`); upb was
**not in the protobuf repo before v25** (`git ls-tree v21.12 upb` → empty), so
pre-v25 rows describe the standalone upb via dated commits (§1). Tag dates:
v21.12 2022-12-12, v22.4 2023-05-03, v25.0 2023-11-01, v26.0 2024-03-12,
v27.0 2024-05-22, v29.0 2024-11-27, v30.0 2025-03-04, v33.0 2025-10-15,
v34.0 2026-02-25.

| Era / tag | Editions | Fasttable | Rust kernel | JSON | Text format | One-pass encoder |
|---|---|---|---|---|---|---|
| v21.x (`v21.12`) | No (editions pre-date v25) | Yes — `decode_fast.c` since 2020-10 (`a345af988`…) [INFERRED in-tree at tag; standalone history] | No (Rust kernel is 2023-03+, protobuf repo) | Yes (`d49c1db6c` 2020-02-23) [INFERRED] | Serializer only (`ce1a399a1` 2020-02-04) [INFERRED] | No (2026 feature) |
| v22–v24 (`v22.4`) | No | Yes [INFERRED] | No | Yes [INFERRED] | Serializer only [INFERRED] | No |
| v25 (`v25.0`) | Yes — editions 2023 experimental (`3813b6622`, `55fb27df2`; GA `[INFERRED]` v26) | Yes — `upb/wire/decode_fast.c` (2 files, verified) | Yes — `rust/upb_kernel/` (verified) | Yes (verified) | Serializer (verified; no parser ever) | No |
| v26 (`v26.0`) | Yes [INFERRED GA] | Yes — `decode_fast.c` (verified) | Yes — `rust/upb_kernel/` (verified) | Yes (verified) | Serializer (verified) | No |
| v27–v29 (`v27.0`, `v29.0`) | Yes | Yes — `decode_fast.c` (verified) | Yes — renamed to `rust/upb.rs` + `rust/upb/` (verified at v27) | Yes (verified) | Serializer (verified) | No |
| v30–v33 (`v30.0`, `v33.0`) | Yes | v30: `decode_fast.c`; v33: `decode_fast/` dir split (`7cd3d4e60` 2025-05-01) (verified) | Yes — `rust/upb.rs` layout [INFERRED] | Yes (verified) | Serializer (verified) | No |
| v34 (`v34.0`) | Yes | Yes — `decode_fast/` dir (verified) | Yes — pre-split layout `rust/upb.rs`+`rust/upb/` (verified) | Yes (verified) | Serializer (verified) | No |
| v36-dev (`2de70d710`, pin) | Yes | Yes — `decode_fast/` dir; flag default **off** (`upb/BUILD:48-53`) | Yes — `rust/upb_kernel/` + `rust/upb/` FFI split (`2b3058dcf` 2026-03-20) | Yes | Serializer (README.md:42 no parser) | **Yes** — `back_alloc.c` (`a7864c77b` 2026-05-07) |

Fasttable *code* presence ≠ enabled: `fasttable_enabled` Bazel flag defaults
False and requires 64-bit (upb/BUILD:48-53, 61-84). There is no final `v36.0`
tag: 463 tags present, newest are `v36.0-rc2`/`v36.0-rc1`/`v36-dev` (verified
`git tag | sort -V | tail`); the pin `2de70d710` describes to v36-dev-400.

---

## 4. Rust kernel history

- **2023-03-06** `3dc546daf` "Implement a minimal, internal, experimental
  rust_proto_library rule." — first Rust proto support in the protobuf repo
  (pre-upb-merge; `rust/` lived in the monorepo from the start).
- **2023-03-07** `26af540a7` "Add support for proto dependencies to
  rust_proto_library".
- **2023-03-16** `ab9f1ab58` "Configure the build for the Rust UPB backend";
  **2023-03-17** `aaa338b28` "Configure build for the C++ backend" — the
  **upb-vs-cpp kernel abstraction** is born in `rust/defs.bzl` (both rules
  declared; selection via build setting). `git log --follow -- rust/defs.bzl`
  bottoms out at `3dc546daf`.
- **2023-06-06** `ff750bb4c` "Put shared.rs and cpp.rs/upb.rs into the same
  crate." — kernel files `rust/upb.rs`/`rust/cpp.rs`.
- **2023-08-25** upb merge (`81242c57c`) brings `rust/upb_kernel/` into the
  monorepo (present at v25.0, verified).
- **v27.0** (2024-05-22) layout: `rust/upb_kernel/` renamed/replaced by
  `rust/upb.rs` + `rust/upb/` (verified by ls-tree; exact rename SHA
  [UNVERIFIED]).
- **2026-03-20** `2b3058dcf` "Refactor: Split upb and cpp backends into
  submodules" — `rust/upb_kernel/` (9 .rs) and `rust/cpp_kernel/` (9 .rs) as
  today, with the FFI crate at `rust/upb/` (`upb_api.c`).

**Selection today** (verified in-tree):
- `rust/BUILD:369-377` — `string_flag rust_proto_library_kernel`, default
  `"cpp"`, values `upb`/`cpp`; `use_upb_kernel` config_setting at :379-385.
- `rust/defs.bzl:16-43` — `rust_proto_library()` macro: declares **both**
  `_upb_rust_proto` and `_cpp_rust_proto` targets (:45-56) and an `alias`
  (:36-43) selecting `:use_upb_kernel` → upb, else cpp. Both kernels compile
  in one build so one TAP config tests both (rust/BUILD:23-29).
- `rust/BUILD:32-42` — `:protobuf` rust_library compiles `protobuf.rs` with
  `--cfg=upb_kernel` or `--cfg=cpp_kernel`; `:protobuf_upb` (:116-144) deps
  `//rust/upb` + `@crate_index//:linkme`; `:protobuf_cpp` (:187-213) deps
  `:cpp_api` (the C++ bridge, :251-285). Kernel-agnostic files compile twice
  (`PROTOBUF_SHARED`, :66-82).
- Protoc toolchains: `proto_rust_upb_toolchain` / `proto_rust_cpp_toolchain`
  (rust/BUILD:342-362) → `protoc-gen-rust` runtime selection.

---

## 5. Security-significant commits

Grep terms: CVE, security, OOM, overflow, malformed, fuzz, DoS, recursion,
stack, hang, out of bounds (path-limited to `upb/`, case-insensitive). The
full 2011→2026 span yields ~60 hits; selection below (dedup'd with
SECURITY_HISTORY.md §2/§3 which owns the mechanistic detail):

**2026 (hardening wave, all verified above in §2)**: `2a3652039` (oom in
unset required), `cfe0723d8` (alloc fail in field_message), `05ff89ea9`
(0-sized malloc-fail), `89081325d` (ignored returns), `668f9d6a7` (large
group tags), `6165c5279` (tag-match before unknown promotion), `085b305c2`
(mini_table link bounds #28553), `c6b856d78` (overflow.h),
`65fccf3b0` (2026-07-13, presence index int16 overflow #28231),
`c4e07ae40` (2026-07-01, size_t overflow in json decode),
`ac5284a05` (2026-06-25, ptrdiff_t fast delimited parser),
`452153d35` (2026-06-04, `upb_Arena_Malloc` near-SIZE_MAX #27568 — 32-bit
relevant, OPEN_QUESTIONS §5.5),
`cfa9acc18` (2026-06-10, dependency-index bounds in file_def #26562),
`58edfa50c` (2026-05-13, sign-extended index in jsondec_base64 #27215),
`d1e231d4b` (2026-05-19, fasttable recursion depth),
`27d822c82` (2026-05-19, fasttable oneof submessage merge corruption),
`ea8072564` (2026-05-13, fasttable minitable/extreg collision),
`78d8c10dc` (2026-05-05, uint16 field_count overflow in MtDecoder #27133),
`b22d59765` (2026-04-08, overflow in `upb_Array_Realloc`),
`08d520af1`/`e7785e050`/`560869f54` (2026-04-22, uintptr_t overflow in
AddAllLinkedExtensions).

**2024–2025**: `0a2b39bfd` (2025-09-13, reject minitables with improper map
fields — fuzz bug), `9dc766d05` (2025-05-07, ExtensionRegistry field-number
range), `83078b027` (2025-05-22, field-number validation in MiniDescriptor
parsing), `b32b101ba`/`5f1c06a28` (2025-08-27, fast-decoder/scalar bounds
asserts), `ab7ec2887` (2025-10-17, NULL-NULL UB in encode bounds check),
`d8a1f8cf7` (2025-11-19, bounds checking for delimited fields),
`5179ea2c6` (2025-05-05, pointer provenance for EpsCopy + aliased unknowns).

**2023 (post-merge)**: `ececc2162` (2022-07-19, closed-enum unknown in proto2
extension, #fuzzing), `143132fa2` (2023-01-03, generated code fasttable-
agnostic), `c628e53dd`-era accessor renames (2023-01).

**Standalone era**: `b72ed3b97` (2015-06-12, stack overflow cyclic defs),
`a8f719c98` (2019-05-15, OOM checks), `85440108e` (2015-08-11, decoder fixes +
parse-call semantics), `abcb6428a` (2015-07-30, skipping semantics),
`f32f2fdb2`/`715718d5a` (2019-10-30, endsubmsg → submessage closure — depth
accounting precursor).

Notably absent from subjects: no `CVE-*` identifiers appear in upb-path
subjects in this repo (Google's tracker work is usually "Internal change" —
OPEN_QUESTIONS §5.6 undercount caveat).

---

## 6. Unverified

- **Exact rename SHA** `rust/upb_kernel → rust/upb.rs + rust/upb/` between
  v26.0 and v27.0: presence verified at both tags, but the rename commit was
  not isolated (path-history is noisy post-merge; would need blob-fetch-heavy
  `--follow`).
- **Editions GA row**: editions 2023 became non-experimental in v26
  [INFERRED from `3813b6622` (2023-10-11) → v25.0 (2023-11-01) timing and the
  2024-01-29 `307aeac9c` ctype check]; not verified by release notes.
- **v21.x/v22–v24 fasttable/JSON/text rows** are [INFERRED] from standalone
  commit dates; the standalone upb repo had no tags in this tree to check
  directly.
- **Security grep coverage** is subject-only; "Internal change" subjects hide
  additional hardening (OPEN_QUESTIONS §5.6). The `4388` hits repo-wide vs
  ~60 path-limited to `upb/` — a rough ratio only, not a count of fixes.
- **`git describe` v36-dev-400** assumes the v36-dev branch point tag exists
  in this partial clone (it resolved cleanly); tag set is complete for
  v20.2→v35.x (463 tags).
- **One-pass encoder scope**: `a7864c77b` rewrote `encode.c` around
  `back_alloc`, but whether *every* encode path (maps, unknown fields,
  extensions, `upb_Encode` vs `upb_MessageUnknown_Encode`) is single-pass is
  not verified; byte-exact round-trip courts (OPEN_QUESTIONS §3.3, §1 Phase 4)
  will settle it.
