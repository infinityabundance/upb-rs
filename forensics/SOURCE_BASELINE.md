# SOURCE_BASELINE.md — the pinned oracle, source authority, and build graph

Status: verified against the pinned tree at
`2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` on 2026-08-19. Companion docs:
SURFACE_ATLAS.md (surface inventory), KERNEL_ATLAS.md (Rust kernel
contract), VERSION_ATLAS.md (history). This file owns *which source is
authoritative and how it is built*; behavioral claims live in the sibling
atlases (OPEN_QUESTIONS.md §5.3).

---

## 1. Pinned oracle

| Field | Value | Evidence |
|---|---|---|
| Repository | `https://github.com/protocolbuffers/protobuf.git` | `third_party/protobuf/PIN.md:11` |
| Commit SHA | `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` | `PIN.md:12`; `git rev-parse HEAD` |
| describe | `v36-dev-400-g2de70d710` | `git describe --tags` |
| version.json | `protoc 37-dev`, `rust 0.37-dev`; `date: 2026-07-09`; `lts: false`; cpp 7.37-dev, python 7.37-dev, legacy_rust 4.37-dev | `third_party/protobuf/version.json:2-17` (main.protoc_version :3, main.languages.rust :15) |
| Commit subject | "Add allocation failure tests for unknowns and defbuilder" | `git log -1` |
| Commit date | 2026-08-19 13:44:36 -0700 | `git log -1 --format=%ad --date=iso` |
| Author | Protobuf Team Bot `<protobuf-github-bot@google.com>` | `git log -1 --format=%an` |
| Checkout mode | detached HEAD, partial clone `--filter=blob:none` | `PIN.md:17`; blob fetch observed during archaeology (network) |
| Head ref | `origin/main` == `origin/HEAD` == `main` == HEAD | `git log --oneline -1` |

Note the version-number asymmetry: `git describe` says **v36-dev-400** while
`version.json` already says **37-dev** — the repo is 400 commits past the
v36-dev branch point, and version.json was bumped to the next dev line
(upstream bumps version.json right after a release, cf. `baca23903`
2022-04-22 "Add initial version.json file", `d259bd328` 2022-05-10 "Updating
version.json ... to: 21.0-rc1"). The oracle *is* the commit, not the tag.

### Initial build environment (recorded 2026-08-19)

| Tool | Version | Source of truth |
|---|---|---|
| OS | Linux x86_64, kernel `7.1.8-1-cachyos` | `uname -srm` |
| rustc | `1.96.0 (ac68faa20 2026-05-25)` | `rustc --version`; `rust-toolchain.toml` |
| gcc | `16.2.1 20260810` | `gcc --version` |
| cmake | `4.4.2` | `cmake --version` |
| python3 | `3.14.7` | `python3 --version` |
| git | `2.55.0` | `git --version` |
| CPU / RAM | 16 cores / 125 GiB (40 GiB available at record time) | `nproc`; `free -h` |

### Oracle build recipe (cmake, static)

```sh
cmake -S third_party/protobuf -B third_party/build \
  -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_PROTOC=OFF \
  -Dprotobuf_BUILD_SHARED_LIBS=OFF
cmake --build third_party/build --target libupb -j
```

Sources: `PIN.md:42-45`. **Precision note**: the cmake target is named
`libupb` (`cmake/libupb.cmake:19`), aliased `protobuf::libupb` (:54), and the
on-disk library is `${LIB_PREFIX}upb` (:45-48). `PIN.md:45`'s literal
`--target upb` is a typo — no target named `upb` exists in the cmake build
(verified: only `libupb` in `cmake/*.cmake`); build with `--target libupb`.
This produces the **compiled oracle**: a static `libupb` that `tools/oracle`
links against for differential evidence. `receipts/` is the designated
evidence pack store (README.md:38, 58; OPEN_QUESTIONS.md §4 step 3).

---

## 2. Source authority hierarchy

| Tier | Role | Concrete artifact in this repo |
|---|---|---|
| **Tier 1** | Compiled pinned libupb oracle — the *behavioral* truth (what courts diff against) | `third_party/build/` (cmake output) + `tools/oracle/` (links it). Build recipe `PIN.md:42-45`; target `cmake/libupb.cmake:19-24`. Caveat: `third_party/build/` is **empty** and `receipts/` is **empty** as of 2026-08-19 — the initial oracle build is recorded in `PIN.md:38-45` but the artifacts are not yet present. See §6. |
| **Tier 2** | Pinned source tree — the *structural* truth (what file:line claims cite) | `third_party/protobuf/` at `2de70d710…` (`PIN.md:12`). All `upb/…:line` citations in the forensics set resolve against this tree, e.g. `upb/wire/reader.c:19-31` (LongVarint), `upb/mem/arena.c:480-509` (slow-malloc NULL), `cmake/libupb.cmake:55` (utf8_range link). |
| **Tier 3** | Git history — the *temporal* truth (when a behavior appeared/vanished) | The same tree is a full-history partial clone; `git -C third_party/protobuf log …` works offline for subjects/refs, `git show <sha>:<path>` fetches blobs on demand (`PIN.md:17`, observed during this archaeology). **Important**: the standalone upb history (2009–2023) is *present in-repo* as a merged root `d29a54fc97` (2009-02-01), spliced at `81242c57c` (2023-08-25, PR #13686) — see VERSION_ATLAS.md §1 for the correction of the "squashed history" assumption. |
| **Tier 4** | Issues / commit archaeology — *motivation* truth (why a behavior exists) | GitHub PR numbers embedded in merge subjects, e.g. `#550` (minitable-api merge), `#13686` (merge-upb), `#363` (delete-handlers), and hardening PRs `#28553` (mini table bounds), `#28900` (extension rollback), `#27568` (arena overflow), `#27133` (field_count overflow). Citable by subject; bodies not vendored offline. |
| **Tier 5** | Protobuf spec — the *intent* truth (what the format "should" do) | `upb/README.md:22-44` (feature list + the two non-features: **no text-format parsing** :42, **no deep descriptor verification** :43-44); conformance suite `upb/conformance/conformance_upb.c` + `upb/conformance/BUILD:177-183` (performance tests disabled under ASan); `upb/conformance/*_failures*.txt`. The wire format itself is only indirectly pinned (via conformance); no spec doc is vendored. |

Adjudication rule: Tier 1 beats Tier 2 on *observable* disputes (e.g. status
precedence, OPEN_QUESTIONS §3.6); Tier 2 beats Tier 3 on *current* structure;
Tier 3 beats Tier 4 when commit messages conflict; Tier 5 only fills gaps the
others cannot decide.

---

## 3. Tree inventory (`third_party/protobuf/upb/`)

Top level: `BUILD`, `LICENSE`, `README.md`, `generated_code_support.h`
(only 4 files; the amalgamated `upb.c`/`upb.h` are *generated* outputs, not
checked in — `upb/BUILD:155-205` declares them as `outs` of `gen_amalgamation`).

File counts below are `find <dir> -type f \( -name '*.c' -o -name '*.h' \)`
recursive (maxdepth-1 count in parentheses; `internal/` subdirs are listed).

| Subdir | .c/.h | Internal/ | One-line description (from headers present) |
|---|---|---|---|
| `base/` | 8 (6) | `internal/` | Core scalar types & error plumbing: `descriptor_constants.h` (field type/mode enums), `error_handler.h` (status-report callback), `status.h` (`upb_Status`), `string_view.h`, `upcast.h` |
| `hash/` | 5 | — | Table primitives backing maps/unknowns: `str_table.h`, `int_table.h`, `ext_table.h` (open-addressing hash tables), `common.h` |
| `json/` | 4 | — | JSON surface: `decode.h` / `encode.h` (reflection-driven JSON parser/printer; decoder origin `d49c1db6c` 2020-02-23) |
| `lex/` | 6 | — | Parsing helpers: `atoi.h` (varint/ASCII ints), `round_trip.h` (float/double round-trip), `unicode.h` (UTF-8 decode/encode) |
| `mem/` | 6 (4) | `internal/` | Memory model: `arena.h`, `alloc.h` (`upb_Arena`, `upb_Allocator`); bump path + blocks (`upb/mem/arena.c`, MEMORY_MODEL.md) |
| `message/` | 41 (27) | `internal/` | Message objects & accessors: `message.h`, `array.h`, `map.h`, `accessors.h` (+`accessors_split64.h`), `compare.h`, `copy.h`, `merge.h`, `promote.h`, `unknown_fields.h`, `value.h`, `compat.h`, `convert.h`, `map_gencode_util.h`; `internal/` holds layout (`internal/message.h`), presence, extension internals |
| `mini_descriptor/` | 13 (6) | `internal/` | Compressed schema format: `decode.h` (mini-descriptor wire format), `build_enum.h`, `link.h` |
| `mini_table/` | 24 (15) | `internal/` | The runtime schema: `message.h`, `field.h`, `enum.h`, `sub.h`, `extension.h`, `extension_registry.h`, `file.h`, `generated_registry.h`, `compat.h`, `debug_string.h`; `internal/` = packed layouts (`internal/field.h`, `internal/message.h`) |
| `port/` | 5 | — | Portability: `def.inc`/`undef.inc` macro dance (via textual `//upb/port:inc`), `atomic.h`, `overflow.h` (new 2026-08-17, `c6b856d78`), `sanitizers.h`, `vsnprintf_compat.h` |
| `reflection/` | 61 (33) | `internal/`, `cmake/` | Def-pool reflection: `def.h`, `def_pool.h`, `message_def.h`, `field_def.h`, `oneof_def.h`, `enum_def.h`, `file_def.h`, `service_def.h`, `method_def.h`, `message.h` (dynamic messages), `descriptor_bootstrap.h`, `descriptor_pool.h`; `cmake/` holds the checked-in bootstrap `descriptor.upb*.{h,c}` (`cmake/libupb.cmake:6-15`) |
| `text/` | 7 (5) | `internal/` | Text format **encode only**: `encode.h`, `debug_string.h`, `options.h`; no parser (README.md:42) |
| `util/` | 5 | — | `def_to_proto.h` (def→FileDescriptorProto), `required_fields.h` (required-field checker) |
| `wire/` | 46 (14) | `internal/` | Wire codecs: `reader.h` (varint/tag/delimited, `reader.c:19-31` LongVarint), `decode.h`, `encode.h` (+`encode_extension.h`), `writer.h`, `byte_size.h`, `eps_copy_input_stream.h`, `types.h`; `internal/` = `back_alloc.h/.c` (one-pass encoder, `a7864c77b`), `encoder.h`, `reader_internal.h`, `decode_fast/` subdir split from `decode_fast.c` (`7cd3d4e60` 2025-05-01) |
| `conformance/` | 1 | — | `conformance_upb.c` (conformance runner binary source) + `BUILD`, `build_defs.bzl`, `conformance_upb_failures.txt`, `conformance_upb_failures_performance.txt` |
| `test/` | 2 | — | `fuzz_util.h`, `parse_text_proto.h` + test protos (`test.proto`, `proto3_test.proto`, `editions_test.proto`, …) and `*_test.cc` harnesses |
| `bazel/`, `cmake/` | 0 | — | Bazel helper bzl files (`copts.bzl`, amalgamation rules); cmake glue (`upb/cmake/upb_cmake_dist.cmake` etc.) |

**Totals**: 235 `.c`/`.h` files in `upb/` (recursive). Eight `internal/`
dirs: `base`, `mem`, `wire`, `mini_table`, `reflection`, `message`, `text`,
`mini_descriptor` (nothing in `hash`/`json`/`lex`/`port`/`util`).

### `third_party/protobuf/rust/` (the official Rust bindings — not our port)

- `upb_kernel/` — **9 .rs files**: `mod.rs`, `message.rs`, `minitable.rs`,
  `map.rs`, `repeated.rs`, `string.rs`, `extension.rs`, `conversions.rs`,
  `interop.rs`. The upb-backed kernel (layout after `2b3058dcf` 2026-03-20
  "Split upb and cpp backends into submodules").
- `cpp_kernel/` — 9 .rs files (`mod.rs`, `message.rs`, `map.rs`,
  `repeated.rs`, `string.rs`, `extension.rs`, `interop.rs`, `raw.rs`,
  `rust_alloc_for_cpp_api.rs`) + `.cc/.h` C++ bridge (`cpp_api` target).
- `protobuf_macros/` — proc-macro crate: `proto_proc_macro_impl.rs`.
- `release_crates/` — crates.io packaging: `protobuf`, `protobuf_codegen`,
  `protobuf_macros`, `protobuf_well_known_types`, `google_protobuf`,
  `google_protobuf_codegen`, `protobuf_example`, `protobuf_tests`,
  `protobuf_lite`-era templates, `substitute_rust_release_version.bzl`.
- Top-level API files — 17 `.rs` at `rust/`: `protobuf.rs`,
  `protobuf_lite.rs`, `shared.rs`, `prelude.rs`, `codegen_traits.rs`,
  `proxied.rs`, `singular.rs`, `repeated.rs`, `map.rs`, `primitive.rs`,
  `enum.rs`, `string.rs`, `extension.rs`, `cord.rs`, `internal.rs`,
  `gtest_matchers.rs`, `gtest_matchers_impl.rs`; plus `BUILD`, `defs.bzl`,
  `rules.bzl`, `dist.bzl`, and the `upb/` FFI crate (`upb/lib.rs`,
  `upb/arena.rs`, `upb/message.rs`, `upb/wire.rs`, `upb/text.rs`,
  `upb/sys/` = `upb_api.c` + bindings).
- Kernel selection: `rust/BUILD:369-377` (`rust_proto_library_kernel`
  string_flag, default `cpp`), `rust/defs.bzl:36-43` (alias select).
  Details in VERSION_ATLAS.md §4.

### `third_party/protobuf/upb_generator/` (code generators)

| Binary | BUILD decl | Emits |
|---|---|---|
| `protoc-gen-upb` | `upb_generator/c/BUILD:43-44` (`bootstrap_cc_binary`) | C API gencode: `<file>.upb.h` + `<file>.upb.c` (`c/names_internal.cc:34`, `c/generator.cc:113`) |
| `protoc-gen-upb_minitable` | `upb_generator/minitable/BUILD:88-89` | Mini tables: `<file>.upb_minitable.h` + `.upb_minitable.c` (`minitable/names_internal.cc:37`, `minitable/main.cc:37`) |
| `protoc-gen-upbdefs` | `upb_generator/reflection/BUILD:28-29` | Reflection defs: `<file>.upbdefs.h` + `.upbdefs.c` (`reflection/header.cc:89`, `reflection/source.cc:34`) |

Shared machinery: `upb_generator/common.{cc,h}`, `file_layout.{cc,h}`,
`plugin.{cc,h}` (`plugin.h` = protoc plugin bootstrap), `names*.{h,cc}`,
`bootstrap_compiler.bzl`, `stage0/` (self-host bootstrap sources).

---

## 4. Build graph essentials

Bazel targets in `upb/BUILD` (primary):

- `generated_code_support` (`upb/BUILD:111-140`): header-only support for
  generated code; deps on `base`, `mem`, `message`(+internal), `mini_descriptor`,
  `mini_table`(+internal), `wire`, and — **only when fasttable is enabled** —
  `//upb/wire/decode_fast:field_parsers` (:133-139). Its only hdr is
  `generated_code_support.h` (:113).
- `gen_amalgamation` + `amalgamation` (:155-213): `upb_amalgamation` rule
  emits `upb.c`/`upb.h` from the full lib list (:161-202, incl.
  `descriptor_upb_c_proto`/`descriptor_upb_minitable_proto` bootstrap protos);
  the `cc_library` `amalgamation` compiles `upb.c` and depends on
  `//third_party/utf8_range` (:207-213). `gen_php_amalgamation`/`php_amalgamation`
  (:215-274) and `gen_ruby_amalgamation`/`ruby_amalgamation` (:276-334) do the
  same with `php-`/`ruby-` prefixes and per-language extras (php adds `//upb/json`
  :232, ruby adds `//upb/util:def_to_proto` :311).
- `source_files` (:336-351): `filegroup` of all `**/*.h` (excludes
  `conformance_upb.c` and `reflection/stage0/**`), used by
  `//upb/cmake` and python dist — this is the "what ships" list.
- `test_util` (:387-398): testonly aggregation (`fuzz_util`,
  `parse_text_proto`, `def_to_proto_test_lib`, wire test_util targets).
- Other: `test_protos` (:353-368), `test_srcs` (:370-385), `generated_cpp_support`
  (:143-151, for `//hpb`).

**`fasttable_enabled` build flag** (`upb/BUILD:48-68`): a Bazel `bool_flag`
(`fasttable_enabled`, default `False`, :48-53) gated through
`fasttable_enabled_setting_flag` (:55-59) and `fasttable_enabled_setting`
(:61-68) which additionally requires `:any_64bit` (:70-84: aarch64, arm64,
mips64, ppc64le, riscv64, s390x, wasm64, x86_64 — fasttable is 64-bit-only,
cf. OPEN_QUESTIONS §5.5). The flag is *off by default*; it is flipped on for
optimized builds inside Google (and was briefly enabled for non-opt builds on
2026-08-17 by `d46a6ff07`, rolled back same day by `857623168`).

**utf8_range third-party dependency**: vendored as a subtree at
`third_party/utf8_range/` (merged 2023-01-19, `163e31a41` "Merge commit
'c2da35d619…' as 'third_party/utf8_range'"; the subtree root commit is
`c2da35d619`, 2023-01-19, "Squashed 'third_party/utf8_range/' content from
commit 72c943dea"). Contains Lemire AVX2/SSE/NEON UTF-8 validators
(`lemire-avx2.c`, `lemire-sse.c`, `lemire-neon.c`) + scalar `naive.c`. Referenced
by the three amalgamation targets (`upb/BUILD:212, 273, 333`).

**CMake `libupb` STATIC target** (`cmake/libupb.cmake:19-24`):
`add_library(libupb STATIC ${libupb_srcs} ${libupb_hdrs} ${bootstrap_sources}
${protobuf_version_rc_file})`, with `bootstrap_sources` from
`upb/reflection/cmake/google/protobuf/descriptor.upb*.{h,c}` + `json_enumvalue_options.upb*`
(:6-15). `OUTPUT_NAME` is `${LIB_PREFIX}upb` (:45-48); comment at :17-18:
"upb does not support shared library builds, and is intended to be statically
linked as a private dependency". Private link: `target_link_libraries(libupb
PRIVATE utf8_range)` (:55). Source lists come from
`src/file_lists.cmake` (`libupb_srcs` :694, `libupb_hdrs` :766).
`protobuf_configure_target(libupb)` (:32) applies common flags; MSVC gets
`/Zc:preprocessor` (:34-43).

---

## 5. Reconstruction rules (Rust kernel vs C oracle)

Derived from the project ground rules (README.md:14-25, §§1/6/42/47 of the
charter, which is not present in-repo — OPEN_QUESTIONS.md §5.1) and the
layout (README.md:27-46):

1. **Production Rust never links, FFI-calls, wraps, or subprocess-delegates
   the C implementation** (README.md:16-19). The C tree under
   `third_party/protobuf/` is *oracle only* (README.md:45).
2. C appears in exactly three non-production roles: oracle tooling
   (`tools/oracle`, links the pinned `libupb`), differential courts
   (`courts/`), and benchmarks (`benches/`) (README.md:18-19).
3. **CI must reject forbidden linkage** (README.md:19): any production crate
   depending on/compiling C sources fails the build. Enforcement mechanism is
   Phase 11 work (OPEN_QUESTIONS.md §1 row 11: "forbidden-linkage CI");
   the specific CI check is not yet implemented in this tree (see §6).
4. Parity is defined observationally against the oracle, not by
   reimplementing source structure: a surface is only PARITY-SEALED with
   residual-free differential receipts (`STATUS.md:3-8`, `PARITY.toml`).
5. The official `rust/upb_kernel` in the pinned tree is *documentation of the
   required C ABI surface*, not an implementation to copy — the C surface it
   touches is enumerated in `rust/upb/sys/upb_api.c:13-25` and KERNEL_ATLAS.md
   §0-§1.

---

## 6. Unverified / needs confirmation

- **Oracle artifacts absent**: `third_party/build/` is empty and `receipts/`
  is empty as of 2026-08-19. The environment table in §1 was verified live,
  but no *initial-build receipt* exists; the build recipe is taken from
  `PIN.md:42-45`. Rebuild and capture a receipt before relying on Tier 1.
- **`tools/oracle` is a skeleton**: `tools/oracle/` contains only an empty
  `src/`; the `tools/oracle/build.sh` and `tools/oracle/README.md` referenced
  by README.md:51-52 / PIN.md:47 do not exist. The oracle binary has never
  been produced in this tree.
- **Charter absent**: §5's rules cite charter §§1/6/42/47, but no charter file
  exists in-repo (OPEN_QUESTIONS.md §5.1); the CI-forbidden-linkage mechanism
  is specified but unimplemented.
- **`protoc`/`protoc-gen-*` binaries**: the pin builds `libupb` only
  (`protobuf_BUILD_PROTOC=OFF`); anything needing generated code must use the
  checked-in bootstrap under `upb/reflection/cmake/` or fetch protoc. The
  `upb_generator` binaries are declared in Bazel only, not cmake.
- **Tier 4 depth**: PR bodies/issues are not vendored; commit-subject
  archaeology may undercount behavior changes hidden behind "Internal change"
  subjects (OPEN_QUESTIONS.md §5.6).
- **utf8_range source of truth**: subtree root `c2da35d619` is a *squashed*
  import ("Squashed 'third_party/utf8_range/' content from commit 72c943dea");
  its internal history is not available here.
