# SURFACE_ATLAS — the upb public surface (pinned oracle)

Oracle: `third_party/protobuf` @ `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60` (37-dev, rust 0.37-dev).
All paths below are relative to `third_party/protobuf/`. Line numbers are from the pinned tree.
Line numbers were verified by reading the pinned files; anything not verified is marked **unverified**.

---

## 1. upb/base/ — foundational scalars, error reporting, descriptor constants

| File | Key public types | Key public functions | Semantic role |
|---|---|---|---|
| `upb/base/status.h` | `upb_Status` `{bool ok; char msg[511]}` (:18-21) | `upb_Status_ErrorMessage` (:27), `upb_Status_IsOk` (:28), `upb_Status_Clear` (:31), `upb_Status_SetErrorMessage` (:32), `upb_Status_SetErrorFormat` (:33), `upb_Status_VSetErrorFormat` (:35), `upb_Status_VAppendErrorFormat` (:37) | Return-channel for fallible non-arena operations (mini-table build, JSON decode, def-pool add). Implemented in `upb/base/status.c` (:19,:27,:31) |
| `upb/base/error_handler.h` | `upb_ErrorCode` (Ok/OOM/Malformed/MaxDepthExceeded, :55-60), `upb_ErrorHandler` `{int code; jmp_buf buf}` (:62-65) | `upb_ErrorHandler_Init` (:67), `upb_ErrorHandler_ThrowError` (:71) | longjmp()-based exceptions for hot C parse paths (arena fallback, decoder, eps-copy stream). Not C++-compatible by design |
| `upb/base/string_view.h` | `upb_StringView` `{const char* data; size_t size}` (:23-26) | `upb_StringView_FromDataAndSize` (:32), `FromString` (:40), `IsEqual` (:44), `Compare` (:50) | The universal bytes/string carrier across the API; repr must be 2 words |
| `upb/base/descriptor_constants.h` | `upb_CType` (:18-30), `upb_Label` (:33-37), `upb_FieldType` (:40-59) | `upb_FieldType_CType` (:68), `upb_FieldType_IsPackable` (:94) | Type taxonomy; 1-based enums mirroring descriptor.proto; CType drives `upb_Array_New`/`upb_Map_New` |
| `upb/base/upcast.h` | — | `UPB_UPCAST(x)` (:25) | Casts generated `pkg_FooMessage` → embedded `upb_Message` via a `base` member named `base_dont_copy_me__upb_internal_use_only` |

## 2. upb/mem/ — arenas and allocation

| File | Key public types | Key public functions | Semantic role |
|---|---|---|---|
| `upb/mem/arena.h` | opaque `upb_Arena` | `upb_Arena_Init` (:49), `Free` (:52), `SetAllocCleanup` (:56), `Fuse` (:63), `IsFused` (:66), `GetUpbAlloc` (:69), `IncRefFor` (:72), `DecRefFor` (:74), `RefArena` (:108), `HasRef` (:115), `SpaceAllocated` (:119), `DebugRefCount` (:121), `New` (:137), `NewSized` (:141), `Malloc` (:145), `Realloc` (:148), `SetMaxBlockSize` (:163), `ShrinkLast` (:169), `TryExtend` (:179) | All message/array/map/string storage lives in arenas; fuse + refcount lifetime graph is the ownership model the Rust kernel leans on (`Arena::fuse`) |
| `upb/mem/internal/arena.h` | `struct upb_Arena {char* ptr; const char* end;}` (:38-42) | inline fast-path `_upb_Arena_Malloc_Unchecked` (:74), `upb_Arena_Malloc` (:94), `ShrinkLast` (:101), `TryExtend` (:123), `Realloc` (:141); block machinery `_upb_Arena_NextBlockSize` (:174), `_upb_Arena_AllocBlock` (:187), `_upb_Arena_AddBlock` (:198), `_upb_Arena_UseBlock` (:216), `_upb_Arena_Steal` (:222) | Exposes the arena as a pointer-bump allocator; `UPB_ARENA_BASE_SIZE_HACK` (:27-30) lets the decoder inline an arena. A pure-Rust kernel must reproduce bump/block semantics + OOM injection |
| `upb/mem/alloc.h` | `upb_alloc` `{func}` (:40-42), `upb_alloc_func` (:31-32), `upb_SizedPtr` (:52) | `upb_malloc` (:44), `upb_SizeReturningMalloc` (:57), `upb_realloc` (:71), `upb_free` (:82), `upb_alloc_global` (:94), `upb_gmalloc` (:101), `upb_AllocationCount_IsAvailable/Get/Reset/FailOn` (:114-121) | Pluggable allocator vtable + thread-local allocation-count OOM simulation (used by fault-injection tests) |

## 3. upb/wire/ — binary wire format

| File | Key types/functions | Role |
|---|---|---|
| `upb/wire/types.h` | `upb_WireType` (:12-19) | Varint/64-bit/Delimited/StartGroup/EndGroup/32-bit |
| `upb/wire/reader.h` | `upb_WireReader_ReadTag` (:39), `GetFieldNumber` (:43), `GetWireType` (:46), `ReadVarint` (:48), `SkipVarint` (:57), `ReadSize` (:75), `ReadFixed32` (:83), `ReadFixed64` (:98), `_upb_WireReader_SkipGroup` (:108) | Bounds-check-free primitives over eps-copy stream (10-byte slop guarantee) |
| `upb/wire/writer.h` | `upb_WireWriter_VarintUnusedSizeFromLeadingZeros64` (:9) | Varint length computation for encode |
| `upb/wire/encode.h` | `kUpb_EncodeOption_Deterministic/SkipUnknown/CheckRequired` (:29-43), `upb_EncodeStatus` (:46-57), max-depth helpers (:60-79) | `upb_Encode` (:81), `upb_EncodeLengthPrefixed` (:87), `upb_EncodeStatus_String` (:92). Impl `upb/wire/encode.c:25` → `_upb_Encode` (internal/encoder.h:128) |
| `upb/wire/decode.h` | decode options `AliasString/CheckRequired/AlwaysValidateUtf8/DisableFastTable` (:30-68), `upb_DecodeStatus` (:86-100) | `upb_Decode` (:103), `upb_DecodeLengthPrefixed` (:110), `upb_DecodeWithTrace` (:116), `upb_DecodeStatus_String` (:123). Impl `upb/wire/decode.c:1311` |
| `upb/wire/byte_size.h` | — | `upb_ByteSize` (:23); impl `byte_size.c:24` = encode-into-arena then report length |
| `upb/wire/eps_copy_input_stream.h` | `upb_EpsCopyInputStream`, `upb_EpsCopyCapture` (:25-26) | `Init` (:31), `InitWithErrorHandler` (:36), `HasErrorHandler` (:49), `IsError` (:55), `IsDone` (:67), `CheckSize` (:76), `Capture_Start/End` (:82/:89), `ReadStringAlwaysAlias` (:105), `ReadStringEphemeral` (:126), limit stack (from :130) |
| `upb/wire/internal/decoder.h` (.c) | decoder state (300-line header; `decode.c` 1395 lines) | General (non-fasttable) message decoder; drives `_upb_Message_*` mutation + `upb_ExtensionRegistry` lookups |
| `upb/wire/internal/encoder.h` (.c) | `upb_encstate`, back-alloc, `_upb_mapsorter` | `_upb_Encode_Field` (:62), `_upb_Encode` (:128); deterministic map sorting |
| `upb/wire/decode_fast/` | `_upb_FieldParser` table entries (`select.h:58` `upb_DecodeFast_GetFunctionPointer`) | JIT-style generated per-field parser dispatch (`field_*.c`, `function_*.c`, `cardinality.c`, `select.c`, `dispatch.c`); enabled by `UPB_FASTTABLE`, embedded as `upb_MiniTable.fasttable[]` |

## 4. upb/message/ — message objects, arrays, maps, accessors

| File | Key public functions | Role |
|---|---|---|
| `upb/message/message.h` | `upb_Message_New` (:36), `NextUnknown` (:56), `HasUnknown` (:59), `ExtensionCount` (:73), `NextExtension` (:76), `Freeze` (:87), `IsFrozen` (:90) | Schema-independent message ops; impl `message.c:34` |
| `upb/message/array.h` | `upb_Array_New` (:30), `Size` (:33), `Capacity` (:36), `Get` (:39), `GetMutable` (:43), `Set` (:46), `Append` (:49), `Copy` (:55), `AppendAll` (:60), `Move` (:66), `Insert` (:73), `Delete` (:79), `Reserve` (:82), `Resize` (:88), `DataPtr` (:92), `MutableDataPtr` (:95), `Freeze` (:100) | Dense typed vectors (elem size from `upb_CType`) |
| `upb/message/map.h` | `upb_Map_New` (:31), `Size` (:35), `Get` (:40), `GetMutable` (:46), `Clear` (:50), `Insert` (:55), `Set` (:63), `Delete` (:73), `Next` (:88), `SetEntryValue` (:93), `MapIterator_*` (:108-117), `Freeze` (:122) | Hash map over `upb_MessageValue` key/value; iteration order is insert order (`kUpb_Map_Begin` = `(size_t)-1`, :84) |
| `upb/message/accessors.h` | `Clear/ClearBaseField/ClearExtension/ClearOneof` (:38-48), `HasBaseField/HasExtension` (:50-54), typed `Get*` (:56-118), `GetOrCreateMutable{Array,Map,Message}` (:98-106), `SetBaseField*` family (:126-266), extension `Get/SetExtension*` (:176-415), `WhichOneofFieldNumber` (:299) | MiniTable-driven field access; presence bits + oneof cases are the mechanism (see internal/accessors.h `_upb_Message_SetPresence` :167) |
| `upb/message/copy.h` | `upb_Message_DeepClone` (:26), `ShallowClone` (:33), `upb_Array_DeepClone` (:38), `upb_Map_DeepClone` (:44), `DeepCopy` (:50), `ShallowCopy` (:58) | Clone/copy semantics used by Rust `CopyFrom` |
| `upb/message/merge.h` | `upb_Message_MergeFrom` (:16) | Merge; implemented as **encode(src)→decode(dst)** round-trip (`merge.c:14-31`) — a critical behavioral quirk to replicate |
| `upb/message/compare.h` | `upb_Message_IsEmpty` (:37), `IsEqual` (:40), `MessageValue_IsEqual` (:45) | Equality with `UPB_COMPARE_OPTION_PARTIAL`; unknown-field-lossy semantics documented in Rust `message_eq` |
| `upb/message/promote.h` | `upb_Message_GetOrPromoteExtension` (:47), `FindUnknown` (:66), `MiniTable_PromoteUnknownToMessage` (:91), `...ToMessageArray` (:103), `...ToMap` (:114) | Lazily promotes serialized (non-canonical) unknown data into parsed form |
| `upb/message/unknown_fields.h` | `NextUnknown2` (:44), `FindUnknown2` (:95), `DeleteUnknown` (:135), `DeleteUnknown2` (:167) | Segmented unknown-field iteration/deletion over `aux_data` |
| `upb/message/convert.h` | `upb_Message_Convert` (:52) | Convert message across two minitables (editions compatibility) |
| `upb/message/compat.h` | `NextExtensionReverse` (:29), `FindExtensionByNumber` (:33) | Cross-version extension compatibility lookup |
| `upb/message/internal/types.h` | `struct upb_Message { uintptr_t internal; }` (:25-30), `upb_TaggedAuxType` (:18-23) | **Core layout**: message is a tagged pointer; bit 0 = frozen; rest = `upb_Message_Internal*` |
| `upb/message/internal/message.h` | `upb_TaggedAuxPtr` (:46-84), `upb_Message_Internal {uint32_t size; uint32_t capacity; upb_TaggedAuxPtr aux_data[];}` (:226-232) | Aux data: aliased/non-aliased unknowns + canonical/non-canonical extensions, tagged in 3 low bits |

## 5. upb/mini_table/ — immutable per-message layout descriptors

| File | Key public functions | Role |
|---|---|---|
| `upb/mini_table/message.h` | `FindFieldByNumber` (:26), `GetFieldByIndex` (:29), `FieldCount` (:32), `IsMessageSet` (:34), `SubMessage` (:43), `MapEntrySubMessage` (:47), `GetSubEnumTable` (:51), `MapKey` (:55), `MapValue` (:59), `FieldIsLinked` (:64), `GetOneof` (:76), `NextOneofField` (:84) | Read-side mini table queries |
| `upb/mini_table/field.h` | `CType` (:25), `HasPresence` (:27), `IsArray` (:29), `IsClosedEnum` (:31), `IsExtension` (:33), `IsInOneof` (:35), `IsMap` (:37), `IsPacked` (:39), `IsScalar` (:41), `IsSubMessage` (:44), `Number` (:47), `Type` (:49) | Field predicate/accessor surface |
| `upb/mini_table/internal/field.h` | **Layout**: `struct upb_MiniTableField {uint32 number; uint16 offset; int16 presence; uint16 submsg_ofs; uint8 descriptortype; uint8 mode;}` (:21-35); `kUpb_FieldMode` (:40), `kUpb_LabelFlags` (:50), `kUpb_FieldRep` (:62-71) | `presence` >0 = hasbit index, <0 = ~oneof index; `mode` packs FieldMode\|LabelFlags\|(FieldRep<<6) — the compressed schema |
| `upb/mini_table/internal/message.h` | **Layout**: `struct upb_MiniTable {fields*; uint16 size; uint16 field_count; uint8 ext; uint8 dense_below; uint8 table_mask; uint8 required_count; fasttable[];}` (:71-94), `kUpb_Message_Align = 8` (:63) | `size` = inline message data size (excludes aux); `ext` = `upb_ExtMode` (:41-55) |
| `upb/mini_table/enum.h`, `sub.h` | `upb_MiniTableEnum` (closed-enum value sets); `upb_MiniTableSub_FromMessage/Enum/Message` (:30-37) | Enum tables; tagged sub union for message/enum fields |
| `upb/mini_table/extension.h` | `MiniTableExtension_CType` (:29), `Number` (:32), `Extendee` (:34), `GetSubMessage` (:37), `GetSubEnum` (:40), `SetSubMessage` (:43), `SetSubEnum` (:46), `ToField` (:49) | Extension descriptors (a `upb_MiniTableField` + extendee + sub) |
| `upb/mini_table/extension_registry.h` | `upb_ExtensionRegistry_New` (:71), `Add` (:74), `AddArray` (:81), `Lookup` (:86), `Size` (:90) | extreg passed to `upb_Decode` for extension parsing |
| `upb/mini_table/file.h` | `MiniTableFile_Enum/EnumCount/Extension/ExtensionCount/Message/MessageCount` (:25-38) | Aggregates one generated file's tables |
| `upb/mini_table/generated_registry.h` | `upb_GeneratedRegistry_Load` (:44), `Release` (:51), `Get` (:57) | Whole-program registry of generated minitables (linker-section based) |
| `upb/mini_table/compat.h` | `upb_MiniTable_Compatible` (:26), `Equals` (:36) | Cross-version layout compatibility |
| `upb/mini_table/debug_string.h` | `upb_MiniTable_DebugString` (:19) | Table dump for tests |
| `upb/mini_table/internal/*` | `message.c` (build logic), `size_log2.h`, `generated_registry.h`, `sub.h`, `extension.h`, `enum.h`, `file.h` | Internal builders/accessors |

## 6. upb/mini_descriptor/ — compressed schema encoding ↔ mini tables

| File | Key public functions | Role |
|---|---|---|
| `upb/mini_descriptor/decode.h` | `upb_MiniTablePlatform` (:30-35), `_upb_MiniTable_Build` (:45), `upb_MiniTable_Build` (:49), `_upb_MiniTableExtension_Init` (:58), `_upb_MiniTableExtension_Build` (:70), `BuildMessage` (:84), `BuildEnum` (:94), `BuildWithBuf` (:111) | Builds `upb_MiniTable` from mini-descriptor string; **this is what the Rust kernel calls at static-init time** (`rust/upb_kernel/minitable.rs`) |
| `upb/mini_descriptor/build_enum.h` | `upb_MiniTableEnum_Build` (:24) | Enum tables from mini descriptors |
| `upb/mini_descriptor/link.h` | `upb_MiniTable_SetSubMessage` (:40), `SetSubEnum` (:46), `GetSubList` (:61), `Link` (:71) | Post-build linking of sub-tables (Rust: `link_mini_table`); unlinked submessage fields parse as unknowns |
| `upb/mini_descriptor/internal/base92.h` | `_upb_ToBase92` (:22), `_upb_FromBase92` (:28), `_upb_Base92_DecodeVarint` (:34) | Base92 varint codec of the mini-descriptor wire format |
| `upb/mini_descriptor/internal/encode.h` | mini-descriptor encoder | Used by reflection (`MiniDescriptorEncode`) and by upb_generator |
| `upb/mini_descriptor/internal/decoder.h` | decoding state machine (:46) | Drives `decode.c` |
| `upb/mini_descriptor/internal/modifiers.h`, `wire_constants.h` | modifier bits, wire constants | Field modifier encoding (packed-ness, presence, etc.) |

## 7. upb/reflection/ — full descriptors (DefPool + *Def types)

| File | Key public functions | Role |
|---|---|---|
| `upb/reflection/def.h` | umbrella export of def_pool/enum/enum_value/extension_range/field/file/message/method/oneof/service defs | The single include for reflection |
| `upb/reflection/def_pool.h` | `upb_DefPool_New` (:30), `Free` (:28), `Find{Message,Enum,EnumValue,File,Extension,Service}ByName*` (:39-77), `AddFile` (:86), `ExtensionRegistry` (:90), `DisableClosedEnumChecking` (:108), `DisableImplicitFieldPresence` (:118) | Symbol table + descriptor→mini-table compiler entry (`AddFile` builds minitables via mini_descriptor) |
| `upb/reflection/message.h` | `upb_Message_GetOrCreateMutableMessage` (:29), `WhichOneofByDef` (:33), `ClearFieldByDef` (:40), `HasFieldByDef` (:44), `GetFieldByDef` (:48), `SetFieldByDef` (:56), `Next` (:76), `DiscardUnknown` (:82) | Reflection-driven accessors (used by JSON/text/php/ruby/conformance) |
| `upb/reflection/message_def.h` | `Field` (:73), `FieldCount` (:75), `FindFieldByNameWithSize` (:103), `FindFieldByNumber` (:105), `FullName` (:111), `MiniDescriptorEncode` (:117), `MiniTable` (:121), `Oneof*` (:134-136), `WellKnownType` (:150) | Message descriptor → mini table bridge |
| `upb/reflection/field_def.h` | `ContainingType` (:35), `CType` (:37), `Default` (:38), `EnumSubDef` (:39), `HasPresence` (:46), `IsEnum/IsMap/IsPacked/IsRepeated/IsRequired/IsSubMessage` (:49-59), `JsonName` (:60), `MessageSubDef` (:63), `MiniDescriptorEncode` (:68), `Name/Number/Type` (:75-81) | Field descriptor surface |
| `enum_def.h`, `enum_value_def.h`, `file_def.h`, `oneof_def.h`, `service_def.h`, `method_def.h`, `extension_range.h`, `enum_reserved_range.h`, `message_reserved_range.h` | per-def accessors (name/number/count/index) | Remaining descriptor objects; `file_def` aggregates `upb_FileDef` (symtab root) |
| `desc_state.h`, `common.h`, `descriptor_bootstrap.h` | `upb_DescState` (string-buffer builder), `upb_WellKnown`, `upb_FieldMode` re-exports, bootstrap defs of descriptor.proto | Shared reflection internals |
| `internal/def_builder.h` | `upb_DefBuilder` context | The descriptor→def compiler engine shared by `AddFile` and upb_generator |

## 8. upb/json/, upb/text/, upb/lex/ — text formats + parsing helpers

| File | Key public functions | Role |
|---|---|---|
| `upb/json/decode.h` | `upb_JsonDecode_IgnoreUnknown` (:25), `upb_JsonDecodeDetectingNonconformance` (:32), `upb_JsonDecode` (:37) | JSON → message (needs reflection `upb_MessageDef` + `upb_DefPool` for extensions) |
| `upb/json/encode.h` | `upb_JsonEncode` (:40) | Message → JSON |
| `upb/text/encode.h` | `upb_TextEncode` (:29) | Message → text format (conformance + python/php/ruby) |
| `upb/text/debug_string.h` | `upb_DebugString` (:33) | Field-number/value dump used by Rust `Debug` (impl `debug_string.c:206`) |
| `upb/text/internal/encode.h` | text encoder internals | Same machinery as `upb_TextEncode` |
| `upb/text/options.h` | `UPB_TXTENC_SINGLELINE` (:13), `SKIPUNKNOWN` (:16), `NOSORT` (:19) | Text-encode flags |
| `upb/lex/atoi.h` | base-100 atoi helpers | Integer parsing (JSON) |
| `upb/lex/round_trip.h` | float round-trip | Correct float printing (JSON) |
| `upb/lex/unicode.h` | surrogate-pair helpers `upb_Unicode_IsHigh/IsLow/ToHigh/ToLow/FromPair` (:21-44) | UTF-16 ↔ code point |

## 9. upb/hash/, upb/util/, upb/port/

| File | Key types/functions | Role |
|---|---|---|
| `upb/hash/common.h` | `upb_table`, `upb_tabent` (:125) | Core open-addressing table (map.c, def_pool, extension registry) |
| `upb/hash/int_table.h` | `upb_IntTable` (:20) | Int-keyed table (field number lookups, def pool by number) |
| `upb/hash/str_table.h` | `upb_StrTable` (:22), `upb_StrTable_Entry` (:126) | String-keyed table (names in def pool, mini descriptor strings) |
| `upb/hash/ext_table.h` | `upb_ExtTable` (:20) | Extension-keyed table (extension registry) |
| `upb/util/def_to_proto.h` | def→`FileDescriptorProto` converters | Python/php/ruby descriptor export; conformance descriptor tests |
| `upb/util/required_fields.h` | `upb_util_HasUnsetRequired` (:68), `upb_FieldPath_ToText` (:57) | Post-parse required-field validation (JSON/text paths) |
| `upb/port/port.c` | thread-local allocation count + OOM fail-on | Fault injection for OOM tests |
| `upb/port/atomic.h` | `_upb_Atomic_*` (:142-289) | Portability atomics (arena fuse refcounts) |
| `upb/port/overflow.h` | checked arithmetic | Size computations in encoder/decoder |

## 10. upb/generated_code_support.h — the generated-code-facing umbrella

Not a function list but a curated include set with a fasttable gate:

- Two-part include dance for `UPB_FASTTABLE` → `UPB_INCLUDE_FAST_DECODE` (:17-21, :44-46).
- Exports (:24-43): `upb/base/upcast.h`, `upb/message/{accessors,array,map_gencode_util,message}.h`, `upb/message/internal/{accessors,array,extension,message}.h`, `upb/mini_descriptor/decode.h`, `upb/mini_table/{enum,extension,extension_registry,field,file,message,sub}.h`, `upb/mini_table/internal/generated_registry.h`, `upb/wire/{decode,encode}.h`, and `upb/wire/decode_fast/field_parsers.h` when fasttable is on.

The actual functions generated C code calls live in `upb/message/internal/accessors.h` (`_upb_Message_GetHasbit` :65, `_upb_Message_SetHasbit` :78, `_upb_Message_OneofCasePtr` :96, `_upb_Message_SetPresence` :167, `_upb_MiniTableField_DataCopy/DataEquals/DataClear/DataIsZero` :176-224, `_upb_Message_IsInitializedShallow` :148), `upb/message/internal/array.h` (`_upb_Array_New` :97, `_upb_Array_TryFastNew` :103, `_upb_Array_TryFastRealloc` :114, `_upb_Array_ResizeUninitialized` :135), and `upb/message/map_gencode_util.h`.

## 11. upb_generator/ — the C code generator (protoc plugins)

| Entry point | Emits | Notes |
|---|---|---|
| `upb_generator/c/generator.cc` | `foo.upb.c` + `foo.upb.h` | Main at :1441; `GenerateFile` :1351; source name = `StripExtension(file) + ".upb.c"` (:113). Emits: message structs (with embedded `upb_Message base`), typed accessors (`GenerateMessageFunctionsInHeader` :465, `GenerateGetters/Setters` :752/:928, hazzers :562, oneof cases :514, map getters :602), mini-descriptor initializers (`WriteMessageMiniDescriptorInitializer` :1272, `WriteEnumMiniDescriptorInitializer` :1296, `WriteResolveCalls` :1236) |
| `upb_generator/minitable/generator.cc` + `main.cc` | `foo.upb_minitable.h` + `foo.upb_minitable.c` | Source name = `+ ".upb_minitable.c"` (main.cc:27). Emits static `upb_MiniTable` initializers directly (no mini_descriptor decode at runtime): per-message `upb_MiniTable` with fields (`WriteSingleFieldInSource` :76), `kUpb_ExtMode_*` (:231-237), one-file `upb_MiniTableFile` |
| `upb_generator/reflection/generator.cc` | `foo.upbdefs.h`/`.c` | Reflection defs (used by conformance_upb, python/php/ruby) |
| `upb_generator/plugin.cc` | shared `PopulateDefPool` (:36-70) | Feeds `FileDescriptorProto` → upb defs for all generators |
| `upb_generator/file_layout.cc/h` | source layout helpers | File-level grouping; `upb_generator/common/*` name mangling |

## 12. upb/conformance/conformance_upb.c — the conformance runner

A stdin/stdout runner implementing the protobuf conformance protocol:
`CheckedRead/CheckedWrite` (:37/:56), `parse_proto` (binary via `upb_Decode`, :70), `serialize_proto` (`upb_Encode`, :84), `serialize_text` (`upb_TextEncode` with `UPB_TXTENC_SKIPUNKNOWN` honoring `print_unknown_fields`, :100), `parse_json`/`serialize_json` (:119/:145), `parse_input` dispatch on payload oneof (:174), `write_output` dispatch on requested output format (:192), `DoTest` (message-type dispatch over 4 generated def pools: proto2/proto3 + editions goldens, :216), `DoTestIo` (:253), `main` (:307). It does **not** implement jspb or text-parse (returns "Unsupported" paths at :184/:208).

---

## 13. Which components are required for what

| Capability | upb files involved | Notes |
|---|---|---|
| Core message representation | `upb/message/message.h`, `internal/message.h`, `internal/types.h`, `mem/arena.{h,c}`, `mini_table/message.h`, `mini_table/internal/message.h` | Tagged-ptr `upb_Message` + `aux_data[]`; inline data sized by minitable `size` |
| Binary decode | `wire/decode.{h,c}`, `wire/eps_copy_input_stream.{h,c}`, `wire/reader.h`, `wire/internal/decoder.{h,c}`, `wire/decode_fast/*`, `message/promote.c`, `mini_table/extension_registry.{h,c}`, `mem/arena`, `hash/ext_table.h` | General decoder + optional fasttable; extension registry; unknown→parsed promotion |
| Binary encode | `wire/encode.{h,c}`, `wire/internal/encoder.{h,c}`, `wire/byte_size.{h,c}`, `message/accessors.c`, `message/map_sorter.c`, `hash/*` | Deterministic option needs `_upb_mapsorter` |
| Mini tables | `mini_table/*`, `mini_descriptor/decode.c` | Read side + build side; minitable generator can bypass mini_descriptor |
| Mini descriptors | `mini_descriptor/decode.{h,c}`, `build_enum.{h,c}`, `link.{h,c}`, `internal/{base92,encode,decoder,modifiers,wire_constants}.h` | Compressed schema strings; base92 codec |
| Arenas | `mem/arena.{h,c}`, `mem/alloc.{h,c}`, `port/port.c`, `port/atomic.h` | Bump allocator + fuse/refcount lifetime graph + OOM injection |
| Maps | `message/map.{h,c}`, `hash/common.{h,c}`, `hash/int_table.h` | `upb_Map` = hash table over `upb_MessageValue` |
| Arrays | `message/array.{h,c}`, `message/internal/array.h` | Dense vectors |
| Reflection | `reflection/*` (def_pool, def_builder, message.c, all *def.c), `mini_descriptor/encode.h` | `AddFile` → defs + minitables |
| Descriptors (dynamic) | `reflection/*` + `util/def_to_proto.c` | Export path for wrappers |
| Extensions | `mini_table/extension.{h,c}`, `message/internal/extension.h`, `mini_table/extension_registry.{h,c}`, `message/promote.c`, `hash/ext_table.h` | Registry + aux_data storage + promotion |
| JSON | `json/decode.{h,c}`, `json/encode.{h,c}`, `lex/*`, `reflection/*` | Reflection-dependent |
| Text | `text/encode.{h,c}`, `text/debug_string.{h,c}`, `text/internal/encode.h`, `text/options.h`, `reflection/*` | `upb_TextEncode` + `upb_DebugString` (Rust Debug) |
| Generated C code | `generated_code_support.h` + `message/internal/{accessors,array,extension,message}.h` + `mini_table/internal/generated_registry.h` + `upb_generator/*` | The .upb.h/.upb.c/.upb_minitable.h/.upb_minitable.c contract |
| **Official Rust upb kernel** | `rust/upb_kernel/*` (9 files), `rust/upb/*`, `rust/upb/sys/*` (+ `sys/upb_api.c`), `upb/mem`, `upb/message/{accessors,array,compare,copy,map,merge}.h`, `upb/mini_descriptor/decode.h`, `upb/mini_table/message.h`, `upb/text/debug_string.h`, `upb/wire/byte_size.h` | The exact C surface is `rust/upb/sys/upb_api.c:13-25`; detailed in KERNEL_ATLAS.md |
| Python/php/ruby integrations | `python/*`, `php/*`, `ruby/*` use reflection + JSON/text + def_to_proto; amalgamations `upb/BUILD:208-333` (`upb.c`, `php-upb.c`, `ruby-upb.c`) | Not part of the Rust milestone |
| Tests | `upb/test/*`, `upb/**/*_test.cc`, `conformance/` | Oracle harnesses |
| Conformance | `upb/conformance/conformance_upb.c` | Runner described in §12 |
| Generators | `upb_generator/*` | §11 |

---

### Verification notes

- All line numbers above were read directly from the pinned tree at commit `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`.
- `rust/upb_kernel/` contains **9** files in the pinned tree (mod, message, minitable, repeated, map, string, extension, conversions, interop), not 10; see KERNEL_ATLAS.md §6.
- `upb/port/def.inc`/`undef.inc` are included at the end of nearly every header (the macro dance); they are not listed per-file above.
- Reflection `internal/` also contains `upb_edition_defaults.h` (edition defaults blob) and `strdup2.{h,c}` — edition handling + arena strdup used by def_builder.
