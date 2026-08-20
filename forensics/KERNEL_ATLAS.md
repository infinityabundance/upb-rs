# KERNEL_ATLAS — roadmap for a pure-Rust kernel behind the official Rust protobuf API

Oracle: `third_party/protobuf` @ `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`. All paths relative to that tree. `rust/…` = `third_party/protobuf/rust/…`, `upb/…` = `third_party/protobuf/upb/…`. Line numbers read from the pinned tree; unverified items in §6.

## 0. Call-graph topology (read this first)

The `upb_kernel` Rust code never touches C directly. There are three layers:

```
rust/upb_kernel/*.rs        (trait impls: Singular, MapValue, Serialize, CopyFrom, …)
        │  calls upb::* re-exports (rust/upb_kernel/mod.rs:19-26, :48-56)
rust/upb/*.rs               (safe-ish wrappers: Arena, MessagePtr<T>, wire::encode, …)
        │  rust/upb/lib.rs:34-70 re-exports from sys
rust/upb/sys/*.rs           (extern "C" declarations + repr(C) mirrors)
        │  linked against
C upb                       (symbols force-exported by rust/upb/sys/upb_api.c:13-25:
        │   upb/mem/arena.h, message/{accessors,array,compare,copy,map,merge}.h,
        │   mini_descriptor/decode.h, mini_table/message.h, text/debug_string.h,
        │   wire/byte_size.h — compiled with UPB_BUILD_API)
```

In Cargo builds (`#[cfg(not(bzl))]`) the `upb` crate is inlined as a module: `shared.rs:75-77` (`#[path = "upb/lib.rs"] mod upb;`); `upb_kernel/mod.rs:43-46` picks `extern crate upb` vs `crate::upb`. **A pure-Rust kernel is a drop-in for the bottom two layers**: it must satisfy every symbol the kernel + API touch (listed below), behind the same `sys` module shape, and keep the `upb_kernel` layer compiling unchanged.

---

## 1. Kernel contract — every C upb function/type the Rust kernel calls

Grouped by domain. Citation format: `call-site rust file:line` → `extern decl (sys file:line)` → what it is needed for. († = called indirectly via `rust/upb/*`.)

### 1.1 Arena
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_Arena_New` | `rust/upb/arena.rs:57` | `rust/upb/sys/mem/arena.rs:22` | Owned message/repeated/map/string construction (`OwnedMessageInner::new`, `repeated_new`, `map_new`, `InnerProtoString`) |
| `upb_Arena_Free` | `rust/upb/arena.rs:185` (Drop) | `sys/mem/arena.rs:23` | Arena lifetime end — the entire ownership model |
| `upb_Arena_Malloc` | `rust/upb/arena.rs:86` (`Arena::alloc`) | `sys/mem/arena.rs:24` | String/bytes copies (`copy_slice_in`), all arena allocation from Rust |
| `upb_Arena_Fuse` | `rust/upb/arena.rs:164` (`Arena::fuse`) | `sys/mem/arena.rs:25` | Child-into-parent arena lifetime extension on every set (see §3) |
| type `upb_Arena` | — | opaque pointee `sys/mem/arena.rs:12` | `RawArena = NonNull<upb_Arena>` (:13); `UPB_MALLOC_ALIGN = 8` (:16) is a hard alignment contract |

### 1.2 Message
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_Message_New` | `rust/upb/message.rs:76` | `sys/message/message.rs:27` | Construct owned message from minitable |
| `upb_Message_Clear` | `rust/upb/message.rs:89` | `sys/message/message.rs:32` | `Clear::clear` (`upb_kernel/message.rs:368-372`) and `clear_and_parse` (:382) |
| `upb_Message_ClearBaseField` | `rust/upb/message.rs:113` | `sys/message/message.rs:37` | Per-field clear |
| `upb_Message_DeepCopy` | `rust/upb/message.rs:97`; `upb_kernel/message.rs:451` (CopyFrom) | `sys/message/message.rs:49` | `CopyFrom::copy_from` |
| `upb_Message_DeepClone` | `rust/upb/message.rs:104`; `upb_kernel/conversions.rs:94` (repeated copy) | `sys/message/message.rs:59` | Clone; array element deep-copy |
| `upb_Message_Get{Bool,Int32,Int64,UInt32,UInt64,Float,Double,String}` | `rust/upb/message.rs:46-48` (macro) | `sys/message/message.rs:68-107` | Typed scalar getters |
| `upb_Message_SetBaseField{Bool,Int32,Int64,UInt32,UInt64,Float,Double,String}` | `rust/upb/message.rs:54-56` (macro); decls `sys/message/message.rs:226-261` | Typed scalar setters |
| `upb_Message_GetMessage` | `rust/upb/message.rs:132` | `sys/message/message.rs:117` | Submessage view (None ⇒ default/empty) |
| `upb_Message_SetBaseFieldMessage` | `rust/upb/message.rs:146`; via `message_set_sub_message` `upb_kernel/message.rs:504` | `sys/message/message.rs:266` | Submessage set (after arena fuse) |
| `upb_Message_GetOrCreateMutableMessage` | `rust/upb/message.rs:162` | `sys/message/message.rs:128` | `get_or_create_mutable_message_at_index` |
| `upb_Message_GetArray` | `rust/upb/message.rs:173` | `sys/message/message.rs:142` | Repeated view |
| `upb_Message_GetOrCreateMutableArray` | `rust/upb/message.rs:201` | `sys/message/message.rs:152` | Repeated mut |
| `upb_Message_GetMap` | `rust/upb/message.rs:212` | `sys/message/message.rs:166` | Map view |
| `upb_Message_GetOrCreateMutableMap` | `rust/upb/message.rs:241` | `sys/message/message.rs:177` | Map mut (needs `map_entry_mini_table` from `upb_MiniTable_SubMessage` :240) |
| `upb_Message_SetBaseField` | `rust/upb/message.rs:186` (array), :224 (map) | `sys/message/message.rs:194` | Store a `upb_Array*`/`upb_Map*` **by pointer address** (val = `&ptr`; C copies via `_upb_MiniTableField_DataCopy`, `upb/message/internal/accessors.h:323-331`) |
| `upb_Message_HasBaseField` | `rust/upb/message.rs:121` | `sys/message/message.rs:187` | Presence test |
| `upb_Message_WhichOneofFieldNumber` | `rust/upb/message.rs:258` | `sys/message/message.rs:274` | Oneof case query |
| `upb_Message_IsEqual` | `upb_kernel/message.rs:321,344` (message_eq / partial) | `sys/message/message.rs:203` | `MatcherEq` for tests; compare options (1<<1 partial) |
| `upb_Message_MergeFrom` | `upb_kernel/message.rs:470` | `sys/message/message.rs:215` | `MergeFrom::merge_from` (C impl = encode+decode round-trip, `upb/message/merge.c:14-31`) |
| type `upb_Message` | — | opaque pointee `sys/message/message.rs:21`; `RawMessage = NonNull<upb_Message>` (:22) | The single opaque message handle |

### 1.3 Mini table
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_MiniTable_Build` | `upb_kernel/minitable.rs:37` | `sys/mini_table/mini_table.rs:92` | Static-init: build table from mini-descriptor string into `THREAD_LOCAL_ARENA` (`upb_kernel/mod.rs:74-78`) |
| `upb_MiniTableEnum_Build` | `upb_kernel/minitable.rs:50` | `sys/mini_table/mini_table.rs:105` | Enum tables from enum mini descriptors |
| `upb_MiniTableExtension_Build` | `upb_kernel/minitable.rs:67` | `sys/mini_table/mini_table.rs:118` | Extension tables from extension mini descriptors |
| `upb_MiniTableExtension_SetSubMessage` / `SetSubEnum` | `upb_kernel/minitable.rs:77,80` | `sys/mini_table/mini_table.rs:129,134` | Link extension sub-tables post-build |
| `upb_MiniTable_Link` | `upb_kernel/minitable.rs:95` (`link_mini_table`) | `sys/mini_table/mini_table.rs:151` | Link message sub-tables/sub-enums post-build (order from `GetSubList`) |
| `upb_MiniTable_GetFieldByIndex` | `rust/upb/message.rs:47,55,112,120,130,145,159,172,182,200,211,220,239,257` | `sys/mini_table/mini_table.rs:76` | **The** field-lookup primitive: every accessor resolves `index → upb_MiniTableField*` in C |
| `upb_MiniTable_SubMessage` | `rust/upb/message.rs:240` | `sys/mini_table/mini_table.rs:82` | Map-entry minitable for `GetOrCreateMutableMap` |
| `upb_MiniTable_FindFieldByNumber` | **not called from kernel code** (declared `#[allow(unused)]`, `sys/mini_table/mini_table.rs:58-67`; only link-tested :168) | — | Reserved for future use |
| types `upb_MiniTable{,Enum,Field,Extension}` | — | `sys/mini_table/mini_table.rs:17-55` | All opaque; `RawMiniTable`/`RawMiniTableEnum` are `#[repr(transparent)]` `NonNull` wrappers; `RawMiniTableField = NonNull` (:48) |

### 1.4 Repeated / array
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_Array_New` | `upb_kernel/repeated.rs:53`; `extension.rs:225` | `sys/message/array.rs:23` | `repeated_new`; repeated-extension creation |
| `upb_Array_Size` | `repeated.rs:63,162`; `conversions.rs:85,172,284` | `sys/message/array.rs:24` | `repeated_len`, reserve, copy |
| `upb_Array_Append` | `repeated.rs:75` | `sys/message/array.rs:27` | `repeated_push` |
| `upb_Array_Resize` | `repeated.rs:89`; `conversions.rs:86,173,286` | `sys/message/array.rs:28` | `repeated_clear`, copy_from |
| `upb_Array_Reserve` | `repeated.rs:163` | `sys/message/array.rs:29` | `repeated_reserve` |
| `upb_Array_Get` | `repeated.rs:100`; `conversions.rs:91` | `sys/message/array.rs:26` | `repeated_get_unchecked` |
| `upb_Array_GetMutable` | `repeated.rs:119` | `sys/message/array.rs:32` | `repeated_get_mut_unchecked` (message arrays) |
| `upb_Array_Set` | `repeated.rs:133`; `conversions.rs:96` | `sys/message/array.rs:25` | `repeated_set_unchecked`, deep-copy loop |
| `upb_Array_DataPtr` / `MutableDataPtr` | `conversions.rs:177-178,289-291` | `sys/message/array.rs:30-31` | Bulk `copy_nonoverlapping` for scalars; `PtrAndLen` array copy for strings/bytes |
| type `upb_Array` | — | opaque pointee `sys/message/array.rs:19`; `RawArray = NonNull<upb_Array>` (:20) | Repeated handle |

### 1.5 Map
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_Map_New` | `upb_kernel/map.rs:126` | `sys/message/map.rs:34` | `map_new` (key/value CType) |
| `upb_Map_Clear` | `map.rs:137` | `sys/message/map.rs:49` | `map_clear` |
| `upb_Map_Size` | `map.rs:142` | `sys/message/map.rs:35` | `map_len` |
| `upb_Map_Insert` | `map.rs:153` | `sys/message/map.rs:36-41` | `map_insert`; `MapInsertStatus` enum (:25-29) |
| `upb_Map_Get` | `map.rs:176` | `sys/message/map.rs:42` | `map_get` (out-param `upb_MessageValue`) |
| `upb_Map_GetMutable` | `map.rs:192` | `sys/message/map.rs:43` | `map_get_mut` (message values) |
| `upb_Map_Delete` | `map.rs:202` | `sys/message/map.rs:44-48` | `map_remove` |
| `upb_Map_Next` | `map.rs:114` (`RawMapIter::next_unchecked`) | `sys/message/map.rs:50-55` | `map_iter`/`map_iter_next`; `UPB_MAP_BEGIN = usize::MAX` (:31) |
| type `upb_Map` | — | opaque pointee `sys/message/map.rs:19`; `RawMap = NonNull` (:20) | Map handle |

### 1.6 String / bytes
No direct C calls in `upb_kernel/string.rs`; strings are arena-backed through:
- `Arena::copy_slice_in` (`rust/upb/arena.rs:140-154` → `upb_Arena_Malloc`) — `InnerProtoString::from` (`upb_kernel/string.rs:26-35`).
- `OwnedArenaBox` (`rust/upb/owned_arena_box.rs:22-51`) pairs a `NonNull<T>` with its `Arena`; `into_raw_parts` returns `(PtrAndLen, Arena)` (`string.rs:20-23`).
- `PtrAndLen = upb::StringView` (`upb_kernel/mod.rs:66`) — must be exactly `{ptr,len}` (`sys/base/string_view.rs`).
- String views returned by `upb_Message_GetString` are wrapped into `ProtoStr::from_utf8_unchecked` (`conversions.rs:260`).

### 1.7 Extensions
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_ExtensionRegistry_New` | `upb_kernel/extension.rs:49` | `sys/mini_table/extension_registry.rs:34` | Build generated extension registry (lazily, into `THREAD_LOCAL_ARENA`) |
| `upb_ExtensionRegistry_Add` | `extension.rs:51` | `sys/mini_table/extension_registry.rs:35-39` | Register all `linkme`-collected extensions; `ExtensionRegistryStatus` enum (:26-30) |
| `upb_Message_HasExtension` | `extension.rs:64,137` | `sys/message/message.rs:278` | `ExtHas::has`; get_mut probe |
| `upb_Message_GetExtension{Message,Bool,Float,Double,Int32,String,Int64,UInt32,UInt64}` | `extension.rs:83,142,177,248-253 (macro),292,332,391` | `sys/message/message.rs:290-391` | `ExtAccess::get` per type |
| `upb_Message_GetExtensionArray` | `extension.rs:177` | `sys/message/message.rs:400` | Repeated extension view |
| `upb_Message_GetExtensionMutableArray` | `extension.rs:219` | `sys/message/message.rs:405` | Repeated extension mut |
| `upb_Message_SetExtension{Message,Bool,Float,Double,Int32,String,Int64,UInt32,UInt64}` | `extension.rs:111,259-264 (macro),312,352,408` | `sys/message/message.rs:283-398` | `ExtAccess::set` per type |
| `upb_Message_SetExtension` | `extension.rs:227` | `sys/message/message.rs:410` | Store a fresh `upb_Array*` into a repeated extension (val = `&ptr`) |
| `upb_Message_ClearExtension` | `extension.rs:368` | `sys/message/message.rs:276` | `ExtClear::clear` |
| types `upb_ExtensionRegistry` | — | opaque pointee `sys/mini_table/extension_registry.rs:17`; `RawExtensionRegistry` (:20) | Registry handle |

### 1.8 Conversions / interop
- No new C symbols; `conversions.rs` is the type-erasure layer over `upb_MessageValue` (`sys/message/message_value.rs:17-34`, `#[repr(C)]` union) and the array/message functions already listed.
- `interop.rs` has **zero** C calls: `OwnedMessageInterop`/`MessageMutInterop` are empty marker traits (:19-34); `MessageViewInterop::__unstable_wrap_raw_message*` just casts `*const c_void` → `RawMessage` (:40-52).

### 1.9 Wire / text / debug
| Symbol | Call site | Decl | Needed for |
|---|---|---|---|
| `upb_Encode` | `rust/upb/wire.rs:33` (→ `Serialize::serialize`, `upb_kernel/message.rs:420`) | `sys/wire/wire.rs:49-56`; `EncodeStatus` (:21-27) | Serialize; options=0 always |
| `upb_Decode` | `rust/upb/wire.rs:96` (→ `clear_and_parse_helper`, `upb_kernel/message.rs:388`) | `sys/wire/wire.rs:63-71`; `DecodeStatus` (:34-41) | Parse with `CHECK_REQUIRED`(2) or 0; `decode_options` consts `wire.rs:14-21` |
| `upb_ByteSize` | `rust/upb/wire.rs:50` (→ `Serialized_len`, `upb_kernel/message.rs:424`) | `sys/wire/wire.rs:76` | `serialized_len` |
| `upb_DebugString` | `rust/upb/text.rs:25,33` (→ `debug_string`, `upb_kernel/mod.rs:58-62`) | `sys/text/text.rs:24-30` | `Debug` formatting |

### 1.10 Enums
No C calls for open enums (values carried as `i32` in `upb_MessageValue`). Closed-enum minitables are built (`upb_MiniTableEnum_Build`) but enum validation in the kernel is Rust-side (`conversions.rs:121-128` `try_from`). `AssociatedMiniTableEnum` (`rust/upb/associated_mini_table.rs:33`) is the marker. **unverified**: whether any current code path actually consults the enum mini table for validation (see §6).

---

## 2. Kernel abstractions — the Rust-side trait surface the API/codegen depends on

Shared (kernel-agnostic) layer, `rust/` (files listed in `rust/BUILD:66-82` `PROTOBUF_SHARED`):

| Trait / type | Defined at | Role |
|---|---|---|
| `Proxied { type View<'msg> }` | `proxied.rs:54-59` | Every field type's "borrowed" form |
| `MutProxied { type Mut<'msg> }` | `proxied.rs:67-73` | "mutable borrow" form |
| `View<'msg,T>`, `Mut<'msg,T>` aliases | `proxied.rs:79,86` | Public sugar |
| `AsView` / `IntoView` / `AsMut` / `IntoMut` / `IntoProxied` | `proxied.rs:93-116,139-168,192-197,210-236,256-259` | The 5 conversion verbs; blanket impls for `&T`/`&mut T`; `IntoProxied` is the kernel's "materialize owned value" hook |
| `EntityType { type Tag }` + `entity_tag::{Message,Enum,Primitive,ViewProxy,MutProxy,Repeated}Tag` | `codegen_traits.rs:112-135` | Blanket-impl dispatch (e.g. singular vs map-value) |
| `MessageType` | `codegen_traits.rs:31-32` | Tag guard `Tag = MessageTag` |
| `Message`, `MessageView<'msg>`, `MessageMut<'msg>` | `codegen_traits.rs:35-106` | The three generated-code entry traits; each lists required supertraits (Parse, Serialize, Clear, ClearAndParse, TakeFrom, CopyFrom, MergeFrom, KernelMessage*…) |
| `create::Parse` | `codegen_traits.rs:139-161` | `parse` = `default()` + `clear_and_parse` |
| `read::Serialize` | `codegen_traits.rs:169-173` | `serialize()`, `serialized_len()` |
| `write::{Clear, ClearAndParse, CopyFrom, TakeFrom, MergeFrom}` | `codegen_traits.rs:182-213` | Mutation verbs; blanket impls live in the kernel (`upb_kernel/message.rs:368-479`) |
| `Singular` (unsafe) | `singular.rs:27-92` | `repeated_new/free/len/push/clear/get_unchecked/get_mut_unchecked/set_unchecked/copy_from/reserve` — implemented per-type in kernel |
| `MapKey`, `MapValue` | `map.rs:16-73` (`MapKey` re-export of kernel trait at `upb_kernel/mod.rs:72`) | `map_new/free/clear/len/insert/get/get_mut/remove/iter/iter_next` |
| `Repeated`/`RepeatedView`/`RepeatedMut` | `repeated.rs:28,127,~300` | Owned/view/mut proxies wrapping `InnerRepeated`/`InnerRepeatedMut` (`upb_kernel/repeated.rs:6-44`) |
| `Map`/`MapView`/`MapMut` | `map.rs:75-215` | Wrap `InnerMap`/`InnerMapMut` (`upb_kernel/map.rs:52-93`) |
| `Enum`, `UnknownEnumValue` | `enum.rs` (re-export `shared.rs:34`) | `try_from`/`from` for enums |
| `ProtoBytes`, `ProtoString`, `ProtoStr`, `Utf8Error` | `string.rs` (re-export `shared.rs:37`) | Wrap `InnerProtoString` (`upb_kernel/string.rs:12-24`) |
| `ExtensionId` + `ExtHas`/`ExtClear`/`ExtAccess`/`ExtGetMut` | `extension.rs:27-98` | Public extension API; kernel implements the `Ext*` traits (`upb_kernel/extension.rs:58-416`) |
| `Private`, `SealedInternal`, `MatcherEq` | `internal.rs:39-59` | Sealing + doc-hidden plumbing |
| `proto!` proc macro | `shared.rs:38`, `rust/protobuf_macros/` | Codegen entry (`proto_proc`) |

Kernel-side glue (`upb_kernel/`):
| Trait | Defined at | Role |
|---|---|---|
| `KernelMessage` / `KernelMessageView<'msg>` / `KernelMessageMut<'msg>` | `message.rs:239-284` | Super-traits of the `Message*` traits; tie `AssociatedMiniTable` + pointer access + interop together |
| `UpbGetMessagePtr` / `UpbGetMessagePtrMut` / `UpbGetArena` | `message.rs:217-237` | How any view/mut hands its `MessagePtr<T>` / `&Arena` to the kernel |
| `UpbTypeConversions<Tag>` | `conversions.rs:4-38` | `upb_type()` (CType), `to/from_message_value`, `into_message_value_fuse_if_required`, `from_message_mut`, `copy_repeated` |
| `AssociatedMiniTable` (unsafe) | `rust/upb/associated_mini_table.rs:28-30` | `fn mini_table() -> RawMiniTable`; implemented by generated code; invariant: 'static non-null constant |

Delegation example (proving the kernel is the only layer that knows storage): `Repeated::new()` (`repeated.rs:41-43`) → `T::repeated_new(Private)` → blanket `Singular` impl (`upb_kernel/repeated.rs:50-55`) → `upb_Array_New(arena.raw(), T::upb_type())`. Generated code calls through `__internal::runtime` (`internal.rs:25-35`), never directly at C.

---

## 3. FFI and layout assumptions

1. **`upb_Message` is a tagged pointer, not a struct.** `struct upb_Message { uintptr_t internal; }` (`upb/message/internal/types.h:25-30`); bit 0 = frozen, rest = `upb_Message_Internal*` (`upb/message/internal/message.h:226-232`, `{size, capacity, aux_data[]}` of `upb_TaggedAuxPtr`). Scalar/repeated/map field data lives in the minitable-sized region *following* the `upb_Message` word; the Rust side never sees it.
2. **The zero-message trick.** `ScratchSpace` 64 KiB zeroed static block is used as the default `MessageView` (`upb_kernel/message.rs:185-212`). Valid only because a zeroed message (tagged ptr = 0 ⇒ no internal, no aux) is a legitimately empty message for *any* minitable whose inline size ≤ 65536. A pure-Rust kernel must keep this property: **empty messages must be bitwise-zeroable**, and the default-view path must never mutate.
3. **Opaque mini tables.** `upb_MiniTable*`/`upb_MiniTableField*` are never dereferenced in Rust; the C side owns layout (`number/offset/presence/submsg_ofs/descriptortype/mode` bit-packing, `upb/mini_table/internal/field.h:21-35`; `upb_MiniTable` `{fields,size,field_count,ext,dense_below,table_mask,required_count,fasttable[]}`, `upb/mini_table/internal/message.h:71-94`). Rust only passes indices/numbers and receives field pointers back. A pure-Rust kernel can keep its own representation as long as `GetFieldByIndex/SubMessage` behave identically.
4. **`upb_MessageValue` is a `#[repr(C)]` union** (`sys/message/message_value.rs:17-34`) with the same member order as `upb/message/value.h:27-47`. `CType` values 1-11 (`sys/base/ctype.rs:12-24`) mirror `upb/base/descriptor_constants.h:18-30`. `EncodeStatus`/`DecodeStatus` values (0,1,3,10,11 / 0,1,2,3,10,11) mirror `upb/wire/encode.h:46-57` / `decode.h:86-100`.
5. **`upb_StringView` = `{const char* data; size_t size}`** (2 words; `upb/base/string_view.h:23-26`). Used as `PtrAndLen` for owned strings (`upb_kernel/mod.rs:66`) and as the default-extension value.
6. **Pointer-to-pointer setter ABI.** Repeated/map setters call `upb_Message_SetBaseField(msg, f, &array_ptr)` (`rust/upb/message.rs:183-187,221-225`); C copies one pointer-sized word per the field's `kUpb_FieldRep` (`upb/message/internal/accessors.h:323-331`). Same pattern for `upb_Message_SetExtension` (`accessors.h:333-344`). A pure-Rust kernel must accept the *address of* the container pointer.
7. **Arena ownership & fusing.** Every owned value pins its arena: `OwnedMessageInner{ptr, arena}` (`message.rs:5-8`), `InnerRepeated{raw, arena}` (`repeated.rs:6-9`), `InnerMap{raw, arena}` (`map.rs:52-55`), `InnerProtoString(OwnedArenaBox)` (`string.rs:12`). On any `set`, the child arena is **fused** into the parent before storing the pointer (`upb_kernel/message.rs:496,517,536,555,581`; `extension.rs:108,310,350`), so dropping the owned value is safe. `Arena::fuse` failure panics (`rust/upb/arena.rs:162-172`).
8. **`THREAD_LOCAL_ARENA` with `ManuallyDrop`** (`upb_kernel/mod.rs:74-78`): minitables + the generated extension registry are built once per thread into an arena that is never freed ⇒ effectively `'static`. `MiniTableInitPtr`/`ExtensionRegistryInitPtr` are `unsafe impl Send/Sync` to live in `OnceLock`/`LazyLock` statics (`upb_kernel/minitable.rs:6-25`).
9. **Type-erased empty containers.** `empty_array` reuses a static `Repeated<i32>` for every `T` (`repeated.rs:187-201`); `empty_map` reuses a static `Map<bool,bool>` (`map.rs:4-34`) — relying on an undocumented upb contract that a const empty map never reads key bytes beyond the smallest key size. A pure-Rust kernel must preserve that empty-view behavior (or the kernel must grow real per-type statics).
10. **Alignment.** `UPB_MALLOC_ALIGN = 8` (`sys/mem/arena.rs:16-18`); `Arena::alloc` asserts `align ≤ 8` (`rust/upb/arena.rs:84,105`). `ScratchSpace` is `#[repr(C, align(8))]` (`message.rs:194`).
11. **Lifetime contract.** Views carry no arena (pure `RawMessage`/`RawArray`/`RawMap` + `PhantomData`); muts carry `&'msg Arena`; several `get_mut` paths unsafely extend an `&Arena` borrow to `'msg` (`extension.rs:134,217`) — the C memory must stay alive for `'msg` (guaranteed by arena ownership in the containing message).

### Minimum pure-Rust kernel requirements (derived from the above)
- Message storage: inline field area sized per mini table + aux/extension/unknown region with equivalent "tagged aux" semantics (or an equivalent scheme the kernel fully controls — nothing in the Rust API observes the C layout).
- Presence: hasbits + oneof case storage per field descriptor (`presence` semantics, `upb/mini_table/internal/field.h:24`).
- Arena semantics: bump allocation, `fuse`, free-on-drop, alignment ≥ 8, allocation-count OOM injection (`upb_AllocationCount_*`, `upb/mem/alloc.h:114-121`).
- Mini table equivalents: field list, offsets, reps, sub-tables, dense_below/table_mask (decode dispatch), required_count; built from the same mini-descriptor strings (`upb_kernel/minitable.rs`) — the pure-Rust kernel can decode these strings itself.
- Accessor semantics: get-with-default, set-with-presence, get-or-create for message/array/map, oneof-case query, per-field clear.
- Container semantics: array resize/reserve/append/insert/delete; map insert/get/delete/iterate (insert-order iteration); string/bytes value copies (arena-backed).
- Whole-message ops: parse (with `CHECK_REQUIRED`/`ALWAYS_VALIDATE_UTF8` options), serialize (+ `serialized_len`), deep copy/clone, merge, equality (+ partial), clear, freeze (untouched by the kernel — **unverified** if any Rust path calls `upb_Message_Freeze`).
- Extensions: registry (add/lookup by number+extendee), get/set/has/clear per type incl. repeated.
- `upb_DebugString`-equivalent for `Debug`.

---

## 4. Build / selection mechanism (today)

Bazel:
- **Flag**: `string_flag(name="rust_proto_library_kernel", default="cpp", values=["upb","cpp"])` + `config_setting(name="use_upb_kernel", flag_values={…:"upb"})` — `rust/BUILD:371-386`.
- **User-facing alias**: `rust_proto_library` (macro, `defs.bzl:16-53`) declares *both* `name_upb_rust_proto` and `name_cpp_rust_proto` via `rust_upb_proto_library`/`rust_cc_proto_library` (`rules.bzl:111-131`, `_make_rust_proto_library`), then `native.alias` selects on `//rust:use_upb_kernel` (`defs.bzl:36-43`). Both kernels compile in one build (TAP runs both).
- **Crate wiring**: `protobuf_lite.rs:18-22` — `#[cfg(cpp_kernel)] use protobuf_cpp as kernel; #[cfg(upb_kernel)] use protobuf_upb as kernel;`. `internal.rs:30-35` — `#[cfg(all(bzl, cpp_kernel))] path="cpp_kernel/mod.rs"` else `path="upb_kernel/mod.rs"` (so **non-bzl/Cargo always uses upb_kernel**).
- **Runtime targets**: `rust/BUILD:32-42` (`protobuf`, rustc_flags select upb/cpp), `:44-57` (`protobuf_lite`), `:111-144` (`protobuf_upb`: `PROTOBUF_SHARED` + the 9 `upb_kernel/*.rs`, crate_root `shared.rs`, `--cfg=upb_kernel --cfg=bzl`, deps `//rust/upb` + `linkme`), `:185+` (`protobuf_cpp`). Gencode depends on the kernel-specific libs directly (BUILD comment :22-31).
- **FFI crate**: `rust/upb/BUILD:12-35` (`upb` rust_library) → `rust/upb/sys/BUILD` (`sys` rust_library + `upb_c_api` cc_library compiling `upb_api.c:11-25` against the 11 C headers listed in §0).
- **Cargo release**: `rust/release_crates/protobuf/Cargo-template.toml` (`links = "upb"` :12; lints allow `cfg(upb_kernel)` :32); `build.rs:8-18` compiles the amalgamated `libupb/upb/upb.c` + `utf8_range.c` with `UPB_BUILD_API` (amalgamation packaged from `:amalgamated_upb` + `upb/cmake:upb_cmake_dist`, `rust/BUILD:409-417`).

**Drop-in hook points for a pure-Rust kernel (upb-rs):**
1. Replace the `sys` crate's `extern "C"` bodies with Rust implementations behind the same module names (`sys/mem/arena.rs`, `sys/message/*`, `sys/mini_table/*`, `sys/wire/wire.rs`, `sys/text/text.rs`) — keep `opaque_pointee` types as handles.
2. Or replace `//rust/upb` + `//rust/upb/sys` deps with a pure-Rust crate exporting the same re-export surface as `rust/upb/lib.rs:34-70` (`Arena`, `MessagePtr`, `RawMiniTable`, `RawArray`, `RawMap`, `upb_*` fns…).
3. Either way `rust/upb_kernel/*` and `PROTOBUF_SHARED` compile unchanged; the `--cfg=upb_kernel` + `--cfg=bzl` wiring, `linkme` extension collection, and `release_crates` packaging all keep working.
4. The **Cargo path** (non-bzl) is the shortest integration target: it already hard-selects upb_kernel (`internal.rs:33-35`) and compiles C via `build.rs`; swapping `cc::Build` for a Rust module is a one-file change.

---

## 5. Integration gap analysis — operation → C function → Rust API → pure-Rust equivalent

| # | Operation | upb C function (pinned file:line) | Rust API that calls it | Minimal pure-Rust equivalent |
|---|---|---|---|---|
| 1 | Construct message | `upb_Message_New` `upb/message/message.c:34` | `MessagePtr::new` `rust/upb/message.rs:76` | Allocate inline region from arena sized by mini-table `size`; zero it |
| 2 | Get scalar | `upb_Message_GetInt32` etc. `upb/message/accessors.h:56-118` | scalar_accessors! `rust/upb/message.rs:46-48` | Read value at field `offset`; apply default if absent (no hasbit / not in oneof) |
| 3 | Set scalar | `upb_Message_SetBaseField*` `accessors.h:126-266` (impl `internal/accessors.h:323-331`) | `set_base_field_*_at_index` `message.rs:54-56` | Write at offset; set presence bit or oneof case (`_upb_Message_SetPresence` semantics, `internal/accessors.h:167-174`) |
| 4 | Get/set string | `upb_Message_GetString`/`SetBaseFieldString` `accessors.h:108-110,261` | getters/setters `message.rs:103-107,261`; `message_set_string_field` `upb_kernel/message.rs:510-525` | Store/fetch `{ptr,len}` at offset; setter fuses child arena first |
| 5 | Get/create submessage | `upb_Message_GetOrCreateMutableMessage` `accessors.h:105-106` | `get_or_create_mutable_message_at_index` `message.rs:154-164` | Return existing child or allocate+presence-set; child arena = parent arena |
| 6 | Repeated push | `upb_Array_Append` `upb/message/array.h:49` | `repeated_push` `upb_kernel/repeated.rs:66-84` | Grow element buffer (elem size from CType/rep), copy value in |
| 7 | Repeated get/set | `upb_Array_Get/Set/GetMutable` `array.h:39-46` | `repeated_get/set/mut_unchecked` `repeated.rs:92-142` | Index into data pointer; for messages, element = `upb_Message*` |
| 8 | Repeated copy | `upb_Array_Resize`+`upb_Message_DeepClone` (`conversions.rs:85-97`) | `copy_repeated` `conversions.rs:79-99` | Resize dest; deep-clone each message element into dest arena |
| 9 | Map insert | `upb_Map_Insert` `upb/message/map.h:55` | `map_insert` `upb_kernel/map.rs:145-167` | Hash key by CType; store `upb_MessageValue`; keep insertion order for iteration |
| 10 | Map get/remove/iter | `upb_Map_Get/GetMutable/Delete/Next` `map.h:40-89` | `map_get/mut/remove/iter*` `map.rs:169-218` | Lookup by hashed key; `Next` must iterate in insert order |
| 11 | Parse | `upb_Decode` `upb/wire/decode.c:1311` | `clear_and_parse_helper` `upb_kernel/message.rs:388` | Wire decoder honoring options (`CHECK_REQUIRED`=2, `ALWAYS_VALIDATE_UTF8`=8, `wire.rs:14-21`); unknown-field capture; extension registry lookups; depth limit |
| 12 | Serialize | `upb_Encode` `upb/wire/encode.c:25` | `Serialize::serialize` `upb_kernel/message.rs:420` | Field iteration in field-number order; varint/fixed/delimited encoders; unknowns appended; required-check |
| 13 | Serialized len | `upb_ByteSize` `upb/wire/byte_size.c:24` (encode into temp arena) | `serialized_len` `message.rs:424` | Size computation without emitting (or emit to scratch) |
| 14 | Clone | `upb_Message_DeepClone` `upb/message/copy.c:301` | `deep_clone` `message.rs:104` | Recursive deep copy onto target arena |
| 15 | CopyFrom | `upb_Message_DeepCopy` `copy.c:348` | `CopyFrom::copy_from` `upb_kernel/message.rs:451` | Clear dest + deep copy src |
| 16 | Clear | `upb_Message_Clear` `accessors.h:38` | `Clear::clear` `message.rs:89,368-372` | Zero inline region; free aux/unknowns (arena semantics) |
| 17 | Merge | `upb_Message_MergeFrom` `upb/message/merge.c:14` (**encode+decode roundtrip**) | `MergeFrom::merge_from` `upb_kernel/message.rs:470` | Roundtrip or direct merge; must match roundtrip observable behavior |
| 18 | Equality | `upb_Message_IsEqual` `upb/message/compare.c:241` | `message_eq`/`message_partially_eq` `upb_kernel/message.rs:321,344` | Field-wise compare incl. unknowns; partial option `1<<1` |
| 19 | Extension has/get/set | `upb_Message_{Has,Get,Set}Extension*` `accessors.h:176-415` | `ExtHas/ExtAccess/ExtGetMut` `upb_kernel/extension.rs:58-416` | Aux region keyed by `upb_MiniTableExtension*`; typed value storage; repeated ext get-or-create dance (:217-238) |
| 20 | Extension registry | `upb_ExtensionRegistry_{New,Add}` `upb/mini_table/extension_registry.h:71-81` | `generated_extension_registry` `extension.rs:47-56` | Linker-collected (`linkme`) list of extension minitables → lookup map |
| 21 | Mini table build | `upb_MiniTable{,_Enum,_Extension}_Build` `upb/mini_descriptor/decode.h:45-102`; `Link` `link.h:71` | `build_mini_table` etc. `upb_kernel/minitable.rs:35-103` | Decode mini-descriptor strings (base92) into kernel-native tables; link sub-tables |
| 22 | Field lookup | `upb_MiniTable_GetFieldByIndex` `upb/mini_table/message.h:29`; `SubMessage` :43 | every index-based accessor `rust/upb/message.rs` | Return kernel-native field handle from index (dense_below/tree-shaking aware) |
| 23 | Debug string | `upb_DebugString` `upb/text/debug_string.c:206` | `debug_string` `upb_kernel/mod.rs:58-62` | Text dump of field-number→value incl. unknowns |
| 24 | Arena ops | `upb_Arena_{New,Malloc,Free,Fuse}` `upb/mem/arena.h:49-63` | `Arena` `rust/upb/arena.rs` | Bump allocator + fuse graph + OOM injection (`upb_AllocationCount_*`) |

---

## 6. Unverified / needs confirmation

1. **"10 files" vs 9**: the brief says `rust/upb_kernel/*.rs` has 10 files; the pinned tree contains **9** (mod, message, minitable, repeated, map, string, extension, conversions, interop). No 10th file found.
2. **`upb_MiniTable_FindFieldByNumber`**: declared in `sys/mini_table/mini_table.rs:58-67` with `#[allow(unused)]`; I found no kernel call site (only the link test :168). Whether any generated code or future path uses it is unverified.
3. **Freeze**: no Rust call site for `upb_Message_Freeze`/`upb_Array_Freeze`/`upb_Map_Freeze` was found in `rust/`. Whether any API surface requires frozen semantics is unverified.
4. **Closed-enum validation**: `upb_MiniTableEnum_Build` is called, but I found no Rust call site that passes the enum table into a C validation function; enum validity appears enforced by Rust `try_from` only (`conversions.rs:121-128`). Whether the C decoder validates closed enums against the table during `upb_Decode` (affecting parity) is **not** confirmed from the Rust side.
5. **Fasttable**: whether oracle/Cargo builds enable `UPB_FASTTABLE` (affecting `upb_Decode` behavior/error ordering via `kUpb_DecodeOption_DisableFastTable`) is unverified for the upb-rs oracle build.
6. **Empty-map type-erasure contract** (`map.rs:4-34`): the claim "upb only hashes key bytes of the provided `upb_MessageValue`" for an empty `Map<bool,bool>` is an upstream comment, not a documented API guarantee.
7. **`upb_Message_MergeFrom` = encode+decode roundtrip** (`merge.c:14-31`): verified in source; the *observable* consequences (unknown-field merge order, extension handling) need differential confirmation.
8. **`message_set_repeated_field`/`message_set_map_field` aliasing** (`upb_kernel/message.rs:548-589`): the parent stores the child's container pointer directly after fusing; whether the child's `Arena` must outlive the parent's *fuse partner* or the parent itself in all paths was not exhaustively checked.
9. **Cargo build of the oracle** (`rust/release_crates/protobuf/build.rs`): the amalgamation layout (`libupb/upb/upb.c`) is packaged by Bazel (`rust/BUILD:409-417`); I did not verify the actual `upb.c` amalgamation file contents exist in the checkout (path was not present in the blob:none partial clone — see `third_party/PIN.md`).
10. **Rust-side `upb_Status`**: sys treats `upb_Status` as opaque and passes `null_mut()` at all call sites (`minitable.rs:41,54,72`); behavior when a mini-descriptor build fails is a Rust panic/assert, not a status read. Error-string parity for malformed mini descriptors is unverified.
11. **`THREAD_LOCAL_ARENA` drop-order**: minitables built in the thread-local arena are `ManuallyDrop`; `LazyLock<ExtensionRegistryInitPtr>` also lives in it. Interaction with `#[linkme]` extension sections across dynamic libraries is unverified (Linux `global_asm!` sentinels at `extension.rs:32-45`).
12. **rust/upb/sys `test_helpers.rs`**: exists but its role beyond tests is unverified.
