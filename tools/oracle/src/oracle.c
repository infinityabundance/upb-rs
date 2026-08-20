// upb-rs oracle server (Tier-1 behavioral oracle).
//
// Links against the pinned upstream libupb (see third_party/protobuf/PIN.md)
// and exposes the observable behavior of upb's primitive wire-reading surface
// through a versioned JSON-lines protocol. This is ORACLE TOOLING ONLY; it is
// never linked into, called from, or depended on by production Rust crates
// (charter §6).
//
// Protocol: one JSON object per line on stdin -> one JSON object per line on
// stdout. See tools/oracle/PROTOCOL.md for the full specification.
//
// The read pattern mirrors the upb message decoder exactly:
//   stream = Init(input)
//   if IsDone(&ptr)            -> EOF (no field present)
//   ptr = Read<X>(ptr, ...)    -> NULL means malformed
//   IsDone at the returned position distinguishes bounded vs unbounded
//   completion (the zero-padded patch buffer lets raw reads succeed past the
//   end of short inputs; the decoder then fails at the next IsDone).

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "upb/base/status.h"
#include "upb/mem/arena.h"
#include "upb/message/array.h"
#include "upb/message/map.h"
#include "upb/message/message.h"
#include "upb/message/unknown_fields.h"
#include "upb/mini_descriptor/decode.h"
#include "upb/mini_table/message.h"
#include "upb/wire/decode.h"
#include "upb/wire/encode.h"
#include "upb/wire/eps_copy_input_stream.h"
#include "upb/wire/reader.h"
#include "upb/wire/types.h"

#define MAX_LINE 65536
#define MAX_INPUT_BYTES 4096

// ---------------------------------------------------------------------------
// Minimal JSON field extraction for the fixed request shape we emit:
// {"v":1,"id":N,"op":"...","hex":"...","tag":N}
// We never parse arbitrary JSON; the corpus generator emits this exact shape.
// ---------------------------------------------------------------------------

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Returns number of decoded bytes, or -1 on malformed hex.
static int parse_hex(const char* s, size_t len, uint8_t* out, size_t cap) {
  uint8_t* base = out;
  size_t i = 0;
  while (i < len) {
    if ((size_t)(out - base) >= cap) return -1;
    int hi = hexval((unsigned char)s[i]);
    int lo = (i + 1 < len) ? hexval((unsigned char)s[i + 1]) : -1;
    if (hi < 0 || lo < 0) return -1;
    *out++ = (uint8_t)((hi << 4) | lo);
    i += 2;
  }
  return (int)(out - base);
}

// Extract the string value of a JSON field "name":"value".
static int json_string(const char* line, const char* name, char* out,
                       size_t cap) {
  size_t nlen = strlen(name);
  const char* p = strstr(line, name);
  if (!p) return -1;
  p += nlen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p != '"') return -1;
  p++;
  size_t o = 0;
  while (*p && *p != '"' && o + 1 < cap) out[o++] = *p++;
  if (*p != '"') return -1;
  out[o] = '\0';
  return (int)o;
}

// Extract the integer value of a JSON field "name":N.
static int json_int(const char* line, const char* name, int64_t* out) {
  size_t nlen = strlen(name);
  const char* p = strstr(line, name);
  if (!p) return -1;
  p += nlen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p == '-') return -1;  // ids/tags are non-negative
  char* end = NULL;
  long long v = strtoll(p, &end, 10);
  if (end == p) return -1;
  *out = (int64_t)v;
  return 0;
}

// Extract a JSON array of strings: "name":["a","b",...]. Each element is
// NUL-terminated into out[i]; returns the element count, or -1.
static int json_string_array(const char* line, const char* name,
                             char out[][MAX_INPUT_BYTES], int max) {
  size_t nlen = strlen(name);
  const char* p = strstr(line, name);
  if (!p) return -1;
  p += nlen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p != '[') return -1;
  p++;
  int count = 0;
  for (;;) {
    while (*p == ' ' || *p == ',') p++;
    if (*p == ']') break;
    if (*p != '"' || count >= max) return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < MAX_INPUT_BYTES) out[count][o++] = *p++;
    if (*p != '"') return -1;
    p++;
    out[count][o] = '\0';
    count++;
  }
  return count;
}

// Extract a JSON array of arrays of integers: "name":[[1,2],[3]]. Row i is
// written to out[i][0..len[i]); returns the row count, or -1.
static int json_int_array2(const char* line, const char* name,
                           int64_t out[][64], int* len, int max_rows) {
  size_t nlen = strlen(name);
  const char* p = strstr(line, name);
  if (!p) return -1;
  p += nlen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p != '[') return -1;
  p++;
  int rows = 0;
  for (;;) {
    while (*p == ' ' || *p == ',') p++;
    if (*p == ']') break;
    if (*p != '[' || rows >= max_rows) return -1;
    p++;
    int elems = 0;
    for (;;) {
      while (*p == ' ' || *p == ',') p++;
      if (*p == ']') {
        p++;
        break;
      }
      char* end = NULL;
      long long v = strtoll(p, &end, 10);
      if (end == p || elems >= 64) return -1;
      out[rows][elems++] = (int64_t)v;
      p = end;
    }
    len[rows] = elems;
    rows++;
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

// Maps a parse pointer back into input coordinates and reports the consumed
// byte count relative to the capture point. The capture must be taken before
// the operation; the mapping is applied immediately after the operation
// returns, BEFORE any subsequent IsDone() call (which may perform a fallback
// copy and rewrite input_delta, invalidating the mapping for pointers that
// still live in the original buffer).
static int64_t consumed_from(upb_EpsCopyInputStream* stream,
                             const char* end, const upb_EpsCopyCapture* capture) {
  const char* mapped =
      upb_EpsCopyInputStream_GetInputPtr_dont_copy_me__upb_internal_use_only(
          stream, end);
  return (int64_t)(mapped - capture->start);
}

static void emit_header(int64_t id, const char* status) {
  printf("{\"v\":1,\"id\":%" PRId64 ",\"status\":\"%s\"", id, status);
}

static void emit_end(void) { printf("}\n"); }

static void emit_field_str(const char* name, const char* value) {
  printf(",\"%s\":\"%s\"", name, value);
}

static void emit_field_u64(const char* name, uint64_t value) {
  printf(",\"%s\":\"%" PRIu64 "\"", name, value);
}

static void emit_field_int(const char* name, int64_t value) {
  printf(",\"%s\":%" PRId64, name, value);
}

static void emit_field_bool(const char* name, int value) {
  printf(",\"%s\":%s", name, value ? "true" : "false");
}

// ---------------------------------------------------------------------------
// Core read evaluation
// ---------------------------------------------------------------------------

// Runs a single primitive read against the pinned upb reader API and reports
// the full observable outcome: EOF, malformed, or ok(value, consumed, bounded).
//
// `read_fn` returns the position past the value, or NULL on malformed.
// `has_value` selects ops that produce a value field (skip ops do not).
typedef const char* (*read_fn)(const char* ptr, void* out,
                               upb_EpsCopyInputStream* stream);

static void run_primitive_read(int64_t id, const char* op, const char* hex,
                               read_fn fn, int has_value) {
  (void)op;
  uint8_t input[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  const char* ptr = (const char*)input;
  upb_EpsCopyInputStream stream;
  upb_EpsCopyInputStream_Init(&stream, &ptr, (size_t)n);

  if (upb_EpsCopyInputStream_IsDone(&stream, &ptr)) {
    emit_header(id, "eof");
    emit_end();
    return;
  }

  const char* start = ptr;
  uint64_t value = 0;
  const char* end = fn(ptr, &value, &stream);
  if (end == NULL) {
    emit_header(id, "error");
    emit_field_str("code", "malformed");
    emit_field_int("consumed", 0);
    emit_end();
    return;
  }

  const char* q = end;
  int done = upb_EpsCopyInputStream_IsDone(&stream, &q);
  int bounded = done ? !upb_EpsCopyInputStream_IsError(&stream) : 1;

  emit_header(id, "ok");
  if (has_value) {
    emit_field_u64("value", value);
  }
  emit_field_int("consumed", (int64_t)(end - start));
  emit_field_bool("bounded", bounded);
  emit_end();
}

static const char* read_varint_fn(const char* ptr, void* out,
                                  upb_EpsCopyInputStream* stream) {
  return upb_WireReader_ReadVarint(ptr, (uint64_t*)out, stream);
}

static const char* read_tag_fn(const char* ptr, void* out,
                               upb_EpsCopyInputStream* stream) {
  return upb_WireReader_ReadTag(ptr, (uint32_t*)out, stream);
}

static const char* read_size_fn(const char* ptr, void* out,
                                upb_EpsCopyInputStream* stream) {
  return upb_WireReader_ReadSize(ptr, (int*)out, stream);
}

static const char* read_fixed32_fn(const char* ptr, void* out,
                                   upb_EpsCopyInputStream* stream) {
  return upb_WireReader_ReadFixed32(ptr, (uint32_t*)out, stream);
}

static const char* read_fixed64_fn(const char* ptr, void* out,
                                   upb_EpsCopyInputStream* stream) {
  return upb_WireReader_ReadFixed64(ptr, (uint64_t*)out, stream);
}

static const char* skip_varint_fn(const char* ptr, void* out,
                                  upb_EpsCopyInputStream* stream) {
  (void)out;
  return upb_WireReader_SkipVarint(ptr, stream);
}

// skip_value / skip_group are handled separately because they take a tag and
// (for skip_value) need the tag to pick the wire type.
static void run_skip_value(int64_t id, const char* hex, uint32_t tag) {
  uint8_t input[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  const char* ptr = (const char*)input;
  upb_EpsCopyInputStream stream;
  upb_EpsCopyInputStream_Init(&stream, &ptr, (size_t)n);

  if (upb_EpsCopyInputStream_IsDone(&stream, &ptr)) {
    emit_header(id, "eof");
    emit_end();
    return;
  }

  upb_EpsCopyCapture capture;
  upb_EpsCopyCapture_Start(&capture, &stream, ptr);
  const char* end = upb_WireReader_SkipValue(ptr, tag, &stream);
  if (end == NULL) {
    emit_header(id, "error");
    emit_field_str("code", "malformed");
    emit_field_int("consumed", 0);
    emit_end();
    return;
  }

  // Consumed must be computed before the boundedness IsDone below (which may
  // perform a fallback copy and rewrite input_delta).
  int64_t consumed = consumed_from(&stream, end, &capture);
  const char* q = end;
  int done = upb_EpsCopyInputStream_IsDone(&stream, &q);
  int bounded = done ? !upb_EpsCopyInputStream_IsError(&stream) : 1;

  emit_header(id, "ok");
  emit_field_int("consumed", consumed);
  emit_field_bool("bounded", bounded);
  emit_end();
}

static void run_skip_group(int64_t id, const char* hex, uint32_t tag) {
  uint8_t input[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  const char* ptr = (const char*)input;
  upb_EpsCopyInputStream stream;
  upb_EpsCopyInputStream_Init(&stream, &ptr, (size_t)n);

  if (upb_EpsCopyInputStream_IsDone(&stream, &ptr)) {
    emit_header(id, "eof");
    emit_end();
    return;
  }

  upb_EpsCopyCapture capture;
  upb_EpsCopyCapture_Start(&capture, &stream, ptr);
  const char* end = upb_WireReader_SkipGroup(ptr, tag, &stream);
  if (end == NULL) {
    emit_header(id, "error");
    emit_field_str("code", "malformed");
    emit_field_int("consumed", 0);
    emit_end();
    return;
  }

  // Consumed must be computed before the boundedness IsDone below (which may
  // perform a fallback copy and rewrite input_delta).
  int64_t consumed = consumed_from(&stream, end, &capture);
  const char* q = end;
  int done = upb_EpsCopyInputStream_IsDone(&stream, &q);
  int bounded = done ? !upb_EpsCopyInputStream_IsError(&stream) : 1;

  emit_header(id, "ok");
  emit_field_int("consumed", consumed);
  emit_field_bool("bounded", bounded);
  emit_end();
}

// ---------------------------------------------------------------------------
// decode_empty: real upb_Decode into a message with an EMPTY (zero-field,
// non-extendable) mini table, so every field is an unknown field. This is the
// observable behavior of `_upb_Decoder_DecodeEmptyMessage`
// (upb/wire/decode.c:1205-1239) plus the encoder's unknown-field emission:
// on success we re-encode the message and return the bytes. Group recursion
// depth is bounded by `depth` (0 -> kUpb_WireFormat_DefaultDepthLimit = 100).
// ---------------------------------------------------------------------------

static void emit_hex_out(const char* buf, size_t len) {
  printf(",\"hex_out\":\"");
  for (size_t i = 0; i < len; i++) {
    printf("%02x", (unsigned char)buf[i]);
  }
  printf("\"");
}

static void run_decode_empty(int64_t id, const char* hex, int64_t depth) {
  uint8_t input[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  upb_Arena* arena = upb_Arena_New();
  if (!arena) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_end();
    return;
  }

  upb_Status status;
  upb_Status_Clear(&status);
  upb_MiniTable* mt = upb_MiniTable_Build("", 0, arena, &status);
  if (!mt) {
    emit_header(id, "error");
    emit_field_str("code", "minitable_build_failed");
    emit_field_str("msg", status.msg);
    emit_end();
    upb_Arena_Free(arena);
    return;
  }

  upb_Message* msg = upb_Message_New(mt, arena);
  if (!msg) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_end();
    upb_Arena_Free(arena);
    return;
  }

  int options = 0;
  if (depth > 0 && depth <= 65535) {
    options = (int)upb_DecodeOptions_MaxDepth((uint16_t)depth);
  }
  upb_DecodeStatus ds = upb_Decode((const char*)input, (size_t)n, msg, mt, NULL,
                                   options, arena);
  if (ds == kUpb_DecodeStatus_Ok) {
    size_t out_len = 0;
    char* out_buf = NULL;
    upb_EncodeStatus es = upb_Encode(msg, mt, 0, arena, &out_buf, &out_len);
    if (es != kUpb_EncodeStatus_Ok) {
      emit_header(id, "error");
      emit_field_str("code", "encode_failed");
      emit_end();
      upb_Arena_Free(arena);
      return;
    }
    emit_header(id, "ok");
    emit_hex_out(out_buf, out_len);
    emit_field_int("consumed", n);
    emit_end();
  } else if (ds == kUpb_DecodeStatus_Malformed) {
    emit_header(id, "error");
    emit_field_str("code", "malformed");
    emit_field_int("consumed", 0);
    emit_end();
  } else if (ds == kUpb_DecodeStatus_MaxDepthExceeded) {
    emit_header(id, "error");
    emit_field_str("code", "max_depth_exceeded");
    emit_field_int("consumed", 0);
    emit_end();
  } else if (ds == kUpb_DecodeStatus_OutOfMemory) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_field_int("consumed", 0);
    emit_end();
  } else {
    emit_header(id, "error");
    emit_field_str("code", "other");
    emit_field_int("code_num", (int64_t)ds);
    emit_end();
  }
  upb_Arena_Free(arena);
}

// ---------------------------------------------------------------------------
// mini_table_inspect: builds a mini table from a mini descriptor string via
// the pinned upb_MiniTable_Build and renders a normalized machine-readable
// form (charter §11). The Rust DUT must produce the identical rendering.
// ---------------------------------------------------------------------------

// Emits a JSON string literal. Convention (shared with the DUT): printable
// ASCII is emitted raw (with \" and \\ escaped); every other byte is rendered
// as the 6-character literal \u00xx (backslash escaped), so both sides produce
// identical *decoded* strings.
static void emit_json_string_raw(const char* s) {
  printf("\"");
  for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
    if (*p == '"' || *p == '\\') {
      printf("\\%c", *p);
    } else if (*p >= 0x20 && *p <= 0x7e) {
      putchar(*p);
    } else {
      printf("\\\\u00%02x", *p);
    }
  }
  printf("\"");
}

static void run_mini_table_inspect(int64_t id, const char* hex) {
  uint8_t input[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  upb_Arena* arena = upb_Arena_New();
  upb_Status status;
  upb_Status_Clear(&status);
  upb_MiniTable* mt =
      upb_MiniTable_Build((const char*)input, (size_t)n, arena, &status);
  if (!mt) {
    emit_header(id, "error");
    emit_field_str("code", "build_failed");
    printf(",\"msg\":");
    emit_json_string_raw(status.msg);
    emit_end();
    upb_Arena_Free(arena);
    return;
  }

  int field_count = upb_MiniTable_FieldCount(mt);
  emit_header(id, "ok");
  printf(",\"mini_table\":{");
  printf("\"version\":");
  if (n) {
    char v[2] = {(char)input[0], 0};
    emit_json_string_raw(v);
  } else {
    printf("null");
  }
  printf(",\"size\":%u", mt->size_dont_copy_me__upb_internal_use_only);
  printf(",\"field_count\":%u", mt->field_count_dont_copy_me__upb_internal_use_only);
  printf(",\"dense_below\":%u", mt->dense_below_dont_copy_me__upb_internal_use_only);
  printf(",\"ext\":%u", mt->ext_dont_copy_me__upb_internal_use_only);
  printf(",\"required_count\":%u", mt->required_count_dont_copy_me__upb_internal_use_only);
  printf(",\"fields\":[");
  for (int i = 0; i < field_count; i++) {
    if (i) printf(",");
    const upb_MiniTableField* f = upb_MiniTable_GetFieldByIndex(mt, i);
    printf("{");
    printf("\"number\":%u", f->number_dont_copy_me__upb_internal_use_only);
    printf(",\"type\":%u", f->descriptortype_dont_copy_me__upb_internal_use_only);
    printf(",\"mode\":%u", f->mode_dont_copy_me__upb_internal_use_only);
    printf(",\"offset\":%u", f->offset_dont_copy_me__upb_internal_use_only);
    printf(",\"presence\":%d", (int)f->presence);
    printf(",\"submsg_ofs\":%u", f->submsg_ofs_dont_copy_me__upb_internal_use_only);
    printf("}");
  }
  printf("],\"oneofs\":[");
  // Group oneof fields by their (negated) case offset.
  int first = 1;
  for (int i = 0; i < field_count; i++) {
    const upb_MiniTableField* f = upb_MiniTable_GetFieldByIndex(mt, i);
    if (f->presence >= 0) continue;
    int case_offset = ~f->presence;
    // Only emit each distinct case offset once; collect members.
    int already = 0;
    for (int j = 0; j < i; j++) {
      const upb_MiniTableField* g = upb_MiniTable_GetFieldByIndex(mt, j);
      if (g->presence < 0 && (~g->presence) == case_offset) {
        already = 1;
        break;
      }
    }
    if (already) continue;
    if (!first) printf(",");
    first = 0;
    printf("{\"case_offset\":%d,\"members\":[", case_offset);
    int mfirst = 1;
    for (int j = 0; j < field_count; j++) {
      const upb_MiniTableField* g = upb_MiniTable_GetFieldByIndex(mt, j);
      if (g->presence < 0 && (~g->presence) == case_offset) {
        if (!mfirst) printf(",");
        mfirst = 0;
        printf("%d", j);
      }
    }
    printf("]}");
  }
  printf("]}");
  emit_end();
  upb_Arena_Free(arena);
}

// ---------------------------------------------------------------------------
// decode_known: real upb_Decode into a message whose mini table is built from
// a mini descriptor, then a normalized accessor dump of the decoded state
// (court decode-known-v1). The Rust DUT must produce the identical dump.
// ---------------------------------------------------------------------------

static void emit_hex_bytes(const unsigned char* p, size_t n) {
  for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static size_t field_elem_size(uint8_t type) {
  switch (type) {
    case 8: return 1;  // Bool
    case 2: case 7: case 15: case 5: case 13: case 14: case 17: return 4;
    case 1: case 6: case 16: case 3: case 4: case 18: return 8;
    default: return 16;  // String/Bytes: upb_StringView
  }
}

// kUpb_NoSub (mini_table/internal/field.h:37): no sub slot for this field.
#define kUpb_NoSub_ ((uint16_t)0xFFFF)

// True when the field carries a linked sub-message (descriptor type Message
// with a sub slot). Group (10) and closed-enum (14) fields also reserve slots;
// this court only emits Message fields.
static int field_is_submsg(const upb_MiniTableField* f) {
  return f->descriptortype_dont_copy_me__upb_internal_use_only == 11 &&
         f->submsg_ofs_dont_copy_me__upb_internal_use_only != kUpb_NoSub_;
}

// Emits the normalized message object
// {"fields":[...],"oneof_cases":[...],"unknown":"..."} for `msg` described
// by `mt`, recursing into linked sub-message fields (court decode-submsg-v1).
static void emit_msg_value(const upb_Message* msg, const upb_MiniTable* mt) {
  int field_count = upb_MiniTable_FieldCount(mt);
  int first_emitted = 1;
  printf("{\"fields\":[");
  for (int i = 0; i < field_count; i++) {
    const upb_MiniTableField* f = upb_MiniTable_GetFieldByIndex(mt, i);
    uint32_t number = f->number_dont_copy_me__upb_internal_use_only;
    uint8_t type = f->descriptortype_dont_copy_me__upb_internal_use_only;
    uint16_t offset = f->offset_dont_copy_me__upb_internal_use_only;
    int is_array = (f->mode_dont_copy_me__upb_internal_use_only & 3) == 1;
    int is_submsg = field_is_submsg(f);
    if (is_array) {
      if (!first_emitted) printf(",");
      first_emitted = 0;
      printf("{\"number\":%u,\"value\":[", number);
      const upb_Array* arr = *(const upb_Array**)((const char*)msg + offset);
      if (arr) {
        size_t n = upb_Array_Size(arr);
        if (is_submsg) {
          const upb_MiniTable* subl = upb_MiniTable_SubMessage(f);
          const upb_Message** elems =
              (const upb_Message**)upb_Array_DataPtr(arr);
          for (size_t j = 0; j < n; j++) {
            if (j) printf(",");
            if (subl) {
              emit_msg_value(elems[j], subl);
            } else {
              printf("{\"fields\":[],\"oneof_cases\":[],\"unknown\":\"\"}");
            }
          }
        } else {
          size_t esz = field_elem_size(type);
          const char* data = (const char*)upb_Array_DataPtr(arr);
          for (size_t j = 0; j < n; j++) {
            if (j) printf(",");
            printf("\"");
            if (type == 9 || type == 12) {
              const upb_StringView* sv = (const upb_StringView*)data + j;
              emit_hex_bytes((const unsigned char*)sv->data, sv->size);
            } else {
              emit_hex_bytes((const unsigned char*)data + j * esz, esz);
            }
            printf("\"");
          }
        }
      }
      printf("]}");
      continue;
    }
    int present;
    if (f->presence > 0) {
      present = (((const unsigned char*)msg)[f->presence / 8] >> (f->presence % 8)) & 1;
    } else if (f->presence < 0) {
      uint32_t case_offset = (uint32_t)~f->presence;
      uint32_t c = *(const uint32_t*)((const char*)msg + case_offset);
      present = (c == number);
    } else {
      present = 1;  // proto3 singular
    }
    if (!present) continue;
    if (!first_emitted) printf(",");
    first_emitted = 0;
    printf("{\"number\":%u,\"value\":", number);
    if (is_submsg) {
      const upb_Message* sub = *(const upb_Message**)((const char*)msg + offset);
      const upb_MiniTable* subl = upb_MiniTable_SubMessage(f);
      if (subl) {
        emit_msg_value(sub, subl);
      } else {
        printf("{\"fields\":[],\"oneof_cases\":[],\"unknown\":\"\"}");
      }
    } else if (type == 9 || type == 12) {
      const upb_StringView* sv =
          (const upb_StringView*)((const char*)msg + offset);
      printf("\"");
      emit_hex_bytes((const unsigned char*)sv->data, sv->size);
      printf("\"");
    } else {
      size_t n = field_elem_size(type);
      if (n > 8) n = 8;
      printf("\"");
      emit_hex_bytes((const unsigned char*)((const char*)msg + offset), n);
      printf("\"");
    }
    printf("}");
  }
  printf("],\"oneof_cases\":[");
  // Collect and sort case offsets, then emit.
  {
    uint16_t offsets[64];
    int n_offsets = 0;
    for (int i = 0; i < field_count && n_offsets < 64; i++) {
      const upb_MiniTableField* f = upb_MiniTable_GetFieldByIndex(mt, i);
      if (f->presence < 0) {
        uint16_t off = (uint16_t)~f->presence;
        int dup = 0;
        for (int j = 0; j < n_offsets; j++) {
          if (offsets[j] == off) dup = 1;
        }
        if (!dup) offsets[n_offsets++] = off;
      }
    }
    for (int a = 0; a < n_offsets; a++) {
      for (int b = a + 1; b < n_offsets; b++) {
        if (offsets[b] < offsets[a]) {
          uint16_t t = offsets[a];
          offsets[a] = offsets[b];
          offsets[b] = t;
        }
      }
    }
    for (int a = 0; a < n_offsets; a++) {
      if (a) printf(",");
      uint32_t c = *(const uint32_t*)((const char*)msg + offsets[a]);
      printf("{\"case_offset\":%u,\"case\":%u}", offsets[a], c);
    }
  }
  printf("],\"unknown\":\"");
  {
    uintptr_t iter = 0;
    upb_MessageUnknown u;
    while (upb_Message_NextUnknown2(msg, &u, &iter)) {
      if (u.type == kUpb_MessageUnknownType_StringView) {
        emit_hex_bytes((const unsigned char*)u.value.bytes.data, u.value.bytes.size);
      }
    }
  }
  printf("\"}");
}

static void emit_dump(const upb_Message* msg, const upb_MiniTable* mt) {
  printf(",\"dump\":");
  emit_msg_value(msg, mt);
}

static void run_decode_known(int64_t id, const char* hex, const char* md,
                             int64_t depth) {
  uint8_t input[MAX_INPUT_BYTES];
  uint8_t desc[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  int dn = parse_hex(md, strlen(md), desc, sizeof(desc));
  if (n < 0 || dn < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  upb_Arena* arena = upb_Arena_New();
  upb_Status status;
  upb_Status_Clear(&status);
  upb_MiniTable* mt =
      upb_MiniTable_Build((const char*)desc, (size_t)dn, arena, &status);
  if (!mt) {
    emit_header(id, "error");
    emit_field_str("code", "minitable_build_failed");
    printf(",\"msg\":");
    emit_json_string_raw(status.msg);
    emit_end();
    upb_Arena_Free(arena);
    return;
  }

  upb_Message* msg = upb_Message_New(mt, arena);
  if (!msg) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_end();
    upb_Arena_Free(arena);
    return;
  }

  int options = 0;
  if (depth > 0 && depth <= 65535) {
    options = (int)upb_DecodeOptions_MaxDepth((uint16_t)depth);
  }
  upb_DecodeStatus ds = upb_Decode((const char*)input, (size_t)n, msg, mt, NULL,
                                   options, arena);
  if (ds == kUpb_DecodeStatus_Ok) {
    emit_header(id, "ok");
    emit_dump(msg, mt);
    emit_end();
  } else if (ds == kUpb_DecodeStatus_Malformed) {
    emit_header(id, "error");
    emit_field_str("code", "malformed");
    emit_end();
  } else if (ds == kUpb_DecodeStatus_BadUtf8) {
    emit_header(id, "error");
    emit_field_str("code", "bad_utf8");
    emit_end();
  } else if (ds == kUpb_DecodeStatus_MaxDepthExceeded) {
    emit_header(id, "error");
    emit_field_str("code", "max_depth_exceeded");
    emit_end();
  } else if (ds == kUpb_DecodeStatus_OutOfMemory) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_end();
  } else {
    emit_header(id, "error");
    emit_field_str("code", "other");
    emit_field_int("code_num", (int64_t)ds);
    emit_end();
  }
  upb_Arena_Free(arena);
}

// ---------------------------------------------------------------------------
// decode_submsg: build a pool of mini tables from `mds` (main first), link
// sub slots in field order using `links` (per-table list of target table
// indices, in sub-slot order), then run the real upb_Decode on the main
// table and dump the decoded state recursively (court decode-submsg-v1).
// ---------------------------------------------------------------------------

#define MAX_TABLES 8

static void run_decode_submsg(int64_t id, const char* hex, int64_t depth,
                              char mds[][MAX_INPUT_BYTES], int n_mds,
                              int64_t links[][64], int* link_lens) {
  uint8_t input[MAX_INPUT_BYTES];
  int n = parse_hex(hex, strlen(hex), input, sizeof(input));
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_hex");
    emit_end();
    return;
  }

  upb_Arena* arena = upb_Arena_New();
  upb_Status status;
  upb_Status_Clear(&status);

  upb_MiniTable* tables[MAX_TABLES] = {0};
  for (int t = 0; t < n_mds; t++) {
    uint8_t desc[MAX_INPUT_BYTES];
    int dn = parse_hex(mds[t], strlen(mds[t]), desc, sizeof(desc));
    if (dn < 0) {
      emit_header(id, "error");
      emit_field_str("code", "bad_hex");
      emit_end();
      upb_Arena_Free(arena);
      return;
    }
    tables[t] =
        upb_MiniTable_Build((const char*)desc, (size_t)dn, arena, &status);
    if (!tables[t]) {
      emit_header(id, "error");
      emit_field_str("code", "minitable_build_failed");
      printf(",\"msg\":");
      emit_json_string_raw(status.msg);
      emit_end();
      upb_Arena_Free(arena);
      return;
    }
  }

  // Link sub slots in field order (sub-slot i of table t -> tables[links[t][i]]).
  // Slots without a provided link stay unlinked, matching upstream's contract
  // (mini_descriptor/link.h: "If a sub-message field is not linked, it will
  // be treated as an unknown field during parsing"); once the provided links
  // are exhausted, all remaining sub fields are unlinked.
  for (int t = 0; t < n_mds; t++) {
    int slot = 0;
    int fc = upb_MiniTable_FieldCount(tables[t]);
    for (int i = 0; i < fc; i++) {
      upb_MiniTableField* f = (upb_MiniTableField*)upb_MiniTable_GetFieldByIndex(
          tables[t], (uint32_t)i);
      if (f->submsg_ofs_dont_copy_me__upb_internal_use_only == kUpb_NoSub_) {
        continue;
      }
      if (slot >= link_lens[t]) break;  // remaining slots unlinked
      int target = (int)links[t][slot];
      if (target < 0 || target >= n_mds) {
        emit_header(id, "error");
        emit_field_str("code", "bad_links");
        emit_end();
        upb_Arena_Free(arena);
        return;
      }
      if (!upb_MiniTable_SetSubMessage(tables[t], f, tables[target])) {
        emit_header(id, "error");
        emit_field_str("code", "link_failed");
        emit_end();
        upb_Arena_Free(arena);
        return;
      }
      slot++;
    }
  }

  upb_Message* msg = upb_Message_New(tables[0], arena);
  if (!msg) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_end();
    upb_Arena_Free(arena);
    return;
  }

  int options = 0;
  if (depth > 0 && depth <= 65535) {
    options = (int)upb_DecodeOptions_MaxDepth((uint16_t)depth);
  }
  upb_DecodeStatus ds = upb_Decode((const char*)input, (size_t)n, msg,
                                   tables[0], NULL, options, arena);
  if (ds == kUpb_DecodeStatus_Ok) {
    emit_header(id, "ok");
    emit_dump(msg, tables[0]);
    emit_end();
  } else if (ds == kUpb_DecodeStatus_Malformed) {
    emit_header(id, "error");
    emit_field_str("code", "malformed");
    emit_end();
  } else if (ds == kUpb_DecodeStatus_BadUtf8) {
    emit_header(id, "error");
    emit_field_str("code", "bad_utf8");
    emit_end();
  } else if (ds == kUpb_DecodeStatus_MaxDepthExceeded) {
    emit_header(id, "error");
    emit_field_str("code", "max_depth_exceeded");
    emit_end();
  } else if (ds == kUpb_DecodeStatus_OutOfMemory) {
    emit_header(id, "error");
    emit_field_str("code", "oom");
    emit_end();
  } else {
    emit_header(id, "error");
    emit_field_str("code", "other");
    emit_field_int("code_num", (int64_t)ds);
    emit_end();
  }
  upb_Arena_Free(arena);
}

// ---------------------------------------------------------------------------
// Arena ops (court arena-v1): a controlled exact-size allocator with OOM
// injection, scripted allocation traces against the real upb_Arena, fuse
// lifetime merging, and alloc-cleanup observation.
//
// Build-configuration note: kUpb_MemblockReserve / kUpb_ArenaStateReserve /
// kUpb_Asan_GuardSize are file-scope/private at this pin, so `arena_info`
// reports the values for THIS build (64-bit release: reserve 16, state 80,
// guard 0, align 8, max 32768). If the oracle is rebuilt with different
// flags (ASAN adds a 32-byte guard; debug adds a refs member), update the
// constants below.
// ---------------------------------------------------------------------------

#define ARENA_MAX_OPS 128
#define ARENA_MAX_TAGGED 8

// UPB_DEFAULT_MAX_BLOCK_SIZE is not exported by the upb headers the oracle
// includes (def.inc undefs it); this is the value for this build (Linux).
#define kOracleDefaultMaxBlockSize 32768UL

// The controlled allocator fulfills every request exactly (no usable-size
// rounding) and fails once the cumulative requested bytes would exceed
// `fail_after` (0 = never). It is the deterministic counterpart to the DUT's
// `ControlledAllocator`.
typedef struct {
  size_t total;       // cumulative requested bytes
  size_t fail_after;  // 0 = never fail; else fail when total + size > fail_after
} CtrlAllocState;

static CtrlAllocState g_ctrl;

static void* controlled_alloc_func(upb_alloc* alloc, void* ptr, size_t oldsize,
                                   size_t size, size_t* actual_size) {
  (void)alloc;
  (void)oldsize;
  if (size == 0) {
    free(ptr);
    return NULL;
  }
  if (g_ctrl.fail_after != 0 && g_ctrl.total + size > g_ctrl.fail_after) {
    return NULL;
  }
  g_ctrl.total += size;
  void* p = malloc(size);
  if (actual_size) *actual_size = p ? size : 0;
  return p;
}

// One upb_alloc per arena slot so the alloc-cleanup callback can identify
// which arena's cleanup ran (upb_Arena_SetAllocCleanup receives the arena's
// upb_alloc*).
typedef struct {
  upb_alloc alloc;
  int64_t id;  // cleanup id for this slot, or -1
} TaggedAlloc;

static TaggedAlloc g_tagged[ARENA_MAX_TAGGED];
static int64_t g_cleanup_order[ARENA_MAX_TAGGED];
static int g_cleanup_n;

static void arena_cleanup_func(upb_alloc* alloc) {
  if (g_cleanup_n >= ARENA_MAX_TAGGED) return;
  for (int i = 0; i < ARENA_MAX_TAGGED; i++) {
    if (&g_tagged[i].alloc == alloc) {
      g_cleanup_order[g_cleanup_n++] = g_tagged[i].id;
      return;
    }
  }
  g_cleanup_order[g_cleanup_n++] = -1;
}

typedef enum {
  ARENA_OP_MALLOC,
  ARENA_OP_REALLOC,
  ARENA_OP_SHRINK,
  ARENA_OP_TRYEXTEND,
  ARENA_OP_MESSAGE,
  ARENA_OP_STRDUP,
  ARENA_OP_CLEANUP,
} ArenaOpKind;

typedef struct {
  ArenaOpKind kind;
  size_t size;
  int ref;  // op index for realloc/shrink/tryextend; cleanup id for CLEANUP
  char hex[4096];  // STRDUP payload
} ArenaOp;

static int json_bool(const char* line, const char* name, int* out) {
  size_t nlen = strlen(name);
  const char* p = strstr(line, name);
  if (!p) return -1;
  p += nlen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (strncmp(p, "true", 4) == 0) {
    *out = 1;
    return 0;
  }
  if (strncmp(p, "false", 5) == 0) {
    *out = 0;
    return 0;
  }
  return -1;
}

// Parses an arena configuration object: {"initial_block":N,"alloc":bool,
// "max_block_size":N,"fail_after_bytes":N}.
static int parse_arena_cfg(const char* line, const char* key,
                           size_t* initial_block, int* alloc,
                           size_t* max_block_size, size_t* fail_after) {
  size_t klen = strlen(key);
  const char* p = strstr(line, key);
  if (!p) return -1;
  p += klen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p != '{') return -1;
  const char* end = strchr(p, '}');
  if (!end) return -1;
  size_t len = (size_t)(end - p + 1);
  char buf[256];
  if (len >= sizeof(buf)) return -1;
  memcpy(buf, p, len);
  buf[len] = '\0';
  int64_t ib = 0, mb = 0, fa = 0;
  json_int(buf, "\"initial_block\"", &ib);
  json_int(buf, "\"max_block_size\"", &mb);
  json_int(buf, "\"fail_after_bytes\"", &fa);
  if (json_bool(buf, "\"alloc\"", alloc) < 0) *alloc = 1;
  *initial_block = (size_t)ib;
  *max_block_size = (size_t)mb;
  *fail_after = (size_t)fa;
  return 0;
}

// Parses an array of arena op objects: [{"k":"malloc","size":16,"ref":N,"hex":".."}, ...].
static int parse_arena_ops(const char* line, const char* key, ArenaOp* ops,
                           int max) {
  size_t klen = strlen(key);
  const char* p = strstr(line, key);
  if (!p) return 0;
  p += klen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p != '[') return 0;
  p++;
  while (*p == ' ') p++;
  if (*p == ']') return 0;  // empty array
  int n = 0;
  while (*p && n < max) {
    while (*p && *p != '{' && *p != ']') p++;
    if (*p != '{') break;  // ']' or end of string: array done
    const char* end = strchr(p, '}');
    if (!end) return -1;
    size_t len = (size_t)(end - p + 1);
    if (len > 4096) return -1;
    char buf[4096];
    memcpy(buf, p, len);
    buf[len] = '\0';
    char k[16] = {0};
    int64_t size = 0, ref = -1;
    if (json_string(buf, "\"k\"", k, sizeof(k)) < 0) return -1;
    json_int(buf, "\"size\"", &size);
    json_int(buf, "\"ref\"", &ref);
    ArenaOp op;
    memset(&op, 0, sizeof(op));
    op.size = (size_t)size;
    op.ref = (int)ref;
    if (strcmp(k, "malloc") == 0) {
      op.kind = ARENA_OP_MALLOC;
    } else if (strcmp(k, "realloc") == 0) {
      op.kind = ARENA_OP_REALLOC;
    } else if (strcmp(k, "shrink") == 0) {
      op.kind = ARENA_OP_SHRINK;
    } else if (strcmp(k, "tryextend") == 0) {
      op.kind = ARENA_OP_TRYEXTEND;
    } else if (strcmp(k, "message") == 0) {
      op.kind = ARENA_OP_MESSAGE;
    } else if (strcmp(k, "strdup") == 0) {
      op.kind = ARENA_OP_STRDUP;
      json_string(buf, "\"hex\"", op.hex, sizeof(op.hex));
    } else if (strcmp(k, "cleanup") == 0) {
      op.kind = ARENA_OP_CLEANUP;
    } else {
      return -1;
    }
    ops[n++] = op;
    p = end + 1;
  }
  return n;
}

// One op result: {"ok":bool,"space":N,"ref":i?,"same_ptr":?,"extended":?,"zeroed":?}.
static void emit_arena_op(int ok, int same_ptr, int extended, int zeroed,
                          uint64_t space, int ref) {
  printf("{\"ok\":%s", ok ? "true" : "false");
  if (same_ptr >= 0) printf(",\"same_ptr\":%s", same_ptr ? "true" : "false");
  if (extended >= 0) printf(",\"extended\":%s", extended ? "true" : "false");
  if (zeroed >= 0) printf(",\"zeroed\":%s", zeroed ? "true" : "false");
  printf(",\"space\":%" PRIu64, space);
  if (ref >= 0) printf(",\"ref\":%d", ref);
  printf("}");
}

typedef struct {
  upb_Arena* arena;
  void* ptrs[ARENA_MAX_OPS];
  size_t sizes[ARENA_MAX_OPS];
  int slot;
} ArenaCtx;

// Runs one op list against an arena, emitting one result object per op.
static void run_arena_ops(ArenaCtx* ctx, ArenaOp* ops, int n) {
  for (int i = 0; i < n; i++) {
    ArenaOp* op = &ops[i];
    if (i) printf(",");
    switch (op->kind) {
      case ARENA_OP_MALLOC: {
        void* p = upb_Arena_Malloc(ctx->arena, op->size);
        ctx->ptrs[i] = p;
        ctx->sizes[i] = op->size;
        uint64_t space = upb_Arena_SpaceAllocated(ctx->arena, NULL);
        emit_arena_op(p != NULL, -1, -1, -1, space, p ? i : -1);
        break;
      }
      case ARENA_OP_REALLOC: {
        void* r = upb_Arena_Realloc(ctx->arena, ctx->ptrs[op->ref],
                                    ctx->sizes[op->ref], op->size);
        int same = (r == ctx->ptrs[op->ref]);
        ctx->ptrs[i] = r;
        ctx->sizes[i] = op->size;
        uint64_t space = upb_Arena_SpaceAllocated(ctx->arena, NULL);
        emit_arena_op(r != NULL, same, -1, -1, space, r ? i : -1);
        break;
      }
      case ARENA_OP_SHRINK:
        upb_Arena_ShrinkLast(ctx->arena, ctx->ptrs[op->ref],
                             ctx->sizes[op->ref], op->size);
        ctx->sizes[op->ref] = op->size;
        emit_arena_op(1, -1, -1, -1,
                      upb_Arena_SpaceAllocated(ctx->arena, NULL), -1);
        break;
      case ARENA_OP_TRYEXTEND: {
        int ok = upb_Arena_TryExtend(ctx->arena, ctx->ptrs[op->ref],
                                     ctx->sizes[op->ref], op->size);
        if (ok) ctx->sizes[op->ref] = op->size;
        emit_arena_op(1, -1, ok, -1,
                      upb_Arena_SpaceAllocated(ctx->arena, NULL), -1);
        break;
      }
      case ARENA_OP_MESSAGE: {
        void* p = upb_Arena_Malloc(ctx->arena, op->size);
        if (p) memset(p, 0, op->size);  // _upb_Message_New zeroes
        ctx->ptrs[i] = p;
        ctx->sizes[i] = op->size;
        uint64_t space = upb_Arena_SpaceAllocated(ctx->arena, NULL);
        emit_arena_op(p != NULL, -1, -1, p != NULL, space, p ? i : -1);
        break;
      }
      case ARENA_OP_STRDUP: {
        size_t len = op->size;
        void* p = upb_Arena_Malloc(ctx->arena, len);
        if (p) {
          uint8_t bytes[2048];
          int bn = parse_hex(op->hex, strlen(op->hex), bytes, sizeof(bytes));
          if (bn > 0) memcpy(p, bytes, (size_t)(bn < (int)len ? bn : (int)len));
        }
        ctx->ptrs[i] = p;
        ctx->sizes[i] = len;
        uint64_t space = upb_Arena_SpaceAllocated(ctx->arena, NULL);
        emit_arena_op(p != NULL, -1, -1, -1, space, p ? i : -1);
        break;
      }
      case ARENA_OP_CLEANUP:
        g_tagged[ctx->slot].id = op->ref;
        upb_Arena_SetAllocCleanup(ctx->arena, arena_cleanup_func);
        emit_arena_op(1, -1, -1, -1,
                      upb_Arena_SpaceAllocated(ctx->arena, NULL), -1);
        break;
    }
  }
}

static void emit_cleanup_order(void) {
  printf(",\"cleanup\":[");
  for (int i = 0; i < g_cleanup_n; i++) {
    if (i) printf(",");
    printf("%" PRId64, g_cleanup_order[i]);
  }
  printf("]");
}

// Initializes an arena per the config; slot selects the TaggedAlloc. Returns
// NULL (and emits an error response) on failure.
static upb_Arena* init_arena_cfg(size_t initial_block, int alloc,
                                 int slot, int64_t id, int* err_emitted) {
  static uint8_t init_buf[4096];
  g_tagged[slot].id = -1;
  g_tagged[slot].alloc.func = controlled_alloc_func;
  upb_alloc* al = alloc ? &g_tagged[slot].alloc : NULL;
  upb_Arena* arena = NULL;
  if (initial_block) {
    if (initial_block > sizeof(init_buf)) {
      emit_header(id, "error");
      emit_field_str("code", "bad_request");
      emit_end();
      *err_emitted = 1;
      return NULL;
    }
    arena = upb_Arena_Init(init_buf, initial_block, al);
  } else {
    arena = upb_Arena_Init(NULL, 0, al);
  }
  if (!arena) {
    emit_header(id, "error");
    emit_field_str("code", "init_failed");
    emit_end();
    *err_emitted = 1;
    return NULL;
  }
  *err_emitted = 0;
  return arena;
}

static void run_arena_trace(int64_t id, const char* line) {
  size_t initial_block = 0, max_block_size = 0, fail_after = 0;
  int alloc = 1;
  if (parse_arena_cfg(line, "\"arena\"", &initial_block, &alloc,
                      &max_block_size, &fail_after) < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  ArenaOp ops[ARENA_MAX_OPS];
  int n = parse_arena_ops(line, "\"ops\"", ops, ARENA_MAX_OPS);
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  int free_at_end = 0;
  json_bool(line, "\"free\"", &free_at_end);

  g_ctrl.total = 0;
  g_ctrl.fail_after = fail_after;
  g_cleanup_n = 0;
  if (max_block_size) upb_Arena_SetMaxBlockSize(max_block_size);

  int err_emitted = 0;
  upb_Arena* arena = init_arena_cfg(initial_block, alloc, 0, id, &err_emitted);
  if (!arena) {
    upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
    return;
  }

  emit_header(id, "ok");
  printf(",\"ops\":[");
  ArenaCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.arena = arena;
  ctx.slot = 0;
  run_arena_ops(&ctx, ops, n);
  printf("]");
  size_t fused = 0;
  uint64_t space = upb_Arena_SpaceAllocated(arena, &fused);
  printf(",\"arena\":{\"space\":%" PRIu64 ",\"fused_count\":%zu}",
         space, fused);
  if (free_at_end) {
    upb_Arena_Free(arena);
    emit_cleanup_order();
  }
  emit_end();
  upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
}

static void run_arena_fuse(int64_t id, const char* line) {
  size_t ib_a = 0, mb_a = 0, fa_a = 0, ib_b = 0, mb_b = 0, fa_b = 0;
  int alloc_a = 1, alloc_b = 1;
  if (parse_arena_cfg(line, "\"a\"", &ib_a, &alloc_a, &mb_a, &fa_a) < 0 ||
      parse_arena_cfg(line, "\"b\"", &ib_b, &alloc_b, &mb_b, &fa_b) < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  ArenaOp ops_a[ARENA_MAX_OPS], ops_b[ARENA_MAX_OPS], ops_post[ARENA_MAX_OPS];
  int na = parse_arena_ops(line, "\"a_ops\"", ops_a, ARENA_MAX_OPS);
  int nb = parse_arena_ops(line, "\"b_ops\"", ops_b, ARENA_MAX_OPS);
  int np = parse_arena_ops(line, "\"post_ops\"", ops_post, ARENA_MAX_OPS);
  if (na < 0 || nb < 0 || np < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  size_t max_block_size = mb_a ? mb_a : mb_b;

  g_ctrl.total = 0;
  g_ctrl.fail_after = fa_a ? fa_a : fa_b;
  g_cleanup_n = 0;
  if (max_block_size) upb_Arena_SetMaxBlockSize(max_block_size);

  int err_emitted = 0;
  upb_Arena* arena_a = init_arena_cfg(ib_a, alloc_a, 0, id, &err_emitted);
  if (!arena_a) {
    upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
    return;
  }
  upb_Arena* arena_b = init_arena_cfg(ib_b, alloc_b, 1, id, &err_emitted);
  if (!arena_b) {
    upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
    return;
  }

  emit_header(id, "ok");
  printf(",\"a_ops\":[");
  ArenaCtx ctx_a;
  memset(&ctx_a, 0, sizeof(ctx_a));
  ctx_a.arena = arena_a;
  ctx_a.slot = 0;
  run_arena_ops(&ctx_a, ops_a, na);
  printf("]");
  printf(",\"b_ops\":[");
  ArenaCtx ctx_b;
  memset(&ctx_b, 0, sizeof(ctx_b));
  ctx_b.arena = arena_b;
  ctx_b.slot = 1;
  run_arena_ops(&ctx_b, ops_b, nb);
  printf("]");

  int fused = upb_Arena_Fuse(arena_a, arena_b);
  printf(",\"is_fused\":%s", fused ? "true" : "false");
  printf(",\"post_ops\":[");
  run_arena_ops(&ctx_b, ops_post, np);
  printf("]");
  size_t fused_count = 0;
  uint64_t space = upb_Arena_SpaceAllocated(arena_b, &fused_count);
  printf(",\"arena\":{\"space\":%" PRIu64 ",\"fused_count\":%zu}",
         space, fused_count);

  upb_Arena_Free(arena_a);
  printf(",\"free_a\":[");
  for (int i = 0; i < g_cleanup_n; i++) {
    if (i) printf(",");
    printf("%" PRId64, g_cleanup_order[i]);
  }
  printf("]");
  g_cleanup_n = 0;
  upb_Arena_Free(arena_b);
  printf(",\"free_b\":[");
  for (int i = 0; i < g_cleanup_n; i++) {
    if (i) printf(",");
    printf("%" PRId64, g_cleanup_order[i]);
  }
  printf("]");
  emit_end();
  upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
}

static void run_arena_info(int64_t id) {
  // Constants for THIS build (64-bit release). See the section comment.
  emit_header(id, "ok");
  printf(",\"arena\":{\"malloc_align\":8,\"guard_size\":0,"
         "\"memblock_reserve\":16,\"state_reserve\":80,"
         "\"default_max_block_size\":32768}");
  emit_end();
}

// ---------------------------------------------------------------------------
// array_trace / map_trace (court collections-v1): scripted upb_Array and
// upb_Map operations against the real APIs. The array ops report the arena
// space (the array data region is a single arena allocation with observable
// realloc growth); the map ops report content semantics only — the internal
// table layout and arena footprint are representation (the DUT keeps entries
// in owned storage).
// ---------------------------------------------------------------------------

typedef struct {
  char k[16];
  int64_t size;
  int64_t ref;
  int64_t index;
  int64_t type;
  int64_t key_type;
  int64_t val_type;
  char hex[4096];
} GenOp;

// Parses an array of generic op objects: [{"k":"...","size":N,"ref":N,
// "index":N,"type":N,"key_type":N,"val_type":N,"hex":".."}, ...].
static int parse_gen_ops(const char* line, const char* key, GenOp* ops,
                         int max) {
  size_t klen = strlen(key);
  const char* p = strstr(line, key);
  if (!p) return 0;
  p += klen;
  while (*p && (*p == ' ' || *p == ':')) p++;
  if (*p != '[') return 0;
  p++;
  while (*p == ' ') p++;
  if (*p == ']') return 0;
  int n = 0;
  while (*p && n < max) {
    while (*p && *p != '{' && *p != ']') p++;
    if (*p != '{') break;
    const char* end = strchr(p, '}');
    if (!end) return -1;
    size_t len = (size_t)(end - p + 1);
    if (len > 4096) return -1;
    char buf[4096];
    memcpy(buf, p, len);
    buf[len] = '\0';
    GenOp op;
    memset(&op, 0, sizeof(op));
    op.ref = -1;
    if (json_string(buf, "\"k\"", op.k, sizeof(op.k)) < 0) return -1;
    json_int(buf, "\"size\"", &op.size);
    json_int(buf, "\"ref\"", &op.ref);
    json_int(buf, "\"index\"", &op.index);
    json_int(buf, "\"type\"", &op.type);
    json_int(buf, "\"key_type\"", &op.key_type);
    json_int(buf, "\"val_type\"", &op.val_type);
    json_string(buf, "\"hex\"", op.hex, sizeof(op.hex));
    ops[n++] = op;
    p = end + 1;
  }
  return n;
}

// _upb_CType_SizeLg2 (mini_table/internal/size_log2.h:25-38), numeric ctypes
// only (1..=9; string/bytes arrays hold StringView structs whose content is
// pointer-valued and therefore out of the court's scope).
static int ctype_lg2(int64_t ctype) {
  switch (ctype) {
    case 1: return 0;  // Bool
    case 2: case 3: case 4: case 5: return 2;  // Float, Int32, UInt32, Enum
    case 6: case 7: case 8: case 9: return 3;  // Message, Double, Int64, UInt64
    default: return -1;
  }
}

static void emit_collections_op(int ok, size_t sz, const upb_Array* arr,
                                int lg2, upb_Arena* arena, int ref);

static void run_array_trace(int64_t id, const char* line) {
  size_t initial_block = 0, max_block_size = 0, fail_after = 0;
  int alloc = 1;
  if (parse_arena_cfg(line, "\"arena\"", &initial_block, &alloc,
                      &max_block_size, &fail_after) < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  GenOp ops[ARENA_MAX_OPS];
  int n = parse_gen_ops(line, "\"ops\"", ops, ARENA_MAX_OPS);
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  g_ctrl.total = 0;
  g_ctrl.fail_after = fail_after;
  if (max_block_size) upb_Arena_SetMaxBlockSize(max_block_size);

  int err_emitted = 0;
  upb_Arena* arena = init_arena_cfg(initial_block, alloc, 0, id, &err_emitted);
  if (!arena) {
    upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
    return;
  }

  upb_Array* arrays[ARENA_MAX_OPS] = {0};
  int lgs[ARENA_MAX_OPS] = {0};

  emit_header(id, "ok");
  printf(",\"ops\":[");
  for (int i = 0; i < n; i++) {
    if (i) printf(",");
    GenOp* op = &ops[i];
    if (strcmp(op->k, "new") == 0) {
      int lg2 = ctype_lg2(op->type);
      upb_Array* arr = lg2 >= 0 ? upb_Array_New(arena, (upb_CType)op->type) : NULL;
      arrays[i] = arr;
      lgs[i] = lg2;
      printf("{\"ok\":%s,\"size\":0,\"data\":\"\","
             "\"space\":%" PRIu64,
             arr ? "true" : "false",
             (uint64_t)upb_Arena_SpaceAllocated(arena, NULL));
      if (arr) printf(",\"ref\":%d", i);
      printf("}");
    } else if (strcmp(op->k, "append") == 0 || strcmp(op->k, "set") == 0) {
      upb_Array* arr = arrays[op->ref];
      int ok = 0;
      if (arr) {
        int lg2 = lgs[op->ref];
        uint8_t bytes[16];
        int bn = parse_hex(op->hex, strlen(op->hex), bytes, sizeof(bytes));
        upb_MessageValue v;
        memset(&v, 0, sizeof(v));
        if (bn == (1 << lg2)) {
          memcpy(&v, bytes, bn);
          if (strcmp(op->k, "append") == 0) {
            ok = upb_Array_Append(arr, v, arena);
          } else {
            upb_Array_Set(arr, (size_t)op->index, v);
            ok = 1;
          }
        }
      }
      size_t sz = arr ? upb_Array_Size(arr) : 0;
      emit_collections_op(ok, sz, arr, lgs[op->ref], arena, i);
    } else if (strcmp(op->k, "resize") == 0) {
      upb_Array* arr = arrays[op->ref];
      int ok = arr && upb_Array_Resize(arr, (size_t)op->size, arena);
      size_t sz = arr ? upb_Array_Size(arr) : 0;
      emit_collections_op(ok, sz, arr, lgs[op->ref], arena, i);
    } else if (strcmp(op->k, "get") == 0) {
      upb_Array* arr = arrays[op->ref];
      int ok = 0;
      if (arr && (size_t)op->index < upb_Array_Size(arr)) {
        upb_MessageValue v = upb_Array_Get(arr, (size_t)op->index);
        printf("{\"ok\":true,\"val\":\"");
        emit_hex_bytes((const unsigned char*)&v, (size_t)1 << lgs[op->ref]);
        printf("\",\"space\":%" PRIu64 "}",
               (uint64_t)upb_Arena_SpaceAllocated(arena, NULL));
        continue;
      }
      printf("{\"ok\":%s,\"space\":%" PRIu64 "}", ok ? "true" : "false",
             (uint64_t)upb_Arena_SpaceAllocated(arena, NULL));
    } else {
      printf("{\"ok\":false}");
    }
  }
  printf("]");
  size_t fused = 0;
  uint64_t space = upb_Arena_SpaceAllocated(arena, &fused);
  printf(",\"arena\":{\"space\":%" PRIu64 ",\"fused_count\":%zu}",
         space, fused);
  emit_end();
  upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
}

static void emit_collections_op(int ok, size_t sz, const upb_Array* arr,
                                int lg2, upb_Arena* arena, int ref) {
  printf("{\"ok\":%s,\"size\":%zu,\"data\":\"", ok ? "true" : "false",
         sz);
  if (arr) {
    emit_hex_bytes((const unsigned char*)upb_Array_DataPtr(arr),
                   sz << lg2);
  }
  printf("\",\"space\":%" PRIu64,
         (uint64_t)upb_Arena_SpaceAllocated(arena, NULL));
  if (ok && arr) printf(",\"ref\":%d", ref);
  printf("}");
}

// Builds a upb_MessageValue from hex: numeric types memcpy the bytes; string
// types (size 0) build a StringView into `buf`.
static void value_from_hex(const char* hex, size_t size, uint8_t* buf,
                           size_t buf_cap, upb_MessageValue* v) {
  memset(v, 0, sizeof(*v));
  int bn = parse_hex(hex, strlen(hex), buf, buf_cap);
  if (size == 0) {
    if (bn > 0) {
      v->str_val = upb_StringView_FromDataAndSize((const char*)buf, (size_t)bn);
    }
  } else if (bn == (int)size) {
    memcpy(v, buf, size);
  }
}

static void run_map_trace(int64_t id, const char* line) {
  size_t initial_block = 0, max_block_size = 0, fail_after = 0;
  int alloc = 1;
  if (parse_arena_cfg(line, "\"arena\"", &initial_block, &alloc,
                      &max_block_size, &fail_after) < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  GenOp ops[ARENA_MAX_OPS];
  int n = parse_gen_ops(line, "\"ops\"", ops, ARENA_MAX_OPS);
  if (n < 0) {
    emit_header(id, "error");
    emit_field_str("code", "bad_request");
    emit_end();
    return;
  }
  g_ctrl.total = 0;
  g_ctrl.fail_after = fail_after;
  if (max_block_size) upb_Arena_SetMaxBlockSize(max_block_size);

  int err_emitted = 0;
  upb_Arena* arena = init_arena_cfg(initial_block, alloc, 0, id, &err_emitted);
  if (!arena) {
    upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
    return;
  }

  upb_Map* maps[ARENA_MAX_OPS] = {0};
  size_t key_sizes[ARENA_MAX_OPS] = {0};
  size_t val_sizes[ARENA_MAX_OPS] = {0};
  static uint8_t kbuf[ARENA_MAX_OPS][512];
  static uint8_t vbuf[ARENA_MAX_OPS][512];

  emit_header(id, "ok");
  printf(",\"ops\":[");
  for (int i = 0; i < n; i++) {
    if (i) printf(",");
    GenOp* op = &ops[i];
    if (strcmp(op->k, "new") == 0) {
      upb_Map* map = upb_Map_New(arena, (upb_CType)op->key_type,
                                 (upb_CType)op->val_type);
      maps[i] = map;
      if (map) {
        key_sizes[i] = map->key_size;
        val_sizes[i] = map->val_size;
      }
      printf("{\"ok\":%s,\"size\":0", map ? "true" : "false");
      if (map) printf(",\"ref\":%d", i);
      printf("}");
    } else if (strcmp(op->k, "insert") == 0) {
      upb_Map* map = maps[op->ref];
      int ok = 0;
      if (map) {
        upb_MessageValue key, val;
        // The value hex follows a '|' separator inside op->hex for string
        // values; for numeric values it is the same field. Split BEFORE
        // parsing the key.
        const char* vhex = op->hex;
        char* sep = strchr(op->hex, '|');
        if (sep) {
          *sep = '\0';
          vhex = sep + 1;
        }
        value_from_hex(op->hex, key_sizes[op->ref], kbuf[i], sizeof(kbuf[i]),
                       &key);
        value_from_hex(vhex, val_sizes[op->ref], vbuf[i], sizeof(vbuf[i]),
                       &val);
        upb_MapInsertStatus st =
            upb_Map_Insert(map, key, val, arena);
        printf("{\"ok\":true,\"status\":%s,\"size\":%zu}",
               st == kUpb_MapInsertStatus_Inserted
                   ? "\"inserted\""
                   : (st == kUpb_MapInsertStatus_Replaced ? "\"replaced\""
                                                          : "\"oom\""),
               upb_Map_Size(map));
        continue;
      }
      printf("{\"ok\":%s}", ok ? "true" : "false");
    } else if (strcmp(op->k, "get") == 0) {
      upb_Map* map = maps[op->ref];
      int found = 0;
      if (map) {
        upb_MessageValue key, val;
        value_from_hex(op->hex, key_sizes[op->ref], kbuf[i], sizeof(kbuf[i]),
                       &key);
        found = upb_Map_Get(map, key, &val);
        if (found) {
          printf("{\"ok\":true,\"found\":true,\"val\":\"");
          if (val_sizes[op->ref] == 0) {
            emit_hex_bytes((const unsigned char*)val.str_val.data,
                           val.str_val.size);
          } else {
            emit_hex_bytes((const unsigned char*)&val, val_sizes[op->ref]);
          }
          printf("\"}");
          continue;
        }
      }
      printf("{\"ok\":true,\"found\":%s}", found ? "true" : "false");
    } else if (strcmp(op->k, "delete") == 0) {
      upb_Map* map = maps[op->ref];
      int removed = 0;
      if (map) {
        upb_MessageValue key, val;
        value_from_hex(op->hex, key_sizes[op->ref], kbuf[i], sizeof(kbuf[i]),
                       &key);
        removed = upb_Map_Delete(map, key, &val);
        printf("{\"ok\":true,\"removed\":%s,\"size\":%zu}",
               removed ? "true" : "false", upb_Map_Size(map));
        continue;
      }
      printf("{\"ok\":%s}", removed ? "true" : "false");
    } else if (strcmp(op->k, "iterate") == 0) {
      upb_Map* map = maps[op->ref];
      printf("{\"ok\":true,\"entries\":[");
      if (map) {
        // upb's table iterator advances BEFORE scanning (hash/common.c,
        // `next()`), so the initial state must be kUpb_Map_Begin ((size_t)-1);
        // starting at 0 silently skips any entry hashing to slot 0.
        size_t iter = kUpb_Map_Begin;
        upb_MessageValue key, val;
        // Collect and sort by key bytes so the comparison is order-free
        // (upstream iteration order is table layout, representation).
        char collected[128][64];
        size_t n_entries = 0;
        while (upb_Map_Next(map, &key, &val, &iter) && n_entries < 128) {
          // Build a comparable string of the pair: keyhex|valhex.
          char tmp[64];
          size_t o = 0;
          if (key_sizes[op->ref] == 0) {
            for (size_t j = 0; j < key.str_val.size && o + 1 < sizeof(tmp); j++) {
              o += (size_t)sprintf(tmp + o, "%02x",
                                   (unsigned char)key.str_val.data[j]);
            }
          } else {
            for (size_t j = 0; j < key_sizes[op->ref] && o + 1 < sizeof(tmp); j++) {
              o += (size_t)sprintf(tmp + o, "%02x",
                                   ((const unsigned char*)&key)[j]);
            }
          }
          if (o + 1 < sizeof(tmp)) tmp[o++] = '|';
          if (val_sizes[op->ref] == 0) {
            for (size_t j = 0; j < val.str_val.size && o + 1 < sizeof(tmp); j++) {
              o += (size_t)sprintf(tmp + o, "%02x",
                                   (unsigned char)val.str_val.data[j]);
            }
          } else {
            for (size_t j = 0; j < val_sizes[op->ref] && o + 1 < sizeof(tmp); j++) {
              o += (size_t)sprintf(tmp + o, "%02x",
                                   ((const unsigned char*)&val)[j]);
            }
          }
          tmp[o] = '\0';
          memcpy(collected[n_entries], tmp, o + 1);
          n_entries++;
        }
        // Simple insertion sort on the collected pair strings.
        for (size_t a = 0; a < n_entries; a++) {
          for (size_t b = a + 1; b < n_entries; b++) {
            if (strcmp(collected[b], collected[a]) < 0) {
              char t[64];
              memcpy(t, collected[a], sizeof(t));
              memcpy(collected[a], collected[b], sizeof(t));
              memcpy(collected[b], t, sizeof(t));
            }
          }
        }
        for (size_t a = 0; a < n_entries; a++) {
          if (a) printf(",");
          // Re-derive the pair as a JSON array from the sorted string.
          char* sep = strchr(collected[a], '|');
          printf("[\"");
          if (sep) {
            *sep = '\0';
            printf("%s", collected[a]);
          }
          printf("\",\"");
          if (sep) printf("%s", sep + 1);
          printf("\"]");
        }
      }
      printf("]}");
    } else {
      printf("{\"ok\":false}");
    }
  }
  printf("]");
  size_t fused = 0;
  uint64_t space = upb_Arena_SpaceAllocated(arena, &fused);
  printf(",\"arena\":{\"space\":%" PRIu64 ",\"fused_count\":%zu}",
         space, fused);
  emit_end();
  upb_Arena_SetMaxBlockSize(kOracleDefaultMaxBlockSize);
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

int main(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  char line[MAX_LINE];
  while (fgets(line, sizeof(line), stdin)) {
    // Strip trailing newline.
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0') continue;

    char op[64] = {0};
    char hex[8192] = {0};
    int64_t id = 0;
    int64_t tag = 0;
    int64_t v = 0;

    if (json_string(line, "\"op\"", op, sizeof(op)) < 0 ||
        json_int(line, "\"id\"", &id) < 0 || json_int(line, "\"v\"", &v) < 0) {
      emit_header(0, "error");
      emit_field_str("code", "bad_request");
      emit_end();
      continue;
    }
    // `hex` is optional (absent == empty payload).
    if (json_string(line, "\"hex\"", hex, sizeof(hex)) < 0) {
      hex[0] = '\0';
    }

    if (strcmp(op, "ping") == 0) {
      emit_header(id, "ok");
      emit_field_str("echo", "pong");
      emit_end();
    } else if (strcmp(op, "read_varint") == 0) {
      run_primitive_read(id, op, hex, read_varint_fn, 1);
    } else if (strcmp(op, "read_tag") == 0) {
      run_primitive_read(id, op, hex, read_tag_fn, 1);
    } else if (strcmp(op, "read_size") == 0) {
      run_primitive_read(id, op, hex, read_size_fn, 1);
    } else if (strcmp(op, "read_fixed32") == 0) {
      run_primitive_read(id, op, hex, read_fixed32_fn, 1);
    } else if (strcmp(op, "read_fixed64") == 0) {
      run_primitive_read(id, op, hex, read_fixed64_fn, 1);
    } else if (strcmp(op, "skip_varint") == 0) {
      run_primitive_read(id, op, hex, skip_varint_fn, 0);
    } else if (strcmp(op, "skip_value") == 0) {
      if (json_int(line, "\"tag\"", &tag) < 0) {
        emit_header(id, "error");
        emit_field_str("code", "bad_request");
        emit_end();
        continue;
      }
      run_skip_value(id, hex, (uint32_t)tag);
    } else if (strcmp(op, "skip_group") == 0) {
      if (json_int(line, "\"tag\"", &tag) < 0) {
        emit_header(id, "error");
        emit_field_str("code", "bad_request");
        emit_end();
        continue;
      }
      run_skip_group(id, hex, (uint32_t)tag);
    } else if (strcmp(op, "decode_empty") == 0) {
      int64_t depth = 0;
      json_int(line, "\"depth\"", &depth);  // optional; 0 -> default 100
      run_decode_empty(id, hex, depth);
    } else if (strcmp(op, "mini_table_inspect") == 0) {
      run_mini_table_inspect(id, hex);
    } else if (strcmp(op, "decode_known") == 0) {
      char md[8192] = {0};
      int64_t depth = 0;
      json_string(line, "\"md\"", md, sizeof(md));
      json_int(line, "\"depth\"", &depth);
      run_decode_known(id, hex, md, depth);
    } else if (strcmp(op, "decode_submsg") == 0) {
      char mds[MAX_TABLES][MAX_INPUT_BYTES] = {{0}};
      int64_t links[MAX_TABLES][64] = {{0}};
      int link_lens[MAX_TABLES] = {0};
      int64_t depth = 0;
      int n_mds = json_string_array(line, "\"mds\"", mds, MAX_TABLES);
      int n_links = json_int_array2(line, "\"links\"", links, link_lens,
                                    MAX_TABLES);
      json_int(line, "\"depth\"", &depth);
      if (n_mds < 1 || n_links != n_mds) {
        emit_header(id, "error");
        emit_field_str("code", "bad_request");
        emit_end();
        continue;
      }
      run_decode_submsg(id, hex, depth, mds, n_mds, links, link_lens);
    } else if (strcmp(op, "arena_info") == 0) {
      run_arena_info(id);
    } else if (strcmp(op, "arena_trace") == 0) {
      run_arena_trace(id, line);
    } else if (strcmp(op, "arena_fuse") == 0) {
      run_arena_fuse(id, line);
    } else if (strcmp(op, "array_trace") == 0) {
      run_array_trace(id, line);
    } else if (strcmp(op, "map_trace") == 0) {
      run_map_trace(id, line);
    } else {
      emit_header(id, "error");
      emit_field_str("code", "unknown_op");
      emit_end();
    }
  }
  return 0;
}
