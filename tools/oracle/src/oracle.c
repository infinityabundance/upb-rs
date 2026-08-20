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
#include "upb/message/message.h"
#include "upb/mini_descriptor/decode.h"
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
    } else {
      emit_header(id, "error");
      emit_field_str("code", "unknown_op");
      emit_end();
    }
  }
  return 0;
}
