// Probe: does deterministic encode sort map entries? Uses 8 string keys in a
// scrambled wire order so table order and sorted order provably differ.
// Tooling only.
#include <stdio.h>
#include <string.h>
#include "upb/mem/arena.h"
#include "upb/message/message.h"
#include "upb/mini_descriptor/decode.h"
#include "upb/mini_descriptor/link.h"
#include "upb/mini_table/message.h"
#include "upb/wire/decode.h"
#include "upb/wire/encode.h"

int main(void) {
  upb_Arena* arena = upb_Arena_New();
  upb_Status st;
  upb_Status_Clear(&st);
  upb_MiniTable* mt = upb_MiniTable_Build("$G", 2, arena, &st);
  upb_MiniTable* entry = upb_MiniTable_Build("%1)", 3, arena, &st);
  if (!mt || !entry) { printf("build failed: %s\n", st.msg); return 1; }
  upb_MiniTableField* f = (upb_MiniTableField*)upb_MiniTable_GetFieldByIndex(mt, 0);
  upb_MiniTable_SetSubMessage(mt, f, entry);

  // Wire order: k5, k1, k4, k2, k7, k0, k6, k3 (scrambled).
  const char* keys[] = {"k5", "k1", "k4", "k2", "k7", "k0", "k6", "k3"};
  unsigned char input[256];
  size_t n = 0;
  for (int i = 0; i < 8; i++) {
    size_t klen = strlen(keys[i]);
    size_t plen = 1 + 1 + klen + 2; // 0A len, 0A klen key, 10 val
    input[n++] = 0x0A;
    input[n++] = (unsigned char)plen;
    input[n++] = 0x0A;
    input[n++] = (unsigned char)klen;
    memcpy(&input[n], keys[i], klen); n += klen;
    input[n++] = 0x10;
    input[n++] = (unsigned char)i;
  }

  upb_Message* msg = upb_Message_New(mt, arena);
  upb_DecodeStatus ds = upb_Decode((const char*)input, n, msg, mt, NULL, 0, arena);
  printf("decode=%d\n", (int)ds);
  if (ds != 0) return 1;
  for (int opt = 0; opt <= 1; opt++) {
    char* buf = NULL;
    size_t size = 0;
    upb_EncodeStatus es = upb_Encode(msg, mt, opt, arena, &buf, &size);
    printf("opt=%d hex=", opt);
    // Print only the entry payloads (skip tag+len of each entry) for clarity:
    // full hex otherwise.
    for (size_t i = 0; i < size; i++) printf("%02x", (unsigned char)buf[i]);
    printf("\n");
  }
  upb_Arena_Free(arena);
  return 0;
}
