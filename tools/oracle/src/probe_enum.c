// Probe: closed-enum decode with DisableFastTable, several payloads, dumping
// unknown segments. Tooling only.
#include <stdio.h>
#include <string.h>
#include "upb/mem/arena.h"
#include "upb/message/array.h"
#include "upb/message/message.h"
#include "upb/message/unknown_fields.h"
#include "upb/mini_descriptor/decode.h"
#include "upb/mini_descriptor/link.h"
#include "upb/mini_table/message.h"
#include "upb/wire/decode.h"

static void run(const char* name, const unsigned char* input, size_t n) {
  upb_Arena* arena = upb_Arena_New();
  upb_Status st;
  upb_Status_Clear(&st);
  upb_MiniTable* mt = upb_MiniTable_Build("$H", 2, arena, &st);
  upb_MiniTableEnum* en = upb_MiniTableEnum_Build("!(", 2, arena, &st);
  upb_MiniTableField* f = (upb_MiniTableField*)upb_MiniTable_GetFieldByIndex(mt, 0);
  upb_MiniTable_SetSubEnum(mt, f, en);
  printf("== %s: field mode=%u type=%u offset=%u\n", name,
         (unsigned)f->mode_dont_copy_me__upb_internal_use_only,
         (unsigned)f->descriptortype_dont_copy_me__upb_internal_use_only,
         (unsigned)f->offset_dont_copy_me__upb_internal_use_only);
  for (int opt = 0; opt <= 1; opt++) {
  upb_Message* msg = upb_Message_New(mt, arena);
  upb_DecodeStatus ds = upb_Decode((const char*)input, n, msg, mt, NULL,
                                   opt ? kUpb_DecodeOption_DisableFastTable : 0, arena);
  printf("%-16s opt=%s status=%d", name, opt ? "slow" : "fast", (int)ds);
  const upb_Array* arr = *(const upb_Array**)((const char*)msg + 8);
  if (arr) {
    const unsigned char* data = (const unsigned char*)upb_Array_DataPtr(arr);
    printf(" arr[%zu]:", upb_Array_Size(arr));
    for (size_t i = 0; i < upb_Array_Size(arr); i++)
      printf(" %02x%02x%02x%02x", data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]);
  }
  uintptr_t iter = 0;
  upb_MessageUnknown u;
  printf(" unknown:");
  while (upb_Message_NextUnknown2(msg, &u, &iter)) {
    printf(" [");
    for (size_t i = 0; i < u.value.bytes.size; i++) printf("%02x", (unsigned char)u.value.bytes.data[i]);
    printf("]");
  }
  printf("\n");
  }
}

int main(void) {
  const unsigned char a[] = {0x0a, 0x01, 0x05};            // packed {5} (invalid only)
  const unsigned char b[] = {0x0a, 0x02, 0x85, 0x00};      // packed overlong 5
  const unsigned char c[] = {0x0a, 0x03, 0x05, 0x06, 0x07};// packed {5,6,7} all invalid
  const unsigned char d[] = {0x0a, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}; // {1..6}
  const unsigned char e[] = {0x0a, 0x02, 0x01, 0x05};      // packed {1,5}
  const unsigned char f[] = {0x08, 0x85, 0x00};            // unpacked overlong invalid
  const unsigned char g[] = {0x08, 0x05};                  // unpacked invalid
  run("a", a, sizeof(a));
  run("b", b, sizeof(b));
  run("c", c, sizeof(c));
  run("d", d, sizeof(d));
  run("e", e, sizeof(e));
  const unsigned char h[] = {0x0a, 0x02, 0x81, 0x00};            // packed overlong 1 (VALID)
  const unsigned char i[] = {0x0a, 0x03, 0x85, 0x80, 0x00};      // packed 3-byte overlong 5
  const unsigned char j[] = {0x0a, 0x02, 0x85, 0x01};            // packed 5 | (1<<7) = 133
  const unsigned char k[] = {0x0a, 0x02, 0x82, 0x00};            // packed overlong 2 (VALID)
  run("h", h, sizeof(h));
  run("i", i, sizeof(i));
  run("j", j, sizeof(j));
  const unsigned char l[] = {0x0a, 0x03, 0x05, 0x85, 0x00};        // packed {5, overlong-5}
  const unsigned char m[] = {0x0a, 0x04, 0x85, 0x00, 0x85, 0x00};  // {overlong-5, overlong-5}
  const unsigned char n[] = {0x0a, 0x04, 0x85, 0x00, 0x08, 0x05};  // {overlong-5, 5}
  run("l", l, sizeof(l));
  run("m", m, sizeof(m));
  const unsigned char o[] = {0x0a, 0x02, 0x86, 0x00};       // overlong 6
  const unsigned char p[] = {0x0a, 0x03, 0x86, 0x80, 0x00}; // 3-byte overlong 6
  const unsigned char q[] = {0x0a, 0x04, 0x86, 0x80, 0x80, 0x00}; // 4-byte overlong 6
  const unsigned char r[] = {0x0a, 0x02, 0x80, 0x01};       // 128
  const unsigned char s[] = {0x0a, 0x03, 0x80, 0x80, 0x00}; // overlong 0
  const unsigned char t[] = {0x0a, 0x01, 0x81};             // truncated varint (cont bit set)
  run("o", o, sizeof(o));
  run("p", p, sizeof(p));
  run("q", q, sizeof(q));
  run("r", r, sizeof(r));
  run("s", s, sizeof(s));
  run("t", t, sizeof(t));
  return 0;
}
