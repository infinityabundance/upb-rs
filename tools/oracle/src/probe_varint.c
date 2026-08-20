// Probe: raw varint reads through the upstream reader. Tooling only.
#include <stdio.h>
#include <string.h>
#include "upb/mem/arena.h"
#include "upb/wire/eps_copy_input_stream.h"
#include "upb/wire/reader.h"

static void rd(const char* name, const unsigned char* data, size_t n) {
  const char* buf;
  upb_EpsCopyInputStream e;
  const char* ptr = (const char*)data;
  upb_EpsCopyInputStream_Init(&e, &ptr, n);
  // Init may copy into a patch buffer; use the refreshed ptr.
  uint64_t val = 999;
  const char* after = upb_WireReader_ReadVarint(ptr, &val, &e);
  printf("%-12s n=%zu val=%llu (0x%llx) consumed=%ld\n", name, n,
         (unsigned long long)val, (unsigned long long)val,
         after ? (long)(after - ptr) : -1L);
}

int main(void) {
  const unsigned char a[] = {0x85, 0x00};
  const unsigned char b[] = {0x85, 0x80, 0x00};
  const unsigned char c[] = {0x85, 0x01};
  const unsigned char d[] = {0x81, 0x00};
  rd("8500", a, 2);
  rd("858000", b, 3);
  rd("8501", c, 2);
  rd("8100", d, 2);
  return 0;
}
