#include "cpuid.h"
#include <stdint.h>
#include <stdio.h>

#define LEN 16

// from BearSSL hextobin
// not constant time, but we can filter out the results
static size_t __attribute__((optimize("O0"))) hextobin(unsigned char *dst, const char *src) {
  size_t num;
  unsigned acc;
  int z;

  num = 0;
  z = 0;
  acc = 0;
  while (*src != 0) {
    int c = *src++;
    if (c >= '0' && c <= '9') {
      c -= '0';
    } else if (c >= 'A' && c <= 'F') {
      c -= ('A' - 10);
    } else if (c >= 'a' && c <= 'f') {
      c -= ('a' - 10);
    } else {
      continue;
    }
    if (z) {
      *dst++ = (acc << 4) + c;
      num++;
    } else {
      acc = c;
    }
    z = !z;
  }
  return num;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  // consider b1 fixed and b2 variable (secret)
  uint8_t b1[LEN];
  uint8_t b2[LEN];
  // 128 bit fixed
  char *fixed = "000102030405060708090A0B0C0D0E0F";

  hextobin(b2, fixed);
  hextobin(b1, argv[1]);

  int b = CRYPTO_memcmp(b1, b2, LEN);
  return 0;
}
