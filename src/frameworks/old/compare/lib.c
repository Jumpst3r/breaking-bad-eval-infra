/*
A list of comparisons which can potentially be compiled to 
non-constant time code.

Originally shown by [1] to exhibit this behavior on x86 with gcc & clang.
[2] extended this work to include compilations targetting ARM in the static case (clang & gcc).

!!!!
TODO: extended the work of [2] to analyze the behavior in the context of shared libraries on RISCV, MIPS and POWERPC, on various versions of gcc, clang and Intel's ICC
!!!

[1] Simon, Laurent, David Chisnall, and Ross Anderson. "What you get is what you C: Controlling side effects in mainstream C compilers." 2018 IEEE European Symposium on Security and Privacy (EuroS&P). IEEE, 2018.
[2] Daniel, L. A., Bardin, S., & Rezk, T. (2020, May). Binsec/rel: Efficient relational symbolic execution for constant-time at binary-level. In 2020 IEEE Symposium on Security and Privacy (SP) (pp. 1021-1038). IEEE.

*/

#include <stdint.h>
#include <stdbool.h>

/* Program */
int ct_isnonzero_u32(uint32_t x) {
  return (x|-x)>>31;
}

uint32_t ct_mask_u32(uint32_t bit) {
  return -(uint32_t) ct_isnonzero_u32(bit);
}

uint32_t ct_select_u32_v1(uint32_t x, uint32_t y, bool bit) {
  uint32_t m = ct_mask_u32(bit);
  return (x&m) | (y&~m);
}

uint32_t ct_select_u32_v2(uint32_t x, uint32_t y, bool bit) {
  uint32_t m = -(uint32_t) (((uint32_t)bit|-(uint32_t)bit)>>31);
  return (x&m) | (y&~m);
}

uint32_t ct_select_u32_v3(uint32_t x, uint32_t y, bool bit) {
  signed b = 1-bit;
  return (x*bit) | (y*b);
}


uint32_t ct_select_u32_v4(uint32_t x, uint32_t y, bool bit) {
  signed b = 0-bit;
  return (x&b) | (y&~b);
}

uint32_t ct_select_u32_naive(uint32_t x, uint32_t y, bool bit) {
  return bit ? x : y;
}
