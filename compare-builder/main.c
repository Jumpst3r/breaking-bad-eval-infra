#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"

int main(int arc, char **argv) {
  uint32_t x = 5;
  uint32_t y = 10;
  uint32_t (*fct)(uint32_t, uint32_t, bool);
  // read secret from arg list
  bool bit = !(strcmp("0", argv[1]));    
  // read target function from arg list
  if (strcmp("ct_select_v0", argv[2]) == 0) fct = ct_select_u32_naive;
  else if (strcmp("ct_select_v1", argv[2]) == 0) fct = ct_select_u32_v1;
  else if (strcmp("ct_select_v2", argv[2]) == 0) fct = ct_select_u32_v2;
  else if (strcmp("ct_select_v3", argv[2]) == 0) fct = ct_select_u32_v3;
  int c = fct(x,y,bit);
  // avoid the compiler optimizing away the function call
  printf("Return: %d\n", c);
  return 0;
}
