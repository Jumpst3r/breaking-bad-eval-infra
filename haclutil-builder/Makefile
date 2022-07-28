CC ?= gcc
CFLAGS ?= -gdwarf-4

all: cmp_bytes.c Hacl_Policies.c
	$(CC) cmp_bytes.c Hacl_Policies.c -static $(CFLAGS) -o driver.bin 

clean:
	rm *.bin

.PHONY:
	clean
