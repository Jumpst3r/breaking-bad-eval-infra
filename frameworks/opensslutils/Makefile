CC ?= gcc
CFLAGS ?= -gdwarf-4

all: cpuid.c main.c
	$(CC) cpuid.c main.c -static $(CFLAGS) -o driver.bin 

clean:
	rm *.bin

.PHONY:
	clean
