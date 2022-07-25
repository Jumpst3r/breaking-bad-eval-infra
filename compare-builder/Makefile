CFLAGS ?= -O3 -gdwarf-4
CC ?= gcc

all: driver

.PHONY: clean

driver: lib.c main.c
	$(CC) $(CFLAGS) -static -gdwarf-4 main.c -L. lib.c -gdwarf-4 -o driver.bin

clean:
	rm *.bin *.so