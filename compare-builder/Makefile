CFLAGS ?= -O3 -gdwarf-4
CC ?= gcc

all: driver

.PHONY: clean

libcompare.so: lib.c
	$(CC) $(CFLAGS) lib.c -o libcompare.so -shared

driver: libcompare.so
	$(CC) $(CFLAGS) main.c -L. -lcompare -o driver.bin

clean:
	rm *.bin *.so