#!/bin/sh
$IDO7RECOMP -non_shared -G 0 -c test.c
mips-linux-gnu-ld test.o --defsym test2=420
mips-linux-gnu-objcopy -O binary a.out rom.bin
