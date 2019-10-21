#!/bin/bash

yasm="../yasm/yasm"

pushd .
rm *.o libaesni.a
$yasm -D__linux__ -g dwarf2 -f elf64 ../aesnix64asm.s -o ../aesnix64asm.o
gcc -m64 -O0 -o cbcmactest cbcmactest.c ../aesnix64asm.o
ar cru ../libaesni.a ../aesnix64asm.o cbcmactest.o
popd







