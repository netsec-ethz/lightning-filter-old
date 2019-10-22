#!/bin/bash
set -e

pushd .
rm -f *.o libaesni.a
yasm -D__linux__ -g dwarf2 -f elf64 ../aesnix64asm.s -o ../aesnix64asm.o
gcc -c -O0 -m64 cmacVScbc.c
gcc -m64 -O0 -o cmacVScbc cmacVScbc.o ../aesnix64asm.o
ar cru ../libaesni.a ../aesnix64asm.o cmacVScbc.o
popd
