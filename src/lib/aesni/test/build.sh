#!/usr/bin/env bash
set -Eeuo pipefail

pushd .
rm -f *.o libaesni.a
yasm -D__linux__ -g dwarf2 -f elf64 ../aesnix64asm.s -o ../aesnix64asm.o
gcc -c -m64 -O0 cbcmactest.c
gcc -m64 -O0 -o cbcmactest cbcmactest.o ../aesnix64asm.o
ar cru ../libaesni.a ../aesnix64asm.o cbcmactest.o
popd
