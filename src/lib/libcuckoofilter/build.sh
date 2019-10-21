#!/bin/bash

#gcc -Wall -O0 -g3 -I./include src/cuckoo_filter.c tests/cuckootest.c -o test
#gcc -Wall -O0 -g3 -I./include src/cuckoo_filter.c tests/cuckootest2.c -o test2

pushd .
rm *.o libcuckoo.a
gcc -m64 -I./include  -c src/cuckoo_filter.c -o cuckoo_filter.o -O3
ar cru libcuckoo.a cuckoo_filter.o
popd

