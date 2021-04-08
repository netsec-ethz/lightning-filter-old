#!/bin/bash
set -e

pushd .
rm -f *.o libds.a
gcc -I./libcuckoofilter/include -L./libcuckoofilter -m64 -c ds.c -o ds.o -O3
ar cru libds.a ds.o
ar cru libds.a ./libcuckoofilter/cuckoo_filter.o
popd
