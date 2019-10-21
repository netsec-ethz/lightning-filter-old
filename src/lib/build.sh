#!/bin/bash

pushd .
rm *.o libds.a
gcc -I$(pwd)/libcuckoofilter/include -L$(pwd)/libcuckoofilter -m64 -c ds.c -o ds.o -O3 -g
ar cru libds.a ds.o
ar cru libds.a $(pwd)/libcuckoofilter/cuckoo_filter.o
popd
