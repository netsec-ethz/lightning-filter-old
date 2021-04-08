#!/bin/bash
set -e

rm -rf build/

UNAME_M=$(uname -m)

if [[ "$UNAME_M" == 'x86_64' ]]; then
	pushd lib/aesni
	./mk_lnx_lib.sh
	popd
fi

export RTE_SDK=~/dpdk-stable-19.11.6
export RTE_TARGET=build

make
