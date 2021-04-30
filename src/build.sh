#!/usr/bin/env bash
set -Eeuo pipefail

rm -rf build/

UNAME_M=$(uname -m)

if [[ "$UNAME_M" == 'x86_64' ]]; then
	pushd lib/aesni
	./build.sh
	popd
fi

pushd lib/drkey
./build.sh
popd

export RTE_SDK=~/dpdk-stable-19.11.6
export RTE_TARGET=build

make
