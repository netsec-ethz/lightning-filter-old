#!/bin/bash
set -e

rm -rf build/
pushd lib/aesni
./mk_lnx_lib.sh
popd

export RTE_SDK=~/dpdk-19.05/
export RTE_TARGET=x86_64-native-linuxapp-gcc
# export AESNI_MULTI_BUFFER_LIB_PATH=~/intel-ipsec-mb-0.44

make
