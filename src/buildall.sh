rm -rf build/
cd lib/aesni
sh mk_lnx_lib.sh
cd ../../
export RTE_SDK=/home/jgude/dpdk-19.05/
export RTE_TARGET=x86_64-native-linuxapp-gcc
export AESNI_MULTI_BUFFER_LIB_PATH=/home/scion-r4/intel-ipsec-mb-0.44
make

