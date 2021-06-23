#!/usr/bin/env bash
set -Eeuo pipefail

cd ~/scion

rm -rf gen*
export PYTHONPATH=python/:.
printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip
python3 python/topology/generator.py -c ~/lightning-filter/testnet/tiny4.topo
rm gen/jaeger-dc.yml
mkdir gen-cache

cd ~/lightning-filter/testnet/
rm -rf gen/ASff00_0_110/certs
rm -rf gen/ASff00_0_110/crypto
rm -rf gen/ASff00_0_110/keys
rm -rf gen/ASff00_0_111/certs
rm -rf gen/ASff00_0_111/crypto
rm -rf gen/ASff00_0_111/keys
rm -rf gen/ASff00_0_112/certs
rm -rf gen/ASff00_0_112/crypto
rm -rf gen/ASff00_0_112/keys
rm -rf gen/ISD1/trcs
rm -rf gen/certs
rm -rf gen/trcs
rm -rf gen-eh/ASff00_0_111/certs
rm -rf gen-eh/ASff00_0_111/crypto
rm -rf gen-eh/ASff00_0_111/keys
rm -rf gen-eh/ASff00_0_112/certs
rm -rf gen-eh/ASff00_0_112/crypto
rm -rf gen-eh/ASff00_0_112/keys

cp -r ~/scion/gen/ASff00_0_110/certs ~/lightning-filter/testnet/gen/ASff00_0_110/
cp -r ~/scion/gen/ASff00_0_110/crypto ~/lightning-filter/testnet/gen/ASff00_0_110/
cp -r ~/scion/gen/ASff00_0_110/keys ~/lightning-filter/testnet/gen/ASff00_0_110/

cp -r ~/scion/gen/ASff00_0_111/certs ~/lightning-filter/testnet/gen/ASff00_0_111/
cp -r ~/scion/gen/ASff00_0_111/crypto ~/lightning-filter/testnet/gen/ASff00_0_111/
cp -r ~/scion/gen/ASff00_0_111/keys ~/lightning-filter/testnet/gen/ASff00_0_111/

cp -r ~/scion/gen/ASff00_0_112/certs ~/lightning-filter/testnet/gen/ASff00_0_112/
cp -r ~/scion/gen/ASff00_0_112/crypto ~/lightning-filter/testnet/gen/ASff00_0_112/
cp -r ~/scion/gen/ASff00_0_112/keys ~/lightning-filter/testnet/gen/ASff00_0_112/

cp -r ~/scion/gen/ISD1/trcs ~/lightning-filter/testnet/gen/ISD1/
cp -r ~/scion/gen/certs ~/lightning-filter/testnet/gen/
cp -r ~/scion/gen/trcs ~/lightning-filter/testnet/gen/

cp -r ~/scion/gen/ASff00_0_111/certs ~/lightning-filter/testnet/gen-eh/ASff00_0_111/
cp -r ~/scion/gen/ASff00_0_111/crypto ~/lightning-filter/testnet/gen-eh/ASff00_0_111/
cp -r ~/scion/gen/ASff00_0_111/keys ~/lightning-filter/testnet/gen-eh/ASff00_0_111/

cp -r ~/scion/gen/ASff00_0_112/certs ~/lightning-filter/testnet/gen-eh/ASff00_0_112/
cp -r ~/scion/gen/ASff00_0_112/crypto ~/lightning-filter/testnet/gen-eh/ASff00_0_112/
cp -r ~/scion/gen/ASff00_0_112/keys ~/lightning-filter/testnet/gen-eh/ASff00_0_112/

rm -rf gen-cache
mkdir gen-cache
