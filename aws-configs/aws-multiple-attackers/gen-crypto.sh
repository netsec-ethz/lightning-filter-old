#!/usr/bin/env bash
set -Eeuo pipefail

SCION_DIR=~/scion

cd $SCION_DIR

rm -rf gen*
export PYTHONPATH=python/:.
printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip
python3 python/topology/generator.py -c ~/lightning-filter/aws-configs/aws-multiple-attackers/multiple.topo
rm gen/jaeger-dc.yml
mkdir gen-cache

cd ~/lightning-filter/aws-configs/aws-multiple-attackers/deployment

rm -rf AS_110/ASff00_0_110/certs
rm -rf AS_110/ASff00_0_110/crypto
rm -rf AS_110/ASff00_0_110/keys
rm -rf AS_110/ISD1/trcs
rm -rf AS_110/certs
rm -rf AS_110/trcs
cp -r $SCION_DIR/gen/ASff00_0_110/certs AS_110/ASff00_0_110/
cp -r $SCION_DIR/gen/ASff00_0_110/crypto AS_110/ASff00_0_110/
cp -r $SCION_DIR/gen/ASff00_0_110/keys AS_110/ASff00_0_110/
cp -r $SCION_DIR/gen/ISD1/trcs AS_110/ISD1/
cp -r $SCION_DIR/gen/certs AS_110/
cp -r $SCION_DIR/gen/trcs AS_110

rm -rf AS_111/ASff00_0_111/certs
rm -rf AS_111/ASff00_0_111/crypto
rm -rf AS_111/ASff00_0_111/keys
rm -rf AS_111/ISD1/trcs
rm -rf AS_111/certs
rm -rf AS_111/trcs
cp -r $SCION_DIR/gen/ASff00_0_111/certs AS_111/ASff00_0_111/
cp -r $SCION_DIR/gen/ASff00_0_111/crypto AS_111/ASff00_0_111/
cp -r $SCION_DIR/gen/ASff00_0_111/keys AS_111/ASff00_0_111/
cp -r $SCION_DIR/gen/ISD1/trcs AS_111/ISD1/
cp -r $SCION_DIR/gen/certs AS_111/
cp -r $SCION_DIR/gen/trcs AS_111

rm -rf AS_112/ASff00_0_112/certs
rm -rf AS_112/ASff00_0_112/crypto
rm -rf AS_112/ASff00_0_112/keys
rm -rf AS_112/ISD1/trcs
rm -rf AS_112/certs
rm -rf AS_112/trcs
cp -r $SCION_DIR/gen/ASff00_0_112/certs AS_112/ASff00_0_112/
cp -r $SCION_DIR/gen/ASff00_0_112/crypto AS_112/ASff00_0_112/
cp -r $SCION_DIR/gen/ASff00_0_112/keys AS_112/ASff00_0_112/
cp -r $SCION_DIR/gen/ISD1/trcs AS_112/ISD1/
cp -r $SCION_DIR/gen/certs AS_112/
cp -r $SCION_DIR/gen/trcs AS_112

rm -rf AS_113/ASff00_0_113/certs
rm -rf AS_113/ASff00_0_113/crypto
rm -rf AS_113/ASff00_0_113/keys
rm -rf AS_113/ISD1/trcs
rm -rf AS_113/certs
rm -rf AS_113/trcs
cp -r $SCION_DIR/gen/ASff00_0_113/certs AS_113/ASff00_0_113/
cp -r $SCION_DIR/gen/ASff00_0_113/crypto AS_113/ASff00_0_113/
cp -r $SCION_DIR/gen/ASff00_0_113/keys AS_113/ASff00_0_113/
cp -r $SCION_DIR/gen/ISD1/trcs AS_113/ISD1/
cp -r $SCION_DIR/gen/certs AS_113/
cp -r $SCION_DIR/gen/trcs AS_113

rm -rf AS_114/ASff00_0_114/certs
rm -rf AS_114/ASff00_0_114/crypto
rm -rf AS_114/ASff00_0_114/keys
rm -rf AS_114/ISD1/trcs
rm -rf AS_114/certs
rm -rf AS_114/trcs
cp -r $SCION_DIR/gen/ASff00_0_114/certs AS_114/ASff00_0_114/
cp -r $SCION_DIR/gen/ASff00_0_114/crypto AS_114/ASff00_0_114/
cp -r $SCION_DIR/gen/ASff00_0_114/keys AS_114/ASff00_0_114/
cp -r $SCION_DIR/gen/ISD1/trcs AS_114/ISD1/
cp -r $SCION_DIR/gen/certs AS_114/
cp -r $SCION_DIR/gen/trcs AS_114

rm -rf AS_115/ASff00_0_115/certs
rm -rf AS_115/ASff00_0_115/crypto
rm -rf AS_115/ASff00_0_115/keys
rm -rf AS_115/ISD1/trcs
rm -rf AS_115/certs
rm -rf AS_115/trcs
cp -r $SCION_DIR/gen/ASff00_0_115/certs AS_115/ASff00_0_115/
cp -r $SCION_DIR/gen/ASff00_0_114/crypto AS_115/ASff00_0_115/
cp -r $SCION_DIR/gen/ASff00_0_115/keys AS_115/ASff00_0_115/
cp -r $SCION_DIR/gen/ISD1/trcs AS_115/ISD1/
cp -r $SCION_DIR/gen/certs AS_115/
cp -r $SCION_DIR/gen/trcs AS_115