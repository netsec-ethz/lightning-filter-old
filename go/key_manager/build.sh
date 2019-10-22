#!/bin/bash
set -e

go build -o go_key_manager.so -buildmode=c-shared go_key_manager.go
mkdir -p ../../src/lib/go/
cp go_key_manager.{so,h} ../../src/lib/go/
mv go_key_manager.{so,h} testing/
