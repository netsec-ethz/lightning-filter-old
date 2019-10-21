go build -o go_key_manager.so -buildmode=c-shared go_key_manager.go
cp go_key_manager.so ../../src/lib/go
cp go_key_manager.h ../../src/lib/go