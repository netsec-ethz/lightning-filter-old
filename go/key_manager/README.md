This subdiretory contains the mock wrapper for sciond to obtain DRKeys.
The file is compiled as a shared library and called from the c code in 
the LighningFilter application. The code creates a mock DRKey metadata struct and copies
it to a pre-allocated memory location on the c heap. Therefore it is important that the pointer
passed to the wrapper has been allocated in advance.

The mock part generates one of two deterministic key structs, based on the arguments. The BeginEpoch argument is a timestamp,
from this timestamp we extract the curretn second. If it is in the first half of a minute we return key1
and if it is in the second half we generate key2. This enables easy testing. 

Currently both the mock code and the wrapper code are both contained in the same file
as I wasn't able to compile it otherwise. It could be easily separated into two files 
so that the mock part can be swapped out and replaced by the actual sciond call.

To build:
1. Run the build.sh file

Alternatively:
1. Compile go code to shared lib with: 
"go build -o go_key_manager.so -buildmode=c-shared go_key_manager.go"
2. Copy the generated .so and .h file to the /lib/go in the source directory.