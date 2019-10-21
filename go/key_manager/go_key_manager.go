package main

//#include <string.h>
//#include <stdint.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"
)

type IA uint64

// Key validity period
type Epoch struct {
	Begin time.Time
	End   time.Time
}

type Lvl2KeyType uint8

const (
	AS2AS Lvl2KeyType = iota
	AS2Host
	Host2Host
)

type Lvl1DRKey struct {
	Epoch Epoch
	SrcIA IA
	DstIA IA
	DRKey []byte
}

/*
 * This function generates a fake key validity epoch for the DRKey
 * metadata. All keys have the same validity to simplify testing.
 * Given a epoch begin timestamp x it returns an epoch struct with
 * epochBegin: x
 * epochEnd:   X + 90
 * That means each key is valid for 1m 30s
 */
func GetMockEpoch(beginTime uint32) Epoch {
	var KEY_INTERVAL uint32 = 90
	var endTime uint32 = beginTime + KEY_INTERVAL
	return Epoch{
		Begin: time.Unix(int64(beginTime), 0),
		End:   time.Unix(int64(endTime), 0),
	}
}

/*
 * This fucntion returns a mock state as an input
 * for the mock key generator. This is done in order to have deterministic keys
 * for testing. The state is derived from the time provided as an input.
 * From the timestamp we only evaluate the current minute to derive the state.
 * second 0 to  29 -> state 0
 * second 30 to 59 -> state 1
 */
func GetMockKeyState(valTime uint32) int {
	var currentSecond = valTime % 60
	if currentSecond >= 0 && currentSecond < 30 {
		return 0
	} else {
		return 1
	}
}

/*
 * This fuction does return a mock key for a DRKey. In order to
 * have deterministic keys for testing the function returns one of two
 * keys depending on the state that is given as an arguement.
 * Because the state is derived in another function, we assume
 * that the state is always either 1 or 0.
 */
func GetMockSecretKey(state int) []byte {
	if state == 0 || state == 1 {
		return []byte("aaaabbbbccccdddd")
	} else {
		return []byte("eeeeffffgggghhhh")
	}
}

/*
 * This fucntion mocks the API call to sciond an returns a DRKey keystruct.
 * The original API called was not entirely clear what kind of DRKey this is.
 * It should technically be the "delegation secret", but the API called it Lvl1DrKey
 * and also sometimes Lvl2DrKey.
 */
func Mock_getDRKey(keytype Lvl2KeyType, prot string, valTime uint32, srcIA, dstIA IA) Lvl1DRKey {

	// get a mock state (either 0 or 1)
	var state = GetMockKeyState(valTime)

	// generate a mock key validity (epoch)
	var epoch = GetMockEpoch(valTime)

	// generate a deterministic secret key given the mock state
	var secretKey = GetMockSecretKey(state)

	return Lvl1DRKey{
		Epoch: epoch,
		SrcIA: srcIA,
		DstIA: dstIA,
		DRKey: secretKey,
	}
}

/* copy the a byte array to a pre-allocated memory region on the C heap
 * Important! THe memory must be pre-allocated in C !
 * function wraps C.memcopy
 */
func memcpy(dst unsafe.Pointer, src []byte) int {

	n := len(src)
	if n == 0 {
		return 0
	}
	C.memcpy(dst, unsafe.Pointer(&src[0]), C.size_t(n))
	return n
}

/*
 * This function takes a Go DRKey struct and returns a ByteArray,
 * containing the serialized struct. This enables us to copy
 * the struct to C memory with a simply memcopy operation.
 * If the serializstion fails, the fuction returns an error.
 */
func SerializeLvl1DRKey(lvl1DRKey Lvl1DRKey) (*[]byte, error) {

	var resultBuffer []byte
	buffer := new(bytes.Buffer)

	// write epoch begin
	err := binary.Write(buffer, binary.LittleEndian, uint32(lvl1DRKey.Epoch.Begin.Unix()))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}

	// write epoch end
	err = binary.Write(buffer, binary.LittleEndian, uint32(lvl1DRKey.Epoch.End.Unix()))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}

	// write source AS
	err = binary.Write(buffer, binary.LittleEndian, lvl1DRKey.SrcIA)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}

	// write destionatioon AS
	err = binary.Write(buffer, binary.LittleEndian, lvl1DRKey.DstIA)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}

	//return meta data + key as one buffer
	resultBuffer = append(resultBuffer[:], buffer.Bytes()[:]...)
	resultBuffer = append(resultBuffer[:], lvl1DRKey.DRKey[:]...)
	return &resultBuffer, err
}

/*
 * Wrapper function for the c call getDRKey. This function
 * will be available through the compiled header file
 * The function does take a unsafe C pointer as an argument. This
 * pointer points to a pre-allocatied memeory location on the c heap.
 * The function will then copy the fetched (mocked) key to this memory
 * location as the Go Heap memory will be garbage Collected
 */
//export GetLvl1DRKey
func GetLvl1DRKey(keytype Lvl2KeyType, valTime uint32, srcIA, dstIA IA, cpointer unsafe.Pointer) int {

	lvl1DRKey := Mock_getDRKey(AS2AS, "scion_filter", valTime, srcIA, dstIA)
	res, err := SerializeLvl1DRKey(lvl1DRKey)
	memcpy(cpointer, *res)

	if err != nil {
		return -1
	}
	return 0
}

/*
 * Apparently the main package needs a main function
 */
func main() {

}
