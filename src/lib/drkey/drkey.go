// Copyright (c) 2021, [fullname]
// All rights reserved.

package main

import (
	"C"
	"unsafe"

	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/sciond"
)

//export GetDelegationSecret
func GetDelegationSecret(sciondAddr *C.char, srcIA, dstIA uint64, valTime int64,
	validityNotBefore, validityNotAfter *int64, key unsafe.Pointer) int {
	sd, err := sciond.NewService(C.GoString(sciondAddr)).Connect(context.Background())
	if err != nil {
		return -1
	}

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	dsMeta := drkey.Lvl2Meta{
		KeyType:  drkey.AS2AS,
		Protocol: "piskes",
		SrcIA:    addr.IAInt(srcIA).IA(),
		DstIA:    addr.IAInt(dstIA).IA(),
	}
	lvl2Key, err := sd.DRKeyGetLvl2Key(ctx, dsMeta, time.Unix(valTime, 0).UTC())
	if err != nil {
		return -1
	}

	*validityNotBefore = lvl2Key.Epoch.NotBefore.Unix()
	*validityNotAfter = lvl2Key.Epoch.NotAfter.Unix()
	copy((*[16]byte)(key)[:], lvl2Key.Key)

	return 0
}

func main() {}
