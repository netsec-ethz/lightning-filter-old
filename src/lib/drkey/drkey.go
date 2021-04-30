// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
