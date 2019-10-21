package sciond_mock

import (
	"time"
)

type IA struct {
	uint64
}

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
	DRey  string
}

type Lvl2DRKey struct {
	KeyType  Lvl2KeyType
	Protocol string
	Epoch    Epoch
	SrcIA    IA
	DstIA    IA
	DRey     string
}

func GetMockEpoch(valTime uint32) int {
	return 1
}

func Mock_getDRKey(keytype Lvl2KeyType, prot string, valTime uint32, srcIA, dstIA IA) *Lvl2DRKey {
	return nil
}
