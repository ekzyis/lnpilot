package lntypes

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

type Hash [32]byte

func (h Hash) EncodeBase32() ([]byte, error) {
	return bech32.ConvertBits(h[:], 8, 5, true)
}

func (h Hash) IsZero() bool {
	return h == [32]byte{}
}

func (h Hash) EncodeBolt11() ([]byte, error) {
	return h.EncodeBase32()
}

type Preimage [32]byte

func (p Preimage) Hash() Hash {
	return Hash(sha256.Sum256(p[:]))
}
