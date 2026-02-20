package lntypes

import (
	"crypto/sha256"

	"github.com/ekzyis/lnpilot/lib/bech32"
)

type Hash [32]byte

func (h *Hash) Bytes() []byte {
	return h[:]
}

func (h *Hash) IsZero() bool {
	return *h == [32]byte{}
}

func (h *Hash) EncodeBolt11() ([]byte, error) {
	return bech32.NewBytesBase32Encoder(h[:]).EncodeBase32()
}

func (h *Hash) DecodeBolt11(data []byte) error {
	hash, err := bech32.NewBytesBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}
	copy(h[:], hash)
	return nil
}

type Preimage [32]byte

func (p Preimage) Hash() Hash {
	return Hash(sha256.Sum256(p[:]))
}

type HMAC [32]byte
