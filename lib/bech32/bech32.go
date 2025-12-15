package bech32

import (
	"bytes"
	"fmt"
	"math/bits"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

type Base32Encoder interface {
	EncodeBase32() ([]byte, error)
}

type Base32BytesEncoder struct {
	data []byte
}

func (e Base32BytesEncoder) EncodeBase32() ([]byte, error) {
	return bech32.ConvertBits(e.data, 8, 5, true)
}

func NewBase32StringEncoder(data string) Base32BytesEncoder {
	return Base32BytesEncoder{data: []byte(data)}
}

// Encode encodes base32-encoded data into a bech32 string.
func Encode(hrp string, data []byte) (string, error) {
	return bech32.Encode(hrp, data)
}

// ConvertBits converts a byte array from one bit length to another.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	return bech32.ConvertBits(data, fromBits, toBits, pad)
}

// WriteUintBase32 writes a uint value to the buffer in base32 encoding and big-endian order.
// It includes zero padding to match the bit length.
func WriteUintBase32(buf *bytes.Buffer, num, bitLen uint) error {
	base32Len := bitLen / 5

	// this is not the same as bits.Len(num) > bitLen,
	// since the division above will floor the result.
	if bits.Len(num) > int(base32Len*5) {
		return fmt.Errorf(
			"number too big to fit into 5-bit groups with %d total bits: %d (0b%b)",
			bitLen, num, num,
		)
	}

	numBase32 := make([]byte, base32Len)
	// this fills the array from high to low indices,
	// with the most significant bits ending up at the lowest index
	// => big-endian order
	for i := int(base32Len) - 1; i >= 0; i-- {
		// store least significant 5 bits of num at the current index
		numBase32[i] = byte(num & 0b11111)
		// shift num right by 5 bits to process the next 5 bits of higher significance
		num >>= 5
	}

	_, err := buf.Write(numBase32)
	return err
}
