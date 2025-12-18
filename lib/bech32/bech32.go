package bech32

import (
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

type Base32UintEncoder struct {
	num    uint
	bitLen uint
}

type Base32VarUintEncoder struct {
	num uint
}

func (e Base32BytesEncoder) EncodeBase32() ([]byte, error) {
	return bech32.ConvertBits(e.data, 8, 5, true)
}

func NewBase32StringEncoder(data string) Base32BytesEncoder {
	return Base32BytesEncoder{data: []byte(data)}
}

func NewBase32VarUintEncoder(num uint) Base32VarUintEncoder {
	return Base32VarUintEncoder{num: num}
}

func NewBase32UintEncoder(num, bitLen uint) Base32UintEncoder {
	return Base32UintEncoder{num: num, bitLen: bitLen}
}

// EncodeBase32 converts the uint value to a base32-encoded byte array in
// big-endian order. It includes zero padding to match the bit length.
func (e Base32UintEncoder) EncodeBase32() ([]byte, error) {
	num := e.num
	bitLen := e.bitLen
	base32Len := bitLen / 5

	// this is not the same as bits.Len(num) > bitLen,
	// since the division above will floor the result.
	if bits.Len(num) > int(base32Len*5) {
		return nil, fmt.Errorf(
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

	return numBase32, nil
}

// EncodeBase32 converts the uint value to a variable-length base32-encoded byte
// array in big-endian order.
func (e Base32VarUintEncoder) EncodeBase32() ([]byte, error) {
	num := e.num
	var numBase32 []byte
	for num > 0 {
		numBase32 = append([]byte{byte(num & 0b11111)}, numBase32...)
		num >>= 5
	}
	return numBase32, nil
}

// Encode encodes base32-encoded data into a bech32 string.
func Encode(hrp string, data []byte) (string, error) {
	return bech32.Encode(hrp, data)
}

// ConvertBits converts a byte array from one bit length to another.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	return bech32.ConvertBits(data, fromBits, toBits, pad)
}
