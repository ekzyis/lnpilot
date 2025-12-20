package bech32

import (
	"fmt"
	"math/bits"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

var Version0 = bech32.Version0
var VersionM = bech32.VersionM
var VersionUnknown = bech32.VersionUnknown

type Base32Encoder interface {
	EncodeBase32() ([]byte, error)
}

type BytesBase32Encoder struct {
	data []byte
}

type UintBase32Encoder struct {
	num    uint
	bitLen uint
}

type VarUintBase32Encoder struct {
	num uint
}

func NewBytesBase32Encoder(data []byte) BytesBase32Encoder {
	return BytesBase32Encoder{data: data}
}

func NewStringBase32Encoder(data string) BytesBase32Encoder {
	return BytesBase32Encoder{data: []byte(data)}
}

func NewVarUintBase32Encoder(num uint) VarUintBase32Encoder {
	return VarUintBase32Encoder{num: num}
}

func NewUintBase32Encoder(num, bitLen uint) UintBase32Encoder {
	return UintBase32Encoder{num: num, bitLen: bitLen}
}

func (e BytesBase32Encoder) EncodeBase32() ([]byte, error) {
	return bech32.ConvertBits(e.data, 8, 5, true)
}

// EncodeBase32 converts the uint value to a base32-encoded byte array in
// big-endian order. It includes zero padding to match the bit length.
func (e UintBase32Encoder) EncodeBase32() ([]byte, error) {
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
	// this fills the array from high to low indices, with the most significant
	// bits ending up at the lowest index => big-endian order
	for i := int(base32Len) - 1; i >= 0; i-- {
		// store least significant 5 bits of num at the current index
		numBase32[i] = byte(num & 0b11111)
		// shift num right by 5 bits to process the next 5 bits of higher
		// significance
		num >>= 5
	}

	return numBase32, nil
}

// EncodeBase32 converts the uint value to a variable-length base32-encoded byte
// array in big-endian order.
func (e VarUintBase32Encoder) EncodeBase32() ([]byte, error) {
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

// Decode decodes a bech32 encoded string, returning the human-readable part and
// the data part excluding the checksum.
func Decode(bech string) (string, []byte, error) {
	return bech32.Decode(bech)
}

// DecodeGeneric decodes a bech32 encoded string, returning the human-readable
// part, the data part excluding the checksum, and the version.
func DecodeGeneric(bech string) (string, []byte, bech32.Version, error) {
	return bech32.DecodeGeneric(bech)
}

// ConvertBits converts a byte array from one bit length to another.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	return bech32.ConvertBits(data, fromBits, toBits, pad)
}

// BytesToBech32 converts a byte array to a bech32 string without the checksum
// by mapping each byte to the corresponding character in the bech32 charset.
func BytesToBech32Charset(data []byte) string {
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var s string
	for _, b := range data {
		s += string(charset[b])
	}
	return s
}
