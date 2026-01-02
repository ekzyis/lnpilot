package bech32

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

const (
	Version0       = bech32.Version0
	VersionM       = bech32.VersionM
	VersionUnknown = bech32.VersionUnknown
)

var (
	ErrInvalidChecksum       = errors.New("invalid checksum")
	ErrInvalidSeparatorIndex = errors.New("invalid separator index")
	ErrMixedCase             = errors.New("mixed case")
	ErrInvalidLength         = errors.New("invalid length")
)

// ======================
// === encoding stuff ===
// ======================

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

var _ Base32Encoder = (*BytesBase32Encoder)(nil)
var _ Base32Encoder = (*UintBase32Encoder)(nil)
var _ Base32Encoder = (*VarUintBase32Encoder)(nil)

func NewBytesBase32Encoder(data []byte) BytesBase32Encoder {
	return BytesBase32Encoder{data: data}
}

func NewStringBase32Encoder(data string) BytesBase32Encoder {
	return BytesBase32Encoder{data: []byte(data)}
}

func NewUintBase32Encoder(num, bitLen uint) UintBase32Encoder {
	return UintBase32Encoder{num: num, bitLen: bitLen}
}

func NewVarUintBase32Encoder(num uint) VarUintBase32Encoder {
	return VarUintBase32Encoder{num: num}
}

func (e BytesBase32Encoder) EncodeBase32() ([]byte, error) {
	return bech32.ConvertBits(e.data, 8, 5, true)
}

// EncodeBase32 converts the uint value to a base32-encoded byte slice in
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
// slice in big-endian order.
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

// EncodeM encodes base32-encoded data into a bech32m string.
func EncodeM(hrp string, data []byte) (string, error) {
	return bech32.EncodeM(hrp, data)
}

// BytesToBech32 converts a byte slice to a bech32 string without the checksum
// by mapping each byte to the corresponding character in the bech32 charset.
func BytesToBech32Charset(data []byte) string {
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var s string
	for _, b := range data {
		s += string(charset[b])
	}
	return s
}

// ======================
// === decoding stuff ===
// ======================

type Base32Decoder[T any] interface {
	DecodeBase32() (T, error)
}

type BytesBase32Decoder struct {
	data []byte
}

type UintBase32Decoder struct {
	data []byte
}

var _ Base32Decoder[[]byte] = (*BytesBase32Decoder)(nil)
var _ Base32Decoder[uint] = (*UintBase32Decoder)(nil)

func NewBytesBase32Decoder(data []byte) BytesBase32Decoder {
	return BytesBase32Decoder{data: data}
}

func NewUintBase32Decoder(data []byte) UintBase32Decoder {
	return UintBase32Decoder{data: data}
}

// DecodeBase32 decodes the base32-encoded byte slice into a base256 byte slice.
func (d BytesBase32Decoder) DecodeBase32() ([]byte, error) {
	return bech32.ConvertBits(d.data, 5, 8, false)
}

// DecodeBase32 decodes the base32-encoded byte slice in big-endian order into a
// uint value.
func (e UintBase32Decoder) DecodeBase32() (uint, error) {
	num := uint(0)
	for i, b := range e.data {
		// big-endian order: first byte is the most significant byte, so we
		// shift it the most
		num |= uint(b) << (5 * (len(e.data) - i - 1))
	}

	return num, nil
}

// Decode decodes a bech32 encoded string, returning the human-readable part and
// the data part excluding the checksum. It validates the checksum.
func Decode(bech string) (string, []byte, error) {
	hrp, data, err := bech32.Decode(bech)
	return hrp, data, wrapLibError(err)
}

// DecodeGeneric decodes a bech32 encoded string, returning the human-readable
// part, the data part excluding the checksum, and the version. It validates the
// checksum.
func DecodeGeneric(bech string) (string, []byte, bech32.Version, error) {
	hrp, data, version, err := bech32.DecodeGeneric(bech)
	return hrp, data, version, wrapLibError(err)
}

// DecodeNoLimit decodes a bech32 encoded string, returning the human-readable
// part and the data part excluding the checksum. It validates the checksum, but
// does not validate against the BIP-173 maximum length allowed for bech32
// strings.
func DecodeNoLimit(bech string) (string, []byte, error) {
	hrp, data, err := bech32.DecodeNoLimit(bech)
	if err != nil {
		return "", nil, wrapLibError(err)
	}
	return hrp, data, wrapLibError(err)
}

// wrapLibError returns bech32 library error structs as errors created by
// errors.New() and returns them. These errors can be more conveniently used
// with errors.Is(). If the error is unknown, it is returned unchanged.
func wrapLibError(err error) error {
	// TODO: don't lose information contained in original error messages

	if errors.As(err, &bech32.ErrInvalidChecksum{}) {
		return ErrInvalidChecksum
	}

	var sepErr bech32.ErrInvalidSeparatorIndex
	if errors.As(err, &sepErr) {
		return ErrInvalidSeparatorIndex
	}

	if errors.As(err, &bech32.ErrMixedCase{}) {
		return ErrMixedCase
	}

	var lenErr bech32.ErrInvalidLength
	if errors.As(err, &lenErr) {
		return ErrInvalidLength
	}

	return err
}

// ===================
// === other stuff ===
// ===================

// ConvertBits converts a byte slice from one bit length to another.
func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	return bech32.ConvertBits(data, fromBits, toBits, pad)
}
