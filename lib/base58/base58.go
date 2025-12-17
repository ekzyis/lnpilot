package base58

import "github.com/btcsuite/btcd/btcutil/base58"

// Encode encodes a byte slice to a modified base58 string.
func Encode(data []byte) string {
	return base58.Encode(data)
}

// Decode decodes a modified base58 string to a byte slice.
// It does not verify the checksum.
func Decode(data string) []byte {
	return base58.Decode(data)
}

// DecodeAddress decodes a base58 address  and returns the
// network ID and the ripemd160 hash of the pubkey or script.
func DecodeAddress(addr string) (byte, []byte) {
	decoded := Decode(addr)
	netID := decoded[0]
	hash160 := decoded[1 : len(decoded)-4]
	// TODO: verify checksum?
	// checkSum := decoded[len(decoded)-4:]
	return netID, hash160
}
