package bitcoin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ekzyis/lntutor/lib/base58"
	"github.com/ekzyis/lntutor/lightning/lntypes"
	"golang.org/x/crypto/ripemd160"
)

var ErrInvalidLegacyAddress = errors.New("failed to decode as legacy address")
var ErrNotImplemented = errors.New("not implemented")

type Address interface {
	// Encode encodes the address into the appropriate format
	// (bech32 for segwit, base58 for legacy).
	Encode() (string, error)

	// EncodeBase32 encodes the address into a base32-encoded byte array,
	// suitable for writing as the data of a tagged field in a
	// bolt11 payment request.
	EncodeBase32() ([]byte, error)
}

type SegwitAddress struct {
	Network lntypes.Network
	Version byte
	Program []byte
}

type P2PKAddress struct {
	PubKey *secp256k1.PublicKey
}

type P2PKHAddress struct {
	PubKeyHash []byte
}

type P2SHAddress struct {
	ScriptHash []byte
}

func (a *SegwitAddress) Encode() (string, error) {
	// TODO: implement
	return "", ErrNotImplemented
}

func (a *SegwitAddress) EncodeBase32() ([]byte, error) {
	// TODO: implement
	return nil, ErrNotImplemented
}

func (a *P2PKAddress) EncodeBase32() ([]byte, error) {
	// TODO: implement
	return nil, ErrNotImplemented
}

func (a *P2PKAddress) Encode() (string, error) {
	// TODO: implement
	return "", ErrNotImplemented
}

func (a *P2PKHAddress) EncodeBase32() ([]byte, error) {
	// TODO: implement
	return nil, ErrNotImplemented
}

func (a *P2PKHAddress) Encode() (string, error) {
	// TODO: implement
	return "", ErrNotImplemented
}

func (a *P2SHAddress) EncodeBase32() ([]byte, error) {
	// TODO: implement
	return nil, ErrNotImplemented
}

func (a *P2SHAddress) Encode() (string, error) {
	// TODO: implement
	return "", ErrNotImplemented
}

// DecodeAddress decodes a base58 (legacy) or bech32 (segwit) address.
func DecodeAddress(addr string) (Address, error) {
	if isSegwitAddress(addr) {
		return DecodeSegwitAddress(addr)
	}

	a, err := DecodeLegacyAddress(addr)
	if err == ErrInvalidLegacyAddress {
		// we don't wrap the error because we don't want to assume
		// it's a legacy address if we failed to decode it as such.
		return nil, fmt.Errorf("failed to decode address: %s", addr)
	} else if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	return a, nil
}

func isSegwitAddress(addr string) bool {
	return strings.HasPrefix(addr, "bc1") || strings.HasPrefix(addr, "tb1")
}

func DecodeSegwitAddress(addr string) (*SegwitAddress, error) {
	// TODO: implement
	return nil, nil
}

func DecodeLegacyAddress(addr string) (Address, error) {
	// Serialized public keys are either 65 bytes (130 hex chars) if
	// uncompressed/hybrid or 33 bytes (66 hex chars) if compressed.
	isUncompressed := len(addr) == 130
	isCompressed := len(addr) == 66
	isPubKey := isUncompressed || isCompressed

	if isPubKey {
		serializedPubKey, err := hex.DecodeString(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode serialized public key: %w", err)
		}

		pubKey, err := secp256k1.ParsePubKey(serializedPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		return &P2PKAddress{PubKey: pubKey}, nil
	}

	netID, hash160 := base58.DecodeAddress(addr)

	switch len(hash160) {
	case ripemd160.Size:
		// check first byte to determine type but it depends on the network
		switch netID {
		case 0x00, 0x6f, 0x3f:
			return &P2PKHAddress{PubKeyHash: hash160}, nil
		case 0x05, 0xc4, 0x7b:
			return &P2SHAddress{ScriptHash: hash160}, nil
		}
	}
	return nil, ErrInvalidLegacyAddress
}
