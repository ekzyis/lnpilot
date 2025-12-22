package bitcoin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ekzyis/lntutor/lib/base58"
	"github.com/ekzyis/lntutor/lib/bech32"
	liberr "github.com/ekzyis/lntutor/lib/error"
	"github.com/ekzyis/lntutor/lightning/lntypes"
	"golang.org/x/crypto/ripemd160"
)

var errInvalidLegacyAddress = errors.New("failed to decode as legacy address")
var errNoWitnessVersion = errors.New("no witness version")
var errInvalidWitnessVersion = errors.New("invalid witness version")

var Version0 = bech32.Version0
var VersionM = bech32.VersionM

type Address interface {
	// Encode encodes the address into the appropriate format (bech32 for
	// segwit, base58 for legacy).
	Encode() (string, error)

	// EncodeBase32 encodes the address into a base32-encoded byte slice.
	EncodeBase32() ([]byte, error)

	// EncodeBolt11 encodes the address into a base32-encoded byte slice, and
	// includes the version byte for the address type.
	EncodeBolt11() ([]byte, error)
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

var _ Address = (*SegwitAddress)(nil)
var _ Address = (*P2PKAddress)(nil)
var _ Address = (*P2PKHAddress)(nil)
var _ Address = (*P2SHAddress)(nil)

func (a *SegwitAddress) Encode() (string, error) {
	// TODO: implement
	return "", liberr.ErrNotImplemented
}

func (a *SegwitAddress) EncodeBase32() ([]byte, error) {
	base32Bytes, err := bech32.ConvertBits(a.Program, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to convert witness program to base32: %w", err)
	}
	return base32Bytes, nil
}

func (a *SegwitAddress) EncodeBolt11() ([]byte, error) {
	base32Bytes, err := a.EncodeBase32()
	if err != nil {
		return nil, err
	}
	return append([]byte{a.Version}, base32Bytes...), nil
}

func (a *P2PKAddress) Encode() (string, error) {
	// TODO: implement
	return "", liberr.ErrNotImplemented
}

func (a *P2PKAddress) EncodeBase32() ([]byte, error) {
	// TODO: implement
	return nil, liberr.ErrNotImplemented
}

func (a *P2PKAddress) EncodeBolt11() ([]byte, error) {
	// TODO: implement
	return nil, liberr.ErrNotImplemented
}

func (a *P2PKHAddress) Encode() (string, error) {
	// TODO: implement
	return "", liberr.ErrNotImplemented
}

func (a *P2PKHAddress) EncodeBase32() ([]byte, error) {
	base32Bytes, err := bech32.ConvertBits(a.PubKeyHash, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to convert pubkey hash to base32: %w", err)
	}
	return base32Bytes, nil
}

func (a *P2PKHAddress) EncodeBolt11() ([]byte, error) {
	base32Bytes, err := a.EncodeBase32()
	if err != nil {
		return nil, err
	}
	// 0x11 is the version byte for P2PKH addresses in bolt11 (17 in base10)
	return append([]byte{0x11}, base32Bytes...), nil
}

func (a *P2SHAddress) Encode() (string, error) {
	// TODO: implement
	return "", liberr.ErrNotImplemented
}

func (a *P2SHAddress) EncodeBase32() ([]byte, error) {
	base32Bytes, err := bech32.ConvertBits(a.ScriptHash, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("failed to convert script hash to base32: %w", err)
	}
	return base32Bytes, nil
}

func (a *P2SHAddress) EncodeBolt11() ([]byte, error) {
	base32Bytes, err := a.EncodeBase32()
	if err != nil {
		return nil, err
	}
	// 0x12 is the version byte for P2SH addresses in bolt11 (18 in base10)
	return append([]byte{0x12}, base32Bytes...), nil
}

// DecodeAddress decodes a base58 (legacy) or bech32 (segwit) address.
func DecodeAddress(addr string) (Address, error) {
	if isSegwitAddress(addr) {
		return DecodeSegwitAddress(addr)
	}

	a, err := DecodeLegacyAddress(addr)
	if err == errInvalidLegacyAddress {
		// we don't wrap the error because we don't want to assume it's a legacy
		// address if we failed to decode it as such.
		return nil, fmt.Errorf("failed to decode address: %s", addr)
	} else if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	return a, nil
}

func isSegwitAddress(addr string) bool {
	return strings.HasPrefix(addr, "bc1") || strings.HasPrefix(addr, "tb1")
}

// DecodeSegwitAddress decodes a segwit address - duh!
func DecodeSegwitAddress(addr string) (*SegwitAddress, error) {
	hrp, data, bech32version, err := bech32.DecodeGeneric(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode segwit address: %w", err)
	}

	var network lntypes.Network
	switch hrp {
	case "bc":
		network = lntypes.NetworkMainnet
	case "tb":
		network = lntypes.NetworkTestnet
	default:
		return nil, fmt.Errorf("invalid network: %s", hrp)
	}

	// The first byte of the decoded address is the witness version, it must
	// exist.
	if len(data) < 1 {
		return nil, errNoWitnessVersion
	}

	// ...and be <= 16.
	version := data[0]
	if version > 16 {
		return nil, errInvalidWitnessVersion
	}

	// The remaining characters of the address returned are grouped into words
	// of 5 bits. In order to restore the original witness program bytes, we'll
	// need to regroup into 8 bit words.
	base256, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}

	// The regrouped data must be between 2 and 40 bytes.
	if len(base256) < 2 || len(base256) > 40 {
		return nil, fmt.Errorf("invalid data length")
	}

	// For witness version 0, address MUST be exactly 20 or 32 bytes.
	if version == 0 && len(base256) != 20 && len(base256) != 32 {
		return nil, fmt.Errorf("invalid data length for witness version 0: %v", len(base256))
	}

	// For witness version 0, the bech32 encoding must be used.
	if version == 0 && bech32version != bech32.Version0 {
		return nil, fmt.Errorf("invalid encoding for witness version 0: expected bech32, got %v", bech32version)
	}

	// For witness version 1, the bech32m encoding must be used.
	if version == 1 && bech32version != bech32.VersionM {
		return nil, fmt.Errorf("invalid encoding for witness version 1: expected bech32m, got %v", bech32version)
	}

	return &SegwitAddress{
		Network: network,
		Version: version,
		Program: base256,
	}, nil
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
	return nil, errInvalidLegacyAddress
}
