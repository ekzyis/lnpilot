package bitcoin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ekzyis/lnpilot/lib/base58"
	"github.com/ekzyis/lnpilot/lib/bech32"
	liberr "github.com/ekzyis/lnpilot/lib/error"
	"github.com/ekzyis/lnpilot/lightning/lntypes"
	"golang.org/x/crypto/ripemd160"
)

var errInvalidLegacyAddress = errors.New("failed to decode as legacy address")
var errNoWitnessVersion = errors.New("no witness version")
var errInvalidWitnessVersion = errors.New("invalid witness version")
var ErrUnknownVersion = errors.New("unknown version")

var Version0 = bech32.Version0
var VersionM = bech32.VersionM

const (
	segwitMainnetHRP      = "bc"
	segwitTestnetHRP      = "tb"
	segwitRegtestHRP      = "bcrt"
	segwitVersion0   byte = 0
	segwitVersion1   byte = 1

	p2pkhBolt11Version  = 0x11
	p2pkhMainnetVersion = 0x00 // starts with 1
	p2pkhTestnetVersion = 0x6f // starts with m or n (same for regtest)
	p2pkhSignetVersion  = 0x3f // starts with S

	p2shBolt11Version  = 0x12
	p2shMainnetVersion = 0x05 // starts with 3
	p2shTestnetVersion = 0xc4 // starts with 2 (same for regtest)
	p2shSignetVersion  = 0x7b // starts with s
)

type Address interface {
	// Encode encodes the address into a base58 string for legacy addresses, a
	// bech32 string for segwit addresses with witness version 0, or a bech32m
	// string for segwit addresses with witness version 1.
	Encode() (string, error)

	// EncodeBolt11 encodes the address into a base32-encoded byte slice, and
	// includes the version byte for the address type.
	EncodeBolt11() ([]byte, error)

	// DecodeBolt11 decodes the address from a base32-encoded byte slice.
	DecodeBolt11([]byte) error
}

type AddressBolt11Decoder struct {
	addr    *string
	network lntypes.Network
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
	Network    lntypes.Network
	PubKeyHash []byte
}

type P2SHAddress struct {
	Network    lntypes.Network
	ScriptHash []byte
}

var _ Address = (*SegwitAddress)(nil)
var _ Address = (*P2PKAddress)(nil)
var _ Address = (*P2PKHAddress)(nil)
var _ Address = (*P2SHAddress)(nil)

func NewAddressBolt11Decoder(addr *string, network lntypes.Network) AddressBolt11Decoder {
	return AddressBolt11Decoder{addr: addr, network: network}
}

func (d AddressBolt11Decoder) DecodeBolt11(data []byte) error {
	var a Address

	version := data[0]
	switch version {
	case p2pkhBolt11Version:
		a = &P2PKHAddress{Network: d.network}
	case p2shBolt11Version:
		a = &P2SHAddress{Network: d.network}
	case segwitVersion0, segwitVersion1:
		a = &SegwitAddress{Network: d.network, Version: version}
	default:
		return ErrUnknownVersion
	}

	err := a.DecodeBolt11(data)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	*d.addr, err = a.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode address: %w", err)
	}

	return nil
}

func (a *SegwitAddress) Encode() (string, error) {
	var hrp string
	switch a.Network {
	case lntypes.NetworkMainnet:
		hrp = segwitMainnetHRP
	case lntypes.NetworkTestnet:
		hrp = segwitTestnetHRP
	case lntypes.NetworkRegtest:
		hrp = segwitRegtestHRP
	default:
		return "", fmt.Errorf("invalid network: %s", a.Network)
	}

	progBase32, err := bech32.NewBytesBase32Encoder(a.Program).EncodeBase32()
	if err != nil {
		return "", fmt.Errorf("failed to encode witness program: %w", err)
	}

	data := append([]byte{a.Version}, progBase32...)

	switch a.Version {
	case segwitVersion0:
		return bech32.Encode(hrp, data)
	case segwitVersion1:
		return bech32.EncodeM(hrp, data)
	default:
		return "", errInvalidWitnessVersion
	}
}

func (a *SegwitAddress) EncodeBolt11() ([]byte, error) {
	progBase32, err := bech32.NewBytesBase32Encoder(a.Program).EncodeBase32()
	if err != nil {
		return nil, fmt.Errorf("failed to encode witness program: %w", err)
	}
	return append([]byte{a.Version}, progBase32...), nil
}

func (a *SegwitAddress) DecodeBolt11(data []byte) error {
	if len(data) < 1 {
		return errNoWitnessVersion
	}

	version, progBase32 := data[0], data[1:]
	if version > 16 {
		return errInvalidWitnessVersion
	}
	a.Version = version

	progBase256, err := bech32.NewBytesBase32Decoder(progBase32).DecodeBase32()
	if err != nil {
		return fmt.Errorf("failed to decode witness program: %w", err)
	}
	a.Program = progBase256

	return nil
}

func (a *P2PKAddress) Encode() (string, error) {
	// TODO: implement
	return "", liberr.ErrNotImplemented
}

func (a *P2PKAddress) EncodeBolt11() ([]byte, error) {
	// TODO: implement
	return nil, liberr.ErrNotImplemented
}

func (a *P2PKAddress) DecodeBolt11(data []byte) error {
	// TODO: implement
	return liberr.ErrNotImplemented
}

func (a *P2PKHAddress) Encode() (string, error) {
	var version byte
	switch a.Network {
	case lntypes.NetworkMainnet:
		version = p2pkhMainnetVersion
	case lntypes.NetworkTestnet:
		version = p2pkhTestnetVersion
	case lntypes.NetworkSignet:
		version = p2pkhSignetVersion
	default:
		return "", fmt.Errorf("invalid network: %s", a.Network)
	}
	data := append([]byte{version}, a.PubKeyHash...)
	return base58.Encode(data), nil
}

func (a *P2PKHAddress) EncodeBolt11() ([]byte, error) {
	pubKeyHashBase32, err := bech32.NewBytesBase32Encoder(a.PubKeyHash).EncodeBase32()
	if err != nil {
		return nil, fmt.Errorf("failed to encode pubkey hash: %w", err)
	}
	return append([]byte{p2pkhBolt11Version}, pubKeyHashBase32...), nil
}

func (a *P2PKHAddress) DecodeBolt11(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("invalid data length for P2PKH address: %d", len(data))
	}

	version, pubKeyHashBase32 := data[0], data[1:]

	if version != p2pkhBolt11Version {
		return fmt.Errorf("invalid version byte for P2PKH address: expected %d, got 0x%02x", p2pkhBolt11Version, version)
	}

	PubKeyHashBase256, err := bech32.NewBytesBase32Decoder(pubKeyHashBase32).DecodeBase32()
	if err != nil {
		return fmt.Errorf("failed to decode P2PKH address: %w", err)
	}
	a.PubKeyHash = PubKeyHashBase256

	if len(a.PubKeyHash) != ripemd160.Size {
		return fmt.Errorf("invalid data length for P2PKH address: expected %d, got %d", ripemd160.Size, len(a.PubKeyHash))
	}

	return nil
}

func (a *P2SHAddress) Encode() (string, error) {
	var version byte
	switch a.Network {
	case lntypes.NetworkMainnet:
		version = p2shMainnetVersion
	case lntypes.NetworkTestnet:
		version = p2shTestnetVersion
	case lntypes.NetworkSignet:
		version = p2shSignetVersion
	default:
		return "", fmt.Errorf("invalid network: %s", a.Network)
	}
	data := append([]byte{version}, a.ScriptHash...)
	return base58.Encode(data), nil
}

func (a *P2SHAddress) EncodeBolt11() ([]byte, error) {
	scriptHashBase32, err := bech32.NewBytesBase32Encoder(a.ScriptHash).EncodeBase32()
	if err != nil {
		return nil, fmt.Errorf("failed to encode script hash: %w", err)
	}
	return append([]byte{p2shBolt11Version}, scriptHashBase32...), nil
}

// DecodeBolt11 decodes a P2SH address from the tagged field data of a bolt11
// payment request. The byte slice must be in base32.
func (a *P2SHAddress) DecodeBolt11(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("invalid data length for P2SH address: %d", len(data))
	}

	version, scriptHashBase32 := data[0], data[1:]

	if version != p2shBolt11Version {
		return fmt.Errorf("invalid version byte for P2SH address: expected %d, got 0x%02x", p2shBolt11Version, version)
	}

	scriptHashBase256, err := bech32.NewBytesBase32Decoder(scriptHashBase32).DecodeBase32()
	if err != nil {
		return fmt.Errorf("failed to decode P2SH address: %w", err)
	}
	a.ScriptHash = scriptHashBase256

	if len(a.ScriptHash) != ripemd160.Size {
		return fmt.Errorf("invalid data length for P2SH address: expected %d, got %d", ripemd160.Size, len(a.ScriptHash))
	}

	return nil
}

// DecodeAddress decodes a base58 (legacy) or bech32 (segwit) address.
func DecodeAddress(addr string) (Address, error) {
	if isSegwitAddress(addr) {
		return decodeSegwitAddress(addr)
	}

	a, err := decodeLegacyAddress(addr)
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
	for _, hrp := range []string{segwitMainnetHRP, segwitTestnetHRP, segwitRegtestHRP} {
		if strings.HasPrefix(addr, hrp+"1") {
			return true
		}
	}
	return false
}

// decodeSegwitAddress decodes a segwit address - duh!
func decodeSegwitAddress(addr string) (*SegwitAddress, error) {
	hrp, data, bech32version, err := bech32.DecodeGeneric(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode segwit address: %w", err)
	}

	var network lntypes.Network
	switch hrp {
	case segwitMainnetHRP:
		network = lntypes.NetworkMainnet
	case segwitTestnetHRP:
		network = lntypes.NetworkTestnet
	case segwitRegtestHRP:
		network = lntypes.NetworkRegtest
	default:
		return nil, fmt.Errorf(
			"invalid hrp: expected %s, %s or %s, got %s",
			segwitMainnetHRP, segwitTestnetHRP, segwitRegtestHRP, hrp,
		)
	}

	// The first byte of the decoded address is the witness version, it must
	// exist.
	if len(data) < 1 {
		return nil, errNoWitnessVersion
	}

	// ...and be <= 16.
	version, progBase32 := data[0], data[1:]
	if version > 16 {
		return nil, errInvalidWitnessVersion
	}

	// The remaining characters of the address returned are grouped into words
	// of 5 bits. In order to restore the original witness program bytes, we'll
	// need to regroup into 8 bit words.
	progBase256, err := bech32.ConvertBits(progBase32, 5, 8, false)
	if err != nil {
		return nil, err
	}

	// The regrouped data must be between 2 and 40 bytes.
	if len(progBase256) < 2 || len(progBase256) > 40 {
		return nil, fmt.Errorf("invalid data length")
	}

	// For witness version 0, address MUST be exactly 20 or 32 bytes.
	if version == 0 && len(progBase256) != 20 && len(progBase256) != 32 {
		return nil, fmt.Errorf("invalid data length for witness version 0: %v", len(progBase256))
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
		Program: progBase256,
	}, nil
}

func decodeLegacyAddress(addr string) (Address, error) {
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

	if len(hash160) != ripemd160.Size {
		return nil, errInvalidLegacyAddress
	}

	var network lntypes.Network
	switch netID {
	case p2pkhMainnetVersion, p2shMainnetVersion:
		network = lntypes.NetworkMainnet
	case p2pkhTestnetVersion, p2shTestnetVersion:
		// could also be regtest since testnet magic bytes are the same
		network = lntypes.NetworkTestnet
	case p2pkhSignetVersion, p2shSignetVersion:
		network = lntypes.NetworkSignet
	}

	switch netID {
	case p2pkhMainnetVersion, p2pkhTestnetVersion, p2pkhSignetVersion:
		return &P2PKHAddress{Network: network, PubKeyHash: hash160}, nil
	case p2shMainnetVersion, p2shTestnetVersion, p2shSignetVersion:
		return &P2SHAddress{Network: network, ScriptHash: hash160}, nil
	default:
		return nil, errInvalidLegacyAddress
	}
}
