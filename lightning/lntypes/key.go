package lntypes

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type NodePrivateKey struct {
	secp256k1 secp256k1.PrivateKey
}

type NodePublicKey struct {
	secp256k1 secp256k1.PublicKey
}

func NewNodePrivateKey(secp256k1 *secp256k1.PrivateKey) *NodePrivateKey {
	return &NodePrivateKey{
		secp256k1: *secp256k1,
	}
}

func (k NodePrivateKey) PubKey() *NodePublicKey {
	return &NodePublicKey{
		secp256k1: *k.secp256k1.PubKey(),
	}
}

func NewNodePublicKey(secp256k1 *secp256k1.PublicKey) *NodePublicKey {
	return &NodePublicKey{
		secp256k1: *secp256k1,
	}
}

func ParseNodePublicKeyFromHex(hexStr string) (*NodePublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key as hex: %s: %w", hexStr, err)
	}
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return NewNodePublicKey(pubKey), nil
}

func MustParseNodePublicKeyFromHex(hexStr string) *NodePublicKey {
	pubKey, err := ParseNodePublicKeyFromHex(hexStr)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func (k NodePublicKey) SerializeCompressed() ([]byte, error) {
	return k.secp256k1.SerializeCompressed(), nil
}

func ParseNodePublicKeyFromBytes(bytes []byte) (*NodePublicKey, error) {
	pubKey, err := secp256k1.ParsePubKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return NewNodePublicKey(pubKey), nil
}
