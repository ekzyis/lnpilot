package lntypes

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

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
