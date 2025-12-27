package secp256k1

import (
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// CompactECDSASignature is a compact ECDSA signature over secp256k1.
type CompactECDSASignature struct {
	RecoveryId byte
	R          [32]byte
	S          [32]byte
}

type Signer interface {
	// CompactECDSASign returns a compact ECDSA signature over secp256k1. The
	// message will be hashed using sha256 before signing.
	CompactECDSASign(msg []byte) (*CompactECDSASignature, error)
}

type PrivateKeySigner struct {
	privateKey *secp256k1.PrivateKey
}

const (
	// compactSigMagicOffset is a value used when creating the compact signature
	// recovery code inherited from Bitcoin and has no meaning, but has been
	// retained for compatibility. For historical purposes, it was originally
	// picked to avoid a binary representation that would allow compact
	// signatures to be mistaken for other components.
	compactSigMagicOffset = 27

	// compactSigCompPubKey is a value used when creating the compact signature
	// recovery code to indicate the original public key was compressed.
	compactSigCompPubKey = 4
)

func NewPrivateKeySigner(bytes []byte) (Signer, error) {
	// TODO: also check if private key is in range [1, N-1]
	if len(bytes) != 32 {
		return nil, fmt.Errorf("private key bytes must be 32 bytes long, got %d bytes", len(bytes))
	}

	return &PrivateKeySigner{
		privateKey: secp256k1.PrivKeyFromBytes(bytes),
	}, nil
}

func (s *PrivateKeySigner) CompactECDSASign(msg []byte) (*CompactECDSASignature, error) {
	hash := sha256.Sum256(msg)

	// flag for SignCompact to indicate if the produced signature should
	// reference a compressed public key
	compressed := true

	// this will generate a deterministic compact ECDSA signature according to
	// RFC 6979
	sig := ecdsa.SignCompact(s.privateKey, hash[:], compressed)

	compactRecoveryId := sig[0]
	publicKeyRecoverId := compactRecoveryId - compactSigMagicOffset
	if compressed {
		publicKeyRecoverId -= compactSigCompPubKey
	}

	return &CompactECDSASignature{
		RecoveryId: publicKeyRecoverId,
		R:          [32]byte(sig[1:33]),
		S:          [32]byte(sig[33:65]),
	}, nil
}
