package secp256k1

import (
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type PrivateKey = secp256k1.PrivateKey
type PublicKey = secp256k1.PublicKey
type JacobianPoint = secp256k1.JacobianPoint
type ModNScalar = secp256k1.ModNScalar
type FieldVal = secp256k1.FieldVal

// CompactECDSASignature is a compact ECDSA signature over secp256k1.
type CompactECDSASignature struct {
	RecoveryId byte
	R          [32]byte
	S          [32]byte
}

type Signer interface {
	// CompactECDSASign returns a deterministic, compact, low-S ECDSA signature
	// over secp256k1 according to RFC6979 and BIP62. The message will be hashed
	// using sha256 before signing. The signature will reference a compressed
	// public key.
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

func PrivKeyFromBytes(privKeyBytes []byte) *PrivateKey {
	return secp256k1.PrivKeyFromBytes(privKeyBytes)
}

func GeneratePrivateKey() (*PrivateKey, error) {
	return secp256k1.GeneratePrivateKey()
}

func NewPublicKey(x *FieldVal, y *FieldVal) *PublicKey {
	return secp256k1.NewPublicKey(x, y)
}

func ParsePubKey(serialized []byte) (*PublicKey, error) {
	return secp256k1.ParsePubKey(serialized)
}

func ScalarMultNonConst(k *ModNScalar, point *JacobianPoint, result *JacobianPoint) {
	secp256k1.ScalarMultNonConst(k, point, result)
}

// CompactECDSASign returns a deterministic, compact, low-S ECDSA signature over
// secp256k1 according to RFC6979 and BIP62. The message will be hashed using
// sha256 before signing. The signature will reference a compressed public key.
func (s *PrivateKeySigner) CompactECDSASign(msg []byte) (*CompactECDSASignature, error) {
	hash := sha256.Sum256(msg)

	// flag for SignCompact to indicate if the produced signature should
	// reference a compressed public key
	compressed := true

	// this will generate a deterministic, compact, low-S ECDSA signature
	// according to RFC6979 and BIP62, referencing a compressed public key.
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

func NewCompactECDSASignatureFromBytes(sigBytes []byte) (*CompactECDSASignature, error) {
	if len(sigBytes) != 65 {
		return nil, fmt.Errorf("signature bytes must be 65 bytes long, got %d", len(sigBytes))
	}
	return &CompactECDSASignature{
		RecoveryId: sigBytes[64] + compactSigMagicOffset + compactSigCompPubKey,
		R:          [32]byte(sigBytes[:32]),
		S:          [32]byte(sigBytes[32:64]),
	}, nil
}

func (sig *CompactECDSASignature) Verify(msg []byte) bool {
	var (
		sigBytes = make([]byte, 65)
		hash     = sha256.Sum256(msg)
		r        = new(secp256k1.ModNScalar)
		s        = new(secp256k1.ModNScalar)
	)

	sigBytes[0] = sig.RecoveryId
	copy(sigBytes[1:33], sig.R[:])
	copy(sigBytes[33:65], sig.S[:])

	pubKey, _, err := ecdsa.RecoverCompact(sigBytes, hash[:])
	if err != nil {
		return false
	}

	s.SetBytes(&sig.S)
	r.SetBytes(&sig.R)
	rawSig := ecdsa.NewSignature(r, s)
	return rawSig.Verify(hash[:], pubKey)
}

func (sig *CompactECDSASignature) NegateS() *CompactECDSASignature {
	s := new(secp256k1.ModNScalar)
	s.SetBytes(&sig.S)
	s.Negate()

	return &CompactECDSASignature{
		RecoveryId: sig.RecoveryId,
		R:          sig.R,
		S:          [32]byte(s.Bytes()),
	}
}

func (sig *CompactECDSASignature) IsHighS() bool {
	s := new(secp256k1.ModNScalar)
	s.SetBytes(&sig.S)
	return s.IsOverHalfOrder()
}
