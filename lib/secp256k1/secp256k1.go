package secp256k1

// CompactECDSASignature is a compact ECDSA signature over secp256k1.
type CompactECDSASignature struct {
	RecoveryId byte
	R          [32]byte
	S          [32]byte
}

type Signer interface {
	// CompactECDSASign returns a compact ECDSA signature over secp256k1. The
	// message will be hashed using sha256 before signing.
	CompactECDSASign(msg []byte) (CompactECDSASignature, error)
}
