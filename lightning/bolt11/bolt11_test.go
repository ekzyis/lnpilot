package bolt11

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	_secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ekzyis/lntutor/lib/secp256k1"
	"github.com/stretchr/testify/assert"
)

var (
	timestamp             = time.Unix(1496314658, 0)
	privKeyBytes, _       = hex.DecodeString("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")
	paymentSecretBytes, _ = hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	paymentHashBytes, _   = hex.DecodeString("0001020304050607080900010203040506070809000102030405060708090102")
)

// TestSigner generates deterministic compact ECDSA signatures
// over secp256k1 using RFC6979 and HMAC-SHA256.
type TestSigner struct{}

func (s *TestSigner) CompactECDSASign(msg []byte) (secp256k1.CompactECDSASignature, error) {
	privKey := _secp256k1.PrivKeyFromBytes(privKeyBytes)

	hash := sha256.Sum256(msg)
	// this will generate a deterministic compact ECDSA signature according to RFC 6979
	sig := ecdsa.SignCompact(privKey, hash[:], true)

	return secp256k1.CompactECDSASignature{
		RecoveryId: sig[0] - 27 - 4,
		R:          [32]byte(sig[1:33]),
		S:          [32]byte(sig[33:65]),
	}, nil
}

func TestPaymentRequest_EncodeBech32_Spec_001(t *testing.T) {
	assert := assert.New(t)

	pr := NewPaymentRequest(
		0,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("Please consider supporting this project"),
		WithExpiry(0),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
	)
	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_002(t *testing.T) {
	assert := assert.New(t)

	pr := NewPaymentRequest(
		250_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("1 cup coffee"),
		WithExpiry(60*time.Second),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
	)
	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_003(t *testing.T) {
	assert := assert.New(t)

	pr := NewPaymentRequest(
		250_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("ナンセンス 1杯"),
		WithExpiry(60*time.Second),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
	)
	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr",
		encoded,
	)
}
