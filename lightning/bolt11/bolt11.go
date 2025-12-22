package bolt11

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ekzyis/lntutor/lib/bech32"
	"github.com/ekzyis/lntutor/lib/secp256k1"
	"github.com/ekzyis/lntutor/lightning/lntypes"
)

func NewPaymentRequest(msats uint64, options ...func(*PaymentRequest)) *PaymentRequest {
	var paymentSecret lntypes.Hash
	// rand.Read never returns an error, and always fills the buffer entirely
	// see https://pkg.go.dev/crypto/rand#Read
	rand.Read(paymentSecret[:])

	pr := &PaymentRequest{
		Network:   lntypes.NetworkMainnet,
		Msats:     lntypes.MilliSatoshi(msats),
		Timestamp: time.Now(),
	}

	// default options
	options = append(
		[]func(*PaymentRequest){
			WithRandomPaymentSecret(),
			WithRandomPaymentHash(),
			WithDefaultExpiry(),
			WithDefaultMinFinalCLTVExpiryDelta(),
		},
		options...,
	)

	for _, option := range options {
		option(pr)
	}

	return pr
}

func (pr *PaymentRequest) sign(signer secp256k1.Signer, buf *bytes.Buffer, hrp string) error {
	// The signature is over the sha256 hash of hrp + data part encoded in
	// base256.
	bufBase256, err := bech32.ConvertBits(buf.Bytes(), 5, 8, true)
	if err != nil {
		return fmt.Errorf("failed to convert buffer to base256: %w", err)
	}
	// hrp as utf-8 bytes
	msg := append([]byte(hrp), bufBase256...)

	// this will hash the message before signing
	sig, err := signer.CompactECDSASign(msg)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	var sigBytes bytes.Buffer
	sigBytes.Write(sig.R[:])
	sigBytes.Write(sig.S[:])
	sigBytes.WriteByte(sig.RecoveryId)
	sigBase32, err := bech32.ConvertBits(sigBytes.Bytes(), 8, 5, true)
	if err != nil {
		return fmt.Errorf("failed to convert signature to base32: %w", err)
	}

	buf.Write(sigBase32)

	return nil
}
