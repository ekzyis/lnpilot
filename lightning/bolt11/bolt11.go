package bolt11

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ekzyis/lnpilot/lib/bech32"
	"github.com/ekzyis/lnpilot/lib/secp256k1"
	"github.com/ekzyis/lnpilot/lightning/lntypes"
)

// NewPaymentRequest creates a new payment request with the given amount and
// options. It returns an error if the payment request is invalid.
func NewPaymentRequest(msats uint64, options ...func(*PaymentRequest)) (*PaymentRequest, error) {
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
			WithDefaultDescription(),
		},
		options...,
	)

	for _, option := range options {
		option(pr)
	}

	err := pr.validate()
	if err != nil {
		return nil, err
	}

	return pr, nil
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

// validate checks if the payment request contains all required fields: payment
// hash, payment secret, description or description hash.
func (pr *PaymentRequest) validate() error {
	if pr.PaymentSecret.IsZero() {
		return fmt.Errorf("%w: payment secret missing", errInvalidPaymentRequest)
	}
	if pr.PaymentHash.IsZero() {
		return fmt.Errorf("%w: payment hash missing", errInvalidPaymentRequest)
	}
	if pr.Description == nil && pr.DescriptionHash.IsZero() {
		return fmt.Errorf("%w: description and description hash are both missing", errInvalidPaymentRequest)
	}
	if pr.Description != nil && !pr.DescriptionHash.IsZero() {
		return fmt.Errorf("%w: description and description hash are both present", errInvalidPaymentRequest)
	}
	return nil
}
