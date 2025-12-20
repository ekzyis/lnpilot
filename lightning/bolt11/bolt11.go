package bolt11

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"iter"
	"slices"
	"time"

	"github.com/ekzyis/lntutor/lib/bech32"
	"github.com/ekzyis/lntutor/lib/bitcoin"
	"github.com/ekzyis/lntutor/lib/secp256k1"
	"github.com/ekzyis/lntutor/lightning/lntypes"
)

var (
	errFieldDataNotFound = errors.New("field data not found")
	errUnknownFieldType  = errors.New("unknown field type")
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

// EncodeBech32 returns the bech32 encoded and signed payment request
func (pr *PaymentRequest) EncodeBech32(signer secp256k1.Signer) (string, error) {
	// TODO: validate pr first?

	var buf bytes.Buffer

	// A bolt11 payment request is in the following format, encoded as bech32:
	//
	// - human-readable part:
	//   - network prefix
	//   - amount
	// - data part:
	//   - timestamp
	//   - zero or more tags
	//   - signature of sha256(hrf||data part)
	//
	// see https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

	timestampBase32, err := NewUintBolt11Encoder(uint(pr.Timestamp.Unix()), 35).EncodeBolt11()
	if err != nil {
		return "", fmt.Errorf("failed to encode timestamp: %w", err)
	}
	buf.Write(timestampBase32)

	err = pr.writeTaggedFields(&buf)
	if err != nil {
		return "", fmt.Errorf("failed to write tagged fields: %w", err)
	}

	hrp, err := pr.humanReadablePart()
	if err != nil {
		return "", err
	}

	err = pr.sign(signer, &buf, hrp)
	if err != nil {
		return "", fmt.Errorf("failed to sign payment request: %w", err)
	}

	encoded, err := bech32.Encode(hrp, buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to encode payment request as bech32: %w", err)
	}
	return encoded, nil
}

// The human-readable part contains the network prefix and the amount
func (pr *PaymentRequest) humanReadablePart() (string, error) {
	prefix, err := func() (lntypes.NetworkPrefix, error) {
		return pr.Network.Prefix(), nil
	}()
	if err != nil {
		return "", fmt.Errorf("failed to encode network: %w", err)
	}

	if pr.Msats == 0 {
		return string(prefix), nil
	}

	amt, multiplier, err := func() (lntypes.Bitcoin, lntypes.Multiplier, error) {
		// Amounts are denominated in bitcoins, not millisatoshis. This means we
		// first convert millisatoshis to picobitcoins, because that's the
		// smallest unit we can represent with our multipliers.
		//
		// The conversion math is as follows:
		//
		//   msats / 1e3 = sats
		//   sats / 1e8 = bitcoin
		//   bitcoin * 1e12 = picobitcoin
		//
		// => picobitcoins = msats * 1e12 / (1e3 * 1e8) = msats * 10
		//
		// This also makes sure that the last decimal is always a zero when
		// 'pico' is used, since HTLCs are denonimated in millisatoshis.
		units := lntypes.PicoBitcoin(pr.Msats * 10)

		var multiplier lntypes.Multiplier
		for _, multiplier = range lntypes.Multipliers {
			if units%1e3 == 0 {
				units /= 1e3
			} else {
				break
			}
		}

		// payment requests are denominated in bitcoins, and the multiplier is
		// used to represent smaller units of bitcoin
		return lntypes.Bitcoin(units), multiplier, nil
	}()
	if err != nil {
		return "", fmt.Errorf("failed to encode amount: %w", err)
	}

	return fmt.Sprintf("%s%d%s", prefix, amt, multiplier), nil
}

func (pr *PaymentRequest) writeTaggedFields(buf *bytes.Buffer) error {
	var stop func()
	pr.routingHintNext, stop = iter.Pull(slices.Values(pr.RoutingHints))
	defer stop()

	for _, fieldType := range pr.taggedFields {
		data, err := pr.getTaggedFieldData(fieldType)
		if err == errFieldDataNotFound {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get tagged field data: 0x%02x: %w", fieldType, err)
		}
		err = writeTaggedField(buf, fieldType, data)
		if err != nil {
			return fmt.Errorf("failed to write tagged field: 0x%02x: %w", fieldType, err)
		}
	}

	// TODO: write remaining tagged fields

	return nil
}

func (pr *PaymentRequest) getTaggedFieldData(fieldType TaggedFieldType) (Bolt11Encoder, error) {
	switch fieldType {
	case fieldTypeS:
		if !pr.PaymentSecret.IsZero() {
			return pr.PaymentSecret, nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeP:
		if !pr.PaymentHash.IsZero() {
			return pr.PaymentHash, nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeD:
		if pr.Description != "" {
			return NewStringBolt11Encoder(pr.Description), nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeH:
		if !pr.DescriptionHash.IsZero() {
			return pr.DescriptionHash, nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeX:
		if pr.Expiry != 0 {
			return NewVarUintBolt11Encoder(uint(pr.Expiry.Seconds())), nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeF:
		if pr.FallbackAddress != "" {
			addr, err := bitcoin.DecodeAddress(pr.FallbackAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to decode fallback address: %w", err)
			}
			return addr, nil
		}
		return nil, errFieldDataNotFound
	case fieldType9:
		return pr.Features, nil
	case fieldTypeR:
		hint, ok := pr.routingHintNext()
		if !ok {
			return nil, errFieldDataNotFound
		}
		return hint, nil
	case fieldTypeC:
		if pr.MinFinalCLTVExpiryDelta != 0 {
			return NewVarUintBolt11Encoder(uint(pr.MinFinalCLTVExpiryDelta)), nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeM:
		if len(pr.PaymentMetadata) > 0 {
			return NewBytesBolt11Encoder(pr.PaymentMetadata), nil
		}
		return nil, errFieldDataNotFound
	}
	return nil, errUnknownFieldType
}

func writeTaggedField(buf *bytes.Buffer, fieldType TaggedFieldType, data Bolt11Encoder) error {
	buf.WriteByte(fieldType)

	dataBolt11, err := data.EncodeBolt11()
	if err != nil {
		return err
	}

	tf := func() *TaggedField {
		tf := &TaggedField{FieldType: fieldType, Data: dataBolt11}
		switch fieldType {
		case fieldTypeP, fieldTypeS, fieldTypeH:
			tf.DataLength = 52
		default:
			tf.DataLength = uint16(len(dataBolt11))
		}
		return tf
	}()

	if len(tf.Data) != int(tf.DataLength) {
		return fmt.Errorf("data length does not match: expected %d, got %d", tf.DataLength, len(tf.Data))
	}

	dataLengthBase32, err := bech32.NewUintBase32Encoder(uint(tf.DataLength), 10).EncodeBase32()
	if err != nil {
		return fmt.Errorf("failed to encode data length: %w", err)
	}
	buf.Write(dataLengthBase32)

	if _, err := buf.Write(tf.Data); err != nil {
		return err
	}

	return nil
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

func appendOrMoveToEnd[S ~[]E, E comparable](slice S, elem E) S {
	// remove element if it exists
	slice = slices.DeleteFunc(slice, func(e E) bool { return e == elem })
	// add element to end
	return append(slice, elem)
}

func remove[S ~[]E, E comparable](slice S, elem E) S {
	return slices.DeleteFunc(slice, func(e E) bool { return e == elem })
}
