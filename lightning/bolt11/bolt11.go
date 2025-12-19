package bolt11

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ekzyis/lntutor/lib/bech32"
	"github.com/ekzyis/lntutor/lib/bitcoin"
	"github.com/ekzyis/lntutor/lib/secp256k1"
	"github.com/ekzyis/lntutor/lightning/bolt09"
	"github.com/ekzyis/lntutor/lightning/lntypes"
)

type PaymentRequest struct {
	Network     lntypes.Network
	Msats       lntypes.MilliSatoshi
	Timestamp   time.Time
	Expiry      time.Duration
	PaymentHash lntypes.Hash

	// PaymentSecret makes sure the recipient can tell if the onion payload was
	// constructed by the sender. If it's not included, the last hop can steal
	// overpaid amount from the sender by 'probing' with a smaller amount first.
	// see https://bitcoin.stackexchange.com/a/115738
	PaymentSecret   lntypes.Hash
	Description     string
	DescriptionHash lntypes.Hash
	Features        bolt09.FeatureVector
	FallbackAddress string

	// taggedFields keeps track of the order the tagged fields were specified in
	// so we can include them in the same order in the bech32 encoding of the
	// payment request.
	taggedFields []TaggedFieldType
}

// bolt09 feature bits that can be set in a bolt11 payment request.
type FeatureBit uint16

const (
	// this bit is marked as assumed in bolt09, but for some reason, there's a test vector with this bit set.
	VarOnionOptinRequired FeatureBit = FeatureBit(bolt09.VarOnionOptinRequired)

	PaymentSecretRequired FeatureBit = FeatureBit(bolt09.PaymentSecretRequired)
	PaymentSecretOptional FeatureBit = FeatureBit(bolt09.PaymentSecretOptional)

	BasicMppRequired FeatureBit = FeatureBit(bolt09.BasicMppRequired)
	BasicMppOptional FeatureBit = FeatureBit(bolt09.BasicMppOptional)

	RouteBlindingRequired FeatureBit = FeatureBit(bolt09.RouteBlindingRequired)
	RouteBlindingOptional FeatureBit = FeatureBit(bolt09.RouteBlindingOptional)

	AttributionDataRequired FeatureBit = FeatureBit(bolt09.AttributionDataRequired)
	AttributionDataOptional FeatureBit = FeatureBit(bolt09.AttributionDataOptional)

	PaymentMetadataRequired FeatureBit = FeatureBit(bolt09.PaymentMetadataRequired)
	PaymentMetadataOptional FeatureBit = FeatureBit(bolt09.PaymentMetadataOptional)
)

type TaggedField struct {
	FieldType  TaggedFieldType // must be encoded as 5 bits
	DataLength uint16          // must be encoded as 10 bits, big-endian (maximum is 1023)
	Data       []byte          // must be encoded as 5 x data_length bits (maximum is 640 bytes)
}

type TaggedFieldType = byte

const (
	// fieldTypeP is the field containing the payment hash.
	fieldTypeP TaggedFieldType = 1
	// fieldTypeS is the field containing the payment secret.
	fieldTypeS TaggedFieldType = 16
	// fieldTypeD is the field containing the description.
	fieldTypeD TaggedFieldType = 13
	// fieldTypeH is the field containing the description hash.
	fieldTypeH TaggedFieldType = 23
	// fieldTypeX is the field containing the expiry.
	fieldTypeX TaggedFieldType = 6
	// fieldType9 is the field containing the feature bits.
	fieldType9 TaggedFieldType = 5
	// fieldTypeF is the field containing the fallback address.
	fieldTypeF TaggedFieldType = 9

	// data_length is limited by 10 bits, so we can only fit 5 x 2^10 bits
	// or 640 bytes of data in a single field.
	MaxDescriptionBytes = 639
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
			WithExpiry(time.Hour),
		},
		options...,
	)

	for _, option := range options {
		option(pr)
	}

	return pr
}

func WithNetwork(network lntypes.Network) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.Network = network
	}
}

func WithTimestamp(timestamp time.Time) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.Timestamp = timestamp
	}
}

func WithPaymentHash(paymentHash [32]byte) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.PaymentHash = lntypes.Hash(paymentHash)
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeP)
	}
}

func WithRandomPaymentHash() func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		var preimage lntypes.Preimage
		rand.Read(preimage[:])
		WithPaymentHash(preimage.Hash())(pr)
		// TODO: how to return preimage to caller?
	}
}

func WithPaymentSecret(paymentSecret [32]byte) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.PaymentSecret = lntypes.Hash(paymentSecret)
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeS)
	}
}

func WithRandomPaymentSecret() func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		var paymentSecret lntypes.Hash
		rand.Read(paymentSecret[:])
		WithPaymentSecret(paymentSecret)(pr)
	}
}

func WithDescription(description string) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		descBytes := []byte(description)
		if len(descBytes) <= MaxDescriptionBytes {
			pr.Description = description
			pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeD)

			// clear any existing description hash
			pr.DescriptionHash = lntypes.Hash{}
			pr.taggedFields = remove(pr.taggedFields, fieldTypeH)
			return
		}

		// description too long, use hash instead
		pr.DescriptionHash = sha256.Sum256(descBytes)
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeH)

		// clear any existing description
		pr.Description = ""
		pr.taggedFields = remove(pr.taggedFields, fieldTypeD)
	}
}

func WithDescriptionHash(descriptionHash [32]byte) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.DescriptionHash = lntypes.Hash(descriptionHash)
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeH)
	}
}

func WithFeatureBits(featureBits ...FeatureBit) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		// Go does not allow a direct cast between []FeatureBit and []bolt09.FeatureBit
		bolt09Bits := make([]bolt09.FeatureBit, len(featureBits))
		for i, bit := range featureBits {
			bolt09Bits[i] = bolt09.FeatureBit(bit)
		}
		pr.Features = *bolt09.NewFeatureVector(bolt09Bits...)
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldType9)
	}
}

func WithExpiry(expiry time.Duration) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.Expiry = expiry
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeX)
	}
}

func WithFallbackAddress(fallbackAddress string) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.FallbackAddress = fallbackAddress
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeF)
	}
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
		// Amounts are denominated in bitcoins, not millisatoshis.
		// This means we first convert millisatoshis to picobitcoins,
		// because that's the smallest unit we can represent with our multipliers.
		//
		// The conversion math is as follows:
		//
		//   msats / 1e3 = sats
		//   sats / 1e8 = bitcoin
		//   bitcoin * 1e12 = picobitcoin
		//
		// => picobitcoins = msats * 1e12 / (1e3 * 1e8) = msats * 10
		//
		// This also makes sure that the last decimal is always a zero when 'pico'
		// is used, since HTLCs are denonimated in millisatoshis.
		units := lntypes.PicoBitcoin(pr.Msats * 10)

		var multiplier lntypes.Multiplier
		for _, multiplier = range lntypes.Multipliers {
			if units%1e3 == 0 {
				units /= 1e3
			} else {
				break
			}
		}

		// payment requests are denominated in bitcoins, and the multiplier
		// is used to represent smaller units of bitcoin
		return lntypes.Bitcoin(units), multiplier, nil
	}()
	if err != nil {
		return "", fmt.Errorf("failed to encode amount: %w", err)
	}

	return fmt.Sprintf("%s%d%s", prefix, amt, multiplier), nil
}

func (pr *PaymentRequest) writeTaggedFields(buf *bytes.Buffer) error {
	for _, fieldType := range pr.taggedFields {
		data, err := getTaggedFieldData(pr, fieldType)
		if err == ErrFieldDataNotFound {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get tagged field data: %x: %w", fieldType, err)
		}
		err = writeTaggedField(buf, fieldType, data)
		if err != nil {
			return fmt.Errorf("failed to write tagged field: %x: %w", fieldType, err)
		}
	}

	// TODO: write remaining tagged fields

	return nil
}

var ErrFieldDataNotFound = errors.New("field data not found")
var ErrUnknownFieldType = errors.New("unknown field type")

func getTaggedFieldData(pr *PaymentRequest, fieldType TaggedFieldType) (Bolt11Encoder, error) {
	switch fieldType {
	case fieldTypeS:
		if !pr.PaymentSecret.IsZero() {
			return pr.PaymentSecret, nil
		}
		return nil, ErrFieldDataNotFound
	case fieldTypeP:
		if !pr.PaymentHash.IsZero() {
			return pr.PaymentHash, nil
		}
		return nil, ErrFieldDataNotFound
	case fieldTypeD:
		if pr.Description != "" {
			return NewStringBolt11Encoder(pr.Description), nil
		}
		return nil, ErrFieldDataNotFound
	case fieldTypeH:
		if !pr.DescriptionHash.IsZero() {
			return pr.DescriptionHash, nil
		}
		return nil, ErrFieldDataNotFound
	case fieldTypeX:
		if pr.Expiry != 0 {
			return NewVarUintBolt11Encoder(uint(pr.Expiry.Seconds())), nil
		}
		return nil, ErrFieldDataNotFound
	case fieldTypeF:
		if pr.FallbackAddress != "" {
			addr, err := bitcoin.DecodeAddress(pr.FallbackAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to decode fallback address: %w", err)
			}
			return addr, nil
		}
		return nil, ErrFieldDataNotFound
	case fieldType9:
		return pr.Features, nil
	}
	return nil, ErrUnknownFieldType
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
	// The signature is over the sha256 hash of hrp + data part encoded in base256.
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
