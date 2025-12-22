package bolt11

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"slices"

	"github.com/ekzyis/lntutor/lib/bech32"
	"github.com/ekzyis/lntutor/lib/bitcoin"
	"github.com/ekzyis/lntutor/lib/secp256k1"
	"github.com/ekzyis/lntutor/lightning/lntypes"
)

var (
	errFieldDataNotFound = errors.New("field data not found")
	errUnknownFieldType  = errors.New("unknown field type")
)

type Bolt11Encoder interface {
	EncodeBase32() ([]byte, error)
	EncodeBolt11() ([]byte, error)
}

// Every Bolt11Encoder must also implement bech32.Base32Encoder
var _ bech32.Base32Encoder = (Bolt11Encoder)(nil)

type BytesBolt11Encoder struct {
	*bech32.BytesBase32Encoder
}

type StringBolt11Encoder struct {
	*bech32.BytesBase32Encoder
}

type VarUintBolt11Encoder struct {
	*bech32.VarUintBase32Encoder
}

type UintBolt11Encoder struct {
	*bech32.UintBase32Encoder
}

func (e BytesBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func (e StringBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func (e VarUintBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func (e UintBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func NewBytesBolt11Encoder(data []byte) Bolt11Encoder {
	encoder := bech32.NewBytesBase32Encoder(data)
	return BytesBolt11Encoder{BytesBase32Encoder: &encoder}
}

func NewStringBolt11Encoder(data string) Bolt11Encoder {
	encoder := bech32.NewStringBase32Encoder(data)
	return StringBolt11Encoder{BytesBase32Encoder: &encoder}
}

func NewUintBolt11Encoder(num, bitLen uint) Bolt11Encoder {
	encoder := bech32.NewUintBase32Encoder(num, bitLen)
	return UintBolt11Encoder{UintBase32Encoder: &encoder}
}

func NewVarUintBolt11Encoder(num uint) Bolt11Encoder {
	encoder := bech32.NewVarUintBase32Encoder(num)
	return VarUintBolt11Encoder{VarUintBase32Encoder: &encoder}
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

	err = pr.encodeTaggedFields(&buf)
	if err != nil {
		return "", fmt.Errorf("failed to write tagged fields: %w", err)
	}

	hrp, err := pr.encodeHRP()
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

// encodeHRP returns the human-readable part for the bech32 encoding of the
// payment request. It contains the network prefix and the amount, if non-zero.
func (pr *PaymentRequest) encodeHRP() (string, error) {
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

// encodeTaggedFields writes the encoded tagged fields to the buffer.
// Every tagged field is encoded using the Bolt11Encoder interface.
func (pr *PaymentRequest) encodeTaggedFields(buf *bytes.Buffer) error {
	// There can be multiple routing hints, so we initialize the iterator here.
	// pr.getTaggedFieldEncoder will then always return the next routing hint.
	var stop func()
	pr.routingHintNext, stop = iter.Pull(slices.Values(pr.RoutingHints))
	defer stop()

	for _, fieldType := range pr.taggedFields {
		encoder, err := pr.getTaggedFieldEncoder(fieldType)
		if err == errFieldDataNotFound {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get tagged field data: 0x%02x: %w", fieldType, err)
		}
		err = encodeTaggedField(buf, fieldType, encoder)
		if err != nil {
			return fmt.Errorf("failed to write tagged field: 0x%02x: %w", fieldType, err)
		}
	}

	return nil
}

// getTaggedFieldEncoder returns the Bolt11Encoder for the given field type.
func (pr *PaymentRequest) getTaggedFieldEncoder(fieldType TaggedFieldType) (Bolt11Encoder, error) {
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

// encodeTaggedFields writes the encoded data returned by encoder to the buffer.
// The field type is used to verify the data length for fields with a fixed data length.
func encodeTaggedField(buf *bytes.Buffer, fieldType TaggedFieldType, encoder Bolt11Encoder) error {
	buf.WriteByte(fieldType)

	dataBolt11, err := encoder.EncodeBolt11()
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
