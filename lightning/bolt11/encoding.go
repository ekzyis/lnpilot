package bolt11

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/ekzyis/lnpilot/lib/bech32"
	"github.com/ekzyis/lnpilot/lib/bitcoin"
	"github.com/ekzyis/lnpilot/lib/secp256k1"
	"github.com/ekzyis/lnpilot/lightning/bolt09"
	"github.com/ekzyis/lnpilot/lightning/lntypes"
	"golang.org/x/exp/constraints"
)

var (
	errFieldDataNotFound     = errors.New("field data not found")
	errUnknownFieldType      = errors.New("unknown field type")
	errInvalidSignature      = errors.New("invalid signature")
	errInvalidHRP            = errors.New("invalid hrp")
	errInvalidPaymentRequest = errors.New("invalid payment request")
)

// ======================
// === encoding stuff ===
// ======================

// Bolt11Encoder is an interface that represents an encoder for a tagged field
// in a bolt11 payment request.
//
// Most encoders simply encode the data in base32, but some (like fallback
// addresses) have additional encoding requirements.
type Bolt11Encoder interface {
	EncodeBolt11() ([]byte, error)
}

type BytesBolt11Encoder struct {
	base32Encoder *bech32.BytesBase32Encoder
}

type StringBolt11Encoder struct {
	base32Encoder *bech32.BytesBase32Encoder
}

type VarUintBolt11Encoder struct {
	base32Encoder *bech32.VarUintBase32Encoder
}

type UintBolt11Encoder struct {
	base32Encoder *bech32.UintBase32Encoder
}

var _ Bolt11Encoder = (*BytesBolt11Encoder)(nil)
var _ Bolt11Encoder = (*StringBolt11Encoder)(nil)
var _ Bolt11Encoder = (*VarUintBolt11Encoder)(nil)
var _ Bolt11Encoder = (*UintBolt11Encoder)(nil)
var _ Bolt11Encoder = (*bolt09.FeatureVector)(nil)
var _ Bolt11Encoder = (*lntypes.Hash)(nil)
var _ Bolt11Encoder = (*lntypes.RoutingHint)(nil)
var _ Bolt11Encoder = (bitcoin.Address)(nil)

func (e BytesBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.base32Encoder.EncodeBase32()
}

func (e StringBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.base32Encoder.EncodeBase32()
}

func (e VarUintBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.base32Encoder.EncodeBase32()
}

func (e UintBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.base32Encoder.EncodeBase32()
}

func NewBytesBolt11Encoder(data []byte) Bolt11Encoder {
	encoder := bech32.NewBytesBase32Encoder(data)
	return BytesBolt11Encoder{base32Encoder: &encoder}
}

func NewStringBolt11Encoder(data string) Bolt11Encoder {
	encoder := bech32.NewStringBase32Encoder(data)
	return StringBolt11Encoder{base32Encoder: &encoder}
}

func NewUintBolt11Encoder(num, bitLen uint) Bolt11Encoder {
	encoder := bech32.NewUintBase32Encoder(num, bitLen)
	return UintBolt11Encoder{base32Encoder: &encoder}
}

func NewVarUintBolt11Encoder(num uint) Bolt11Encoder {
	encoder := bech32.NewVarUintBase32Encoder(num)
	return VarUintBolt11Encoder{base32Encoder: &encoder}
}

// EncodeBech32 returns the bech32 encoded and signed payment request
func (pr *PaymentRequest) EncodeBech32(signer secp256k1.Signer) (string, error) {
	err := pr.validate()
	if err != nil {
		return "", err
	}

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
	defer func() { pr.routingHintNext = nil; stop() }()

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
			return &pr.PaymentSecret, nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeP:
		if !pr.PaymentHash.IsZero() {
			return &pr.PaymentHash, nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeD:
		if pr.Description != nil {
			return NewStringBolt11Encoder(*pr.Description), nil
		}
		return nil, errFieldDataNotFound
	case fieldTypeH:
		if !pr.DescriptionHash.IsZero() {
			return &pr.DescriptionHash, nil
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
		return &pr.Features, nil
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
	case fieldTypeN:
		if pr.PublicKey != nil {
			return NewBytesBolt11Encoder(pr.PublicKey.SerializeCompressed()), nil
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
		case fieldTypeN:
			tf.DataLength = 53
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

// ======================
// === decoding stuff ===
// ======================

// Bolt11Decoder is an interface that represents a decoder for a tagged field in
// a bolt11 payment request.
//
// A Bolt11Decoder should be a member of a PaymentRequest struct, such that
// calling DecodeBolt11 will set the field in the payment request.
type Bolt11Decoder interface {
	DecodeBolt11([]byte) error
}

type StringBolt11Decoder struct {
	s *string
}

type TimeDurationBolt11Decoder struct {
	duration *time.Duration
}

type BytesBolt11Decoder struct {
	bytes *[]byte
}

type PublicKeyBolt11Decoder struct {
	pubKey *secp256k1.PublicKey
}

type RoutingHintBolt11Decoder struct {
	routingHint *lntypes.RoutingHint
}

type UintBolt11Decoder[T constraints.Unsigned] struct {
	num *T
}

var _ Bolt11Decoder = (*StringBolt11Decoder)(nil)
var _ Bolt11Decoder = (*TimeDurationBolt11Decoder)(nil)
var _ Bolt11Decoder = (*bitcoin.AddressBolt11Decoder)(nil)
var _ Bolt11Decoder = (*lntypes.Hash)(nil)
var _ Bolt11Decoder = (*bolt09.FeatureVector)(nil)
var _ Bolt11Decoder = (*BytesBolt11Decoder)(nil)
var _ Bolt11Decoder = (*RoutingHintBolt11Decoder)(nil)
var _ Bolt11Decoder = (*UintBolt11Decoder[uint8])(nil)
var _ Bolt11Decoder = (*UintBolt11Decoder[uint16])(nil)
var _ Bolt11Decoder = (*UintBolt11Decoder[uint32])(nil)
var _ Bolt11Decoder = (*UintBolt11Decoder[uint64])(nil)
var _ Bolt11Decoder = (*UintBolt11Decoder[uint])(nil)

func (d StringBolt11Decoder) DecodeBolt11(data []byte) error {
	decoded, err := bech32.NewBytesBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}
	*d.s = string(decoded)
	return nil
}

func (d TimeDurationBolt11Decoder) DecodeBolt11(data []byte) error {
	duration, err := bech32.NewUintBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}
	*d.duration = time.Duration(duration) * time.Second
	return nil
}

func (d BytesBolt11Decoder) DecodeBolt11(data []byte) error {
	decoded, err := bech32.NewBytesBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}
	*d.bytes = decoded
	return nil
}

func (d PublicKeyBolt11Decoder) DecodeBolt11(data []byte) error {
	decoded, err := bech32.NewBytesBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}
	d.pubKey, err = secp256k1.ParsePubKey(decoded)
	if err != nil {
		return err
	}
	return nil
}

func (d UintBolt11Decoder[T]) DecodeBolt11(data []byte) error {
	num, err := bech32.NewUintBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}
	*d.num = T(num)
	return nil
}

func (d RoutingHintBolt11Decoder) DecodeBolt11(data []byte) error {
	return d.routingHint.DecodeBolt11(data)
}

func NewStringBolt11Decoder(s *string) Bolt11Decoder {
	return StringBolt11Decoder{s: s}
}

func NewTimeDurationBolt11Decoder(duration *time.Duration) Bolt11Decoder {
	return TimeDurationBolt11Decoder{duration: duration}
}

func NewBytesBolt11Decoder(bytes *[]byte) Bolt11Decoder {
	return BytesBolt11Decoder{bytes: bytes}
}

func NewPublicKeyBolt11Decoder(pubKey *secp256k1.PublicKey) Bolt11Decoder {
	return PublicKeyBolt11Decoder{pubKey: pubKey}
}

func NewRoutingHintBolt11Decoder(routingHint *lntypes.RoutingHint) Bolt11Decoder {
	return RoutingHintBolt11Decoder{routingHint: routingHint}
}

func NewUintBolt11Decoder[T constraints.Unsigned](num *T) Bolt11Decoder {
	return UintBolt11Decoder[T]{num: num}
}

// DecodePaymentRequest decodes the bech32-encoded payment request into a
// PaymentRequest struct.
func DecodePaymentRequest(encoded string) (*PaymentRequest, error) {
	hrp, dataBase32, err := bech32.DecodeNoLimit(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payment request: %w", err)
	}

	// the data part must be the same length as the bech32 string without the
	// hrp, bech32 separator, and checksum
	checksumLength := 6
	if len(dataBase32) != len(encoded)-len(hrp)-1-checksumLength {
		return nil, fmt.Errorf("unexpected length of decoded bech32 data part: expected %d, got %d", len(encoded)-len(hrp)-1-checksumLength, len(dataBase32))
	}

	pr := PaymentRequest{}

	err = pr.decodeHumanReadablePart(hrp)
	if err != nil {
		return nil, err
	}

	err = pr.decodeTimestamp(dataBase32[0:7])
	if err != nil {
		return nil, fmt.Errorf("failed to decode timestamp: %w", err)
	}

	// 64 bytes R||S + 1 byte recovery id in base256
	// => 64 * 8 / 5 = 104 bytes in base32
	timestampLengthBase32 := 7
	sigLengthBase32 := 104
	if len(dataBase32)-sigLengthBase32 <= timestampLengthBase32 {
		return nil, bech32.ErrInvalidLength
	}
	tfBase32 := dataBase32[timestampLengthBase32 : len(dataBase32)-sigLengthBase32]

	err = pr.decodeTaggedFields(tfBase32)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tagged fields: %w", err)
	}

	sigBytesBase32 := dataBase32[len(dataBase32)-sigLengthBase32:]
	sigBytesBase256, err := bech32.NewBytesBase32Decoder(sigBytesBase32).DecodeBase32()
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	sig, err := secp256k1.NewCompactECDSASignatureFromBytes(sigBytesBase256)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	msg := append([]byte(hrp), tfBase32...)
	// TODO: this always performs public key recovery, but we must use `n` if provided
	if !sig.Verify(msg) {
		return nil, errInvalidSignature
	}

	// signatures must be low-S if `n` is provided
	if pr.PublicKey != nil && sig.IsHighS() {
		return nil, errInvalidSignature
	}

	err = pr.validate()
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

// decodeHumanReadablePart decodes the hrp and sets the network and millisats
// amount in the payment request.
func (pr *PaymentRequest) decodeHumanReadablePart(hrp string) error {
	var (
		network    lntypes.Network
		amt        lntypes.Bitcoin
		multiplier lntypes.Multiplier
		err        error
	)

	re := regexp.MustCompile(`^(?P<prefix>[a-zA-Z]+)(?:(?P<amount>\d+)(?P<multiplier>[munp]))?$`)
	matches := findNamedMatches(re, hrp)

	if len(matches) != 1 && len(matches) != 3 {
		// must always match prefix, amount and multiplier are optional but must
		// match together
		return fmt.Errorf("%w: invalid format: %s", errInvalidHRP, hrp)
	}

	for key, value := range matches {
		switch key {
		case "prefix":
			network, err = lntypes.DecodeNetworkPrefix(value)
			if err != nil {
				return fmt.Errorf("%w: failed to decode network prefix: %w", errInvalidHRP, err)
			}
		case "amount":
			numAmt, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("%w: failed to parse amount: %w", errInvalidHRP, err)
			}
			amt = lntypes.Bitcoin(numAmt)
		case "multiplier":
			multiplier = lntypes.Multiplier(value)
		}
	}

	pr.Network = network

	if amt == 0 {
		return nil
	}

	if multiplier == lntypes.MultiplierPico && amt%10 != 0 {
		return fmt.Errorf("%w: invalid sub-millisatoshi amount: %d%s", errInvalidHRP, amt, multiplier)
	}

	var picoBitcoins uint64
	switch multiplier {
	case lntypes.MultiplierPico:
		picoBitcoins = uint64(amt)
	case lntypes.MultiplierNano:
		picoBitcoins = uint64(amt) * 1e3
	case lntypes.MultiplierMicro:
		picoBitcoins = uint64(amt) * 1e6
	case lntypes.MultiplierMilli:
		picoBitcoins = uint64(amt) * 1e9
	}
	// see pr.humanReadablePart() for the conversion math
	pr.Msats = lntypes.MilliSatoshi(picoBitcoins / 10)

	return nil
}

// decodeTimestamp decodes the timestamp from the byte slice and sets it in the
// payment request. The byte slice must be in base32, big-endian order and 7
// bytes long.
func (pr *PaymentRequest) decodeTimestamp(dataBase32 []byte) error {
	if len(dataBase32) != 7 {
		return fmt.Errorf("expected 7 bytes in big-endian order, got %d", len(dataBase32))
	}

	timestamp, err := bech32.NewUintBase32Decoder(dataBase32).DecodeBase32()
	if err != nil {
		return err
	}

	pr.Timestamp = time.Unix(int64(timestamp), 0)
	return nil
}

// decodeTaggedFields decodes the tagged fields from the byte slice and sets
// them in the payment request. The byte slice must be in base32.
func (pr *PaymentRequest) decodeTaggedFields(dataBase32 []byte) error {
	// For decoding, we append a new RoutingHint to the slice and return a
	// pointer to it each time one is encountered
	pr.routingHintNext = func() (*lntypes.RoutingHint, bool) {
		hint := &lntypes.RoutingHint{}
		pr.RoutingHints = append(pr.RoutingHints, hint)
		return hint, true
	}
	defer func() { pr.routingHintNext = nil }()

	r := bytes.NewReader(dataBase32)

	for {
		fieldType, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read field type: %w", err)
		}

		tfDataLengthBase32 := make([]byte, 2)
		_, err = io.ReadFull(r, tfDataLengthBase32)
		if err != nil {
			return fmt.Errorf("failed to read data length of 0x%02x: %w", fieldType, err)
		}

		tfDataLength, err := bech32.NewUintBase32Decoder(tfDataLengthBase32).DecodeBase32()
		if err != nil {
			return fmt.Errorf("failed to decode data length of 0x%02x: %w", fieldType, err)
		}

		tfDataBase32 := make([]byte, tfDataLength)
		_, err = io.ReadFull(r, tfDataBase32)
		if err != nil {
			return fmt.Errorf("failed to read data of 0x%02x: %w", fieldType, err)
		}

		tfDecoder, err := pr.getTaggedFieldDecoder(fieldType)
		if err == errUnknownFieldType {
			// We skip any field we don't know about. The "it's okay to be
			// odd"-rule only applies to feature bits.
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get tagged field decoder for 0x%02x: %w", fieldType, err)
		}

		err = tfDecoder.DecodeBolt11(tfDataBase32)
		if errors.Is(err, bitcoin.ErrUnknownVersion) {
			// a reader MUST skip over `f` fields that use an unknown `version`
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to decode data of 0x%02x: %w", fieldType, err)
		}
	}

	return nil
}

// getTaggedFieldDecoder returns the Bolt11Decoder for the given field type and
// data from the payment request. Calling .DecodeBolt11 on the returned decoder
// will set the field in the payment request.
func (pr *PaymentRequest) getTaggedFieldDecoder(fieldType TaggedFieldType) (Bolt11Decoder, error) {
	pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldType)

	switch fieldType {
	case fieldTypeP:
		return &pr.PaymentHash, nil
	case fieldTypeS:
		return &pr.PaymentSecret, nil
	case fieldTypeH:
		return &pr.DescriptionHash, nil
	case fieldTypeD:
		pr.Description = new(string)
		return NewStringBolt11Decoder(pr.Description), nil
	case fieldType9:
		return &pr.Features, nil
	case fieldTypeX:
		return NewTimeDurationBolt11Decoder(&pr.Expiry), nil
	case fieldTypeF:
		return bitcoin.NewAddressBolt11Decoder(&pr.FallbackAddress, pr.Network), nil
	case fieldTypeM:
		return NewBytesBolt11Decoder(&pr.PaymentMetadata), nil
	case fieldTypeR:
		hint, ok := pr.routingHintNext()
		if !ok {
			return nil, errFieldDataNotFound
		}
		return NewRoutingHintBolt11Decoder(hint), nil
	case fieldTypeC:
		return NewUintBolt11Decoder(&pr.MinFinalCLTVExpiryDelta), nil
	case fieldTypeN:
		pr.PublicKey = new(secp256k1.PublicKey)
		return NewPublicKeyBolt11Decoder(pr.PublicKey), nil
	}

	return nil, errUnknownFieldType
}

// findNamedMatches finds the named matches in the regex and returns a map of
// the named matches to the values. If a named group wasn't found, the map does
// not contain the key.
func findNamedMatches(regex *regexp.Regexp, str string) map[string]string {
	matches := regex.FindStringSubmatch(str)
	results := map[string]string{}
	for i, match := range matches {
		if i == 0 || match == "" {
			continue
		}
		results[regex.SubexpNames()[i]] = match
	}
	return results
}
