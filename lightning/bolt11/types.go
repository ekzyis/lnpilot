package bolt11

import (
	"time"

	"github.com/ekzyis/lnpilot/lib/secp256k1"
	"github.com/ekzyis/lnpilot/lightning/bolt09"
	"github.com/ekzyis/lnpilot/lightning/lntypes"
)

type PaymentRequest struct {
	Network     lntypes.Network
	Msats       lntypes.MilliSatoshi
	Timestamp   time.Time
	Expiry      time.Duration
	PaymentHash lntypes.Hash
	PublicKey   *secp256k1.PublicKey

	// PaymentSecret makes sure the recipient can tell if the onion payload was
	// constructed by the sender. If it's not included, the last hop can steal
	// overpaid amount from the sender by 'probing' with a smaller amount first.
	// see https://bitcoin.stackexchange.com/a/115738
	PaymentSecret lntypes.Hash

	Description     *string
	DescriptionHash lntypes.Hash
	Features        bolt09.FeatureVector
	FallbackAddress string

	// Minimum CLTV expiry delta to use for the last HTLC in the route.
	MinFinalCLTVExpiryDelta uint16

	RoutingHints []*lntypes.RoutingHint

	// PaymentMetadata is additional metadata to attach to the payment. This
	// supports applications where the recipient doesn't keep any context for
	// the payment.
	PaymentMetadata []byte

	// routingHintNext returns the next routing hint we should read/write
	// from/to the bech32 encoded payment request when we encounter another `r`
	// tagged field. It is initialized before reading/writing the tagged fields.
	routingHintNext func() (*lntypes.RoutingHint, bool)

	// taggedFields keeps track of the order the tagged fields were specified in
	// so we can include them in the same order in the bech32 encoding of the
	// payment request.
	taggedFields []TaggedFieldType
}

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
	// fieldTypeR is a repeatable field containing a routing hint with one or
	// more hops.
	fieldTypeR TaggedFieldType = 3
	// fieldTypeC is the field containing the minimum CLTV expiry delta to use
	// for the last HTLC in the route.
	fieldTypeC TaggedFieldType = 24
	// fieldTypeM is the field containing the payment metadata.
	fieldTypeM TaggedFieldType = 27
	// fieldTypeN is the compressed public key of the payee node.
	fieldTypeN TaggedFieldType = 19

	// data_length is limited by 10 bits, so we can only fit 5 x 2^10 bits
	// or 640 bytes of data in a single field.
	MaxDescriptionBytes = 639
)

// bolt09 feature bits that can be set in a bolt11 payment request.
type FeatureBit uint16

const (
	// this bit is marked as assumed in bolt09, but for some reason, there's a
	// test vector with this bit set.
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
