package bolt09

import (
	"errors"
	"fmt"
	"slices"
)

// Feature bits aren't implemented as bitmasks, because the maximum feature bit
// can be 5114. They are limited by the 10 bits for data_length in the tagged
// fields of bolt11 payment requests.
//
// So instead, we use map[FeatureBit]struct{} to represent features, inspired by
// LND's implementation.
//
// I think bitmasks are really cool though :/

type FeatureVector struct {
	features map[FeatureBit]struct{}
	maxBit   int
}

type FeatureBit uint16

const (
	DataLossProtectRequired       FeatureBit = 0
	DataLossProtectOptional       FeatureBit = 1
	UpfrontShutdownScriptRequired FeatureBit = 4
	UpfrontShutdownScriptOptional FeatureBit = 5
	GossipQueriesRequired         FeatureBit = 6
	GossipQueriesOptional         FeatureBit = 7
	VarOnionOptinRequired         FeatureBit = 8
	VarOnionOptinOptional         FeatureBit = 9
	GossipQueriesExtendedRequired FeatureBit = 10
	GossipQueriesExtendedOptional FeatureBit = 11
	StaticRemotekeyRequired       FeatureBit = 12
	StaticRemotekeyOptional       FeatureBit = 13
	PaymentSecretRequired         FeatureBit = 14
	PaymentSecretOptional         FeatureBit = 15
	BasicMppRequired              FeatureBit = 16
	BasicMppOptional              FeatureBit = 17
	SupportLargeChannelRequired   FeatureBit = 18
	SupportLargeChannelOptional   FeatureBit = 19
	AnchorsRequired               FeatureBit = 22
	AnchorsOptional               FeatureBit = 23
	RouteBlindingRequired         FeatureBit = 24
	RouteBlindingOptional         FeatureBit = 25
	ShutdownAnysegwitRequired     FeatureBit = 26
	ShutdownAnysegwitOptional     FeatureBit = 27
	DualFundRequired              FeatureBit = 28
	DualFundOptional              FeatureBit = 29
	QuiesceRequired               FeatureBit = 34
	QuiesceOptional               FeatureBit = 35
	AttributionDataRequired       FeatureBit = 36
	AttributionDataOptional       FeatureBit = 37
	OnionMessagesRequired         FeatureBit = 38
	OnionMessagesOptional         FeatureBit = 39
	ProvideStorageRequired        FeatureBit = 42
	ProvideStorageOptional        FeatureBit = 43
	ChannelTypeRequired           FeatureBit = 44
	ChannelTypeOptional           FeatureBit = 45
	ScidAliasRequired             FeatureBit = 46
	ScidAliasOptional             FeatureBit = 47
	PaymentMetadataRequired       FeatureBit = 48
	PaymentMetadataOptional       FeatureBit = 49
	ZeroconfRequired              FeatureBit = 50
	ZeroconfOptional              FeatureBit = 51
	SimpleCloseRequired           FeatureBit = 60
	SimpleCloseOptional           FeatureBit = 61
)

var (
	ErrUnknownRequiredFeatureBit = errors.New("unknown required feature bit")
)

func NewFeatureVector(bits ...FeatureBit) *FeatureVector {
	fv := &FeatureVector{features: make(map[FeatureBit]struct{})}
	for _, bit := range bits {
		fv.Set(bit)
	}
	return fv
}

// Set marks a feature as enabled in the vector.
func (fv *FeatureVector) Set(bit FeatureBit) {
	fv.features[bit] = struct{}{}
	if int(bit) > fv.maxBit {
		fv.maxBit = int(bit)
	}
}

// Bytes returns the bytes of the feature vector in big-endian order.
func (fv *FeatureVector) Bytes() []byte {
	b := make([]byte, fv.maxBit/8+1)
	for bit := range fv.features {
		index := (len(b) - 1) - int(bit)/8
		b[index] |= 1 << (bit % 8)
	}
	return b
}

func (fv *FeatureVector) Bits() []FeatureBit {
	keys := make([]FeatureBit, 0, len(fv.features))
	for bit := range fv.features {
		keys = append(keys, bit)
	}
	slices.Sort(keys)
	return keys
}

// EncodeBolt11 returns the bytes of the feature vector in base32 encoding,
// big-endian order. It will throw an error if the "it's okay to be odd"-rule
// is violated.
func (fv *FeatureVector) EncodeBolt11() ([]byte, error) {
	b := make([]byte, fv.maxBit/5+1)
	for bit := range fv.features {
		if bit.IsUnknown() && bit.IsRequired() {
			return nil, fmt.Errorf("%w: %v", ErrUnknownRequiredFeatureBit, bit)
		}
		index := (len(b) - 1) - int(bit)/5
		b[index] |= 1 << (bit % 5)
	}
	return b, nil
}

// DecodeBolt11 decodes the byte slice to set the corresponding features in the
// feature vector. The byte slice is expected to be in base32 encoding,
// big-endian order.
func (fv *FeatureVector) DecodeBolt11(data []byte) error {
	var bits []FeatureBit

	// big-endian -> little-endian, to make it easier which bit to set while
	// iterating over the bytes
	slices.Reverse(data)
	for i, b := range data {
		for j := 0; j < 5; j++ {
			if b&(1<<j) != 0 {
				bit := FeatureBit(i*5 + j)
				if bit.IsUnknown() && bit.IsRequired() {
					return fmt.Errorf("%w: %v", ErrUnknownRequiredFeatureBit, bit)
				}
				bits = append(bits, bit)
			}
		}
	}

	// override the feature vector with a new one to make sure we always
	// correctly initialize the feature vector
	*fv = *NewFeatureVector(bits...)

	return nil
}

// IsUnknown returns true if the feature bit is unknown to the bolt09 spec.
func (b *FeatureBit) IsUnknown() bool {
	return *b >= 62
}

// IsRequired returns true if the feature bit is required, which means it's an even bit.
func (b *FeatureBit) IsRequired() bool {
	return *b%2 == 0
}

func (b *FeatureBit) Name() string {
	v := *b
	switch v {
	case DataLossProtectRequired, DataLossProtectOptional:
		return "option_data_loss_protect"
	case UpfrontShutdownScriptRequired, UpfrontShutdownScriptOptional:
		return "option_upfront_shutdown_script"
	case GossipQueriesRequired, GossipQueriesOptional:
		return "gossip_queries"
	case VarOnionOptinRequired, VarOnionOptinOptional:
		return "var_onion_optin"
	case GossipQueriesExtendedRequired, GossipQueriesExtendedOptional:
		return "gossip_queries_ex"
	case StaticRemotekeyRequired, StaticRemotekeyOptional:
		return "option_static_remotekey"
	case PaymentSecretRequired, PaymentSecretOptional:
		return "payment_secret"
	case BasicMppRequired, BasicMppOptional:
		return "basic_mpp"
	case SupportLargeChannelRequired, SupportLargeChannelOptional:
		return "option_support_large_channel"
	case AnchorsRequired, AnchorsOptional:
		return "option_anchors"
	case RouteBlindingRequired, RouteBlindingOptional:
		return "option_route_blinding"
	case ShutdownAnysegwitRequired, ShutdownAnysegwitOptional:
		return "option_shutdown_anysegwit"
	case DualFundRequired, DualFundOptional:
		return "option_dual_fund"
	case QuiesceRequired, QuiesceOptional:
		return "option_quiesce"
	case AttributionDataRequired, AttributionDataOptional:
		return "option_attribution_data"
	case OnionMessagesRequired, OnionMessagesOptional:
		return "option_onion_messages"
	case ProvideStorageRequired, ProvideStorageOptional:
		return "option_provide_storage"
	case ChannelTypeRequired, ChannelTypeOptional:
		return "option_channel_type"
	case ScidAliasRequired, ScidAliasOptional:
		return "option_scid_alias"
	case PaymentMetadataRequired, PaymentMetadataOptional:
		return "option_payment_metadata"
	case ZeroconfRequired, ZeroconfOptional:
		return "option_zeroconf"
	case SimpleCloseRequired, SimpleCloseOptional:
		return "option_simple_close"
	default:
		return "unknown"
	}
}
