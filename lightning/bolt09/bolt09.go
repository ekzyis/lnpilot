package bolt09

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
	DataLossProtectRequired FeatureBit = 0
	DataLossProtectOptional FeatureBit = 1

	UpfrontShutdownScriptRequired FeatureBit = 4
	UpfrontShutdownScriptOptional FeatureBit = 5

	GossipQueriesRequired FeatureBit = 6
	GossipQueriesOptional FeatureBit = 7

	VarOnionOptinRequired FeatureBit = 8
	VarOnionOptinOptional FeatureBit = 9

	GossipQueriesExtendedRequired FeatureBit = 10
	GossipQueriesExtendedOptional FeatureBit = 11

	StaticRemotekeyRequired FeatureBit = 12
	StaticRemotekeyOptional FeatureBit = 13

	PaymentSecretRequired FeatureBit = 14
	PaymentSecretOptional FeatureBit = 15

	BasicMppRequired FeatureBit = 16
	BasicMppOptional FeatureBit = 17

	SupportLargeChannelRequired FeatureBit = 18
	SupportLargeChannelOptional FeatureBit = 19

	AnchorsRequired FeatureBit = 22
	AnchorsOptional FeatureBit = 23

	RouteBlindingRequired FeatureBit = 24
	RouteBlindingOptional FeatureBit = 25

	ShutdownAnysegwitRequired FeatureBit = 26
	ShutdownAnysegwitOptional FeatureBit = 27

	DualFundRequired FeatureBit = 28
	DualFundOptional FeatureBit = 29

	QuiesceRequired FeatureBit = 34
	QuiesceOptional FeatureBit = 35

	AttributionDataRequired FeatureBit = 36
	AttributionDataOptional FeatureBit = 37

	OnionMessagesRequired FeatureBit = 38
	OnionMessagesOptional FeatureBit = 39

	ProvideStorageRequired FeatureBit = 42
	ProvideStorageOptional FeatureBit = 43

	ChannelTypeRequired FeatureBit = 44
	ChannelTypeOptional FeatureBit = 45

	ScidAliasRequired FeatureBit = 46
	ScidAliasOptional FeatureBit = 47

	PaymentMetadataRequired FeatureBit = 48
	PaymentMetadataOptional FeatureBit = 49

	ZeroconfRequired FeatureBit = 50
	ZeroconfOptional FeatureBit = 51

	SimpleCloseRequired FeatureBit = 60
	SimpleCloseOptional FeatureBit = 61
)

func NewFeatureVector(bits ...FeatureBit) *FeatureVector {
	fv := &FeatureVector{features: make(map[FeatureBit]struct{})}
	for _, bit := range bits {
		fv.Set(bit)
		if int(bit) > fv.maxBit {
			fv.maxBit = int(bit)
		}
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

// EncodeBase32 returns the bytes of the feature vector in base32 encoding,
// big-endian order.
func (fv FeatureVector) EncodeBase32() ([]byte, error) {
	b := make([]byte, fv.maxBit/5+1)
	for bit := range fv.features {
		index := (len(b) - 1) - int(bit)/5
		b[index] |= 1 << (bit % 5)
	}
	return b, nil
}

func (fv FeatureVector) EncodeBolt11() ([]byte, error) {
	return fv.EncodeBase32()
}
