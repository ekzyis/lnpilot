package bolt11

import (
	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/ekzyis/lntutor/lightning/bolt09"
	"github.com/ekzyis/lntutor/lightning/lntypes"
)

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
		// Go does not allow a direct cast between []FeatureBit and
		// []bolt09.FeatureBit
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

func WithDefaultExpiry() func(*PaymentRequest) {
	return WithExpiry(time.Hour)
}

func WithNoExpiry() func(*PaymentRequest) {
	return WithExpiry(0)
}

func WithFallbackAddress(fallbackAddress string) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.FallbackAddress = fallbackAddress
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeF)
	}
}

func WithRoutingHint(
	hops ...*lntypes.HopHint,
) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.RoutingHints = append(pr.RoutingHints, lntypes.NewRoutingHint(hops))
		pr.taggedFields = append(pr.taggedFields, fieldTypeR)
	}
}

func WithMinFinalCLTVExpiryDelta(minFinalCLTVExpiryDelta uint16) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.MinFinalCLTVExpiryDelta = minFinalCLTVExpiryDelta
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeC)
	}
}

func WithDefaultMinFinalCLTVExpiryDelta() func(*PaymentRequest) {
	return WithMinFinalCLTVExpiryDelta(18)
}

func WithNoMinFinalCLTVExpiryDelta() func(*PaymentRequest) {
	return WithMinFinalCLTVExpiryDelta(0)
}

func WithPaymentMetadata(paymentMetadata []byte) func(*PaymentRequest) {
	return func(pr *PaymentRequest) {
		pr.PaymentMetadata = paymentMetadata
		pr.taggedFields = appendOrMoveToEnd(pr.taggedFields, fieldTypeM)
	}
}
