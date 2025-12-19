package bolt11

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	_secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ekzyis/lntutor/lib/bech32"
	"github.com/ekzyis/lntutor/lib/secp256k1"
	"github.com/ekzyis/lntutor/lightning/lntypes"
	"github.com/stretchr/testify/assert"
)

var (
	timestamp             = time.Unix(1496314658, 0)
	privKeyBytes, _       = hex.DecodeString("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")
	paymentSecretBytes, _ = hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	paymentHashBytes, _   = hex.DecodeString("0001020304050607080900010203040506070809000102030405060708090102")

	// this description is 200 bytes long, which isn't long enough to fall back to hashing,
	// so we hash it ourselves to pass the test vectors
	longDescription     = "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon"
	longDescriptionHash = sha256.Sum256([]byte(longDescription))
)

// TestSigner generates deterministic compact ECDSA signatures
// over secp256k1 using RFC6979 and HMAC-SHA256.
type TestSigner struct{}

func (s *TestSigner) CompactECDSASign(msg []byte) (secp256k1.CompactECDSASignature, error) {
	privKey := _secp256k1.PrivKeyFromBytes(privKeyBytes)

	hash := sha256.Sum256(msg)
	// this will generate a deterministic compact ECDSA signature according to RFC 6979
	sig := ecdsa.SignCompact(privKey, hash[:], true)

	return secp256k1.CompactECDSASignature{
		RecoveryId: sig[0] - 27 - 4,
		R:          [32]byte(sig[1:33]),
		S:          [32]byte(sig[33:65]),
	}, nil
}

func TestPaymentRequest_NewPaymentRequest(t *testing.T) {
	assert := assert.New(t)

	before := time.Now()
	pr := NewPaymentRequest(1_000)
	after := time.Now()

	// check hrp
	assert.Equalf(lntypes.NetworkMainnet, pr.Network, "network should be mainnet")
	assert.Equalf(lntypes.MilliSatoshi(1_000), pr.Msats, "amount should be 1 sat")
	hrp, err := pr.humanReadablePart()
	if !assert.NoError(err) {
		return
	}
	assert.Equalf("lnbc10n", hrp, "hrp should be lnbc10n")

	// check timestamp
	assert.Falsef(pr.Timestamp.IsZero(), "timestamp should be set")
	assert.Truef(before.Before(pr.Timestamp) && after.After(pr.Timestamp), "timestamp should be set to now")

	// check other properties
	assert.Equalf(3600*time.Second, pr.Expiry, "expiry should be 1 hour")
	assert.Falsef(pr.PaymentHash.IsZero(), "payment hash should be set")
	assert.Falsef(pr.PaymentSecret.IsZero(), "payment secret should be set")
	assert.Truef(pr.Description == "", "description should be empty")
	assert.Truef(pr.DescriptionHash.IsZero(), "description hash should be zero")
	assert.Truef(pr.FallbackAddress == "", "fallback address should be empty")

	// encode pr as bech32
	encoded, err := pr.EncodeBech32(&TestSigner{})
	if !assert.NoError(err) {
		return
	}

	// check hrp in bech32 encoded pr
	assert.Truef(strings.HasPrefix(encoded, hrp), "hrp bech32 mismatch")
	encoded = strings.TrimPrefix(encoded, hrp)

	// check bech32 separator '1'
	assert.Truef(strings.HasPrefix(encoded, "1"), "bech32 separator '1' missing")
	encoded = strings.TrimPrefix(encoded, "1")

	// check timestamp in bech32 encoded pr
	timestampBase32, _ := NewUintBolt11Encoder(uint(pr.Timestamp.Unix()), 35).EncodeBolt11()
	timestampBech32 := bech32.BytesToBech32Charset(timestampBase32)
	assert.Truef(strings.HasPrefix(encoded, timestampBech32), "timestamp bech32 mismatch")
	encoded = strings.TrimPrefix(encoded, timestampBech32)

	// check tagged fields + signature + checksum

	toBech32 := func(fieldType TaggedFieldType, data Bolt11Encoder) string {
		dataBase32, _ := data.EncodeBolt11()
		dataBase32Length, _ := NewUintBolt11Encoder(uint(len(dataBase32)), 10).EncodeBolt11()
		return fmt.Sprintf("%s%s%s",
			bech32.BytesToBech32Charset([]byte{fieldType}),
			bech32.BytesToBech32Charset(dataBase32Length),
			bech32.BytesToBech32Charset(dataBase32),
		)
	}

	tfMatchers := []func(*string) bool{
		func(encoded *string) bool {
			if (*encoded)[0] != 'p' {
				return false
			}
			paymentHashBech32 := toBech32(fieldTypeP, pr.PaymentHash)
			assert.Truef(strings.HasPrefix(*encoded, paymentHashBech32), "payment hash bech32 mismatch")
			*encoded = strings.TrimPrefix(*encoded, paymentHashBech32)
			return true
		},
		func(encoded *string) bool {
			if (*encoded)[0] != 's' {
				return false
			}
			paymentSecretBech32 := toBech32(fieldTypeS, pr.PaymentSecret)
			assert.Truef(strings.HasPrefix(*encoded, paymentSecretBech32), "payment secret bech32 mismatch")
			*encoded = strings.TrimPrefix(*encoded, paymentSecretBech32)
			return true
		},
		func(encoded *string) bool {
			if (*encoded)[0] != 'x' {
				return false
			}
			expiryBech32 := toBech32(fieldTypeX, NewVarUintBolt11Encoder(uint(pr.Expiry.Seconds())))
			assert.Truef(strings.HasPrefix(*encoded, expiryBech32), "expiry bech32 mismatch")
			*encoded = strings.TrimPrefix(*encoded, expiryBech32)
			return true
		},
		func(encoded *string) bool {
			if (*encoded)[0] != 'c' {
				return false
			}
			minFinalCLTVExpiryDeltaBech32 := toBech32(fieldTypeC, NewVarUintBolt11Encoder(uint(pr.MinFinalCLTVExpiryDelta)))
			assert.Truef(strings.HasPrefix(*encoded, minFinalCLTVExpiryDeltaBech32), "min_final_cltv_expiry_delta bech32 mismatch")
			*encoded = strings.TrimPrefix(*encoded, minFinalCLTVExpiryDeltaBech32)
			return true
		},
		func(encoded *string) bool {
			// signature is 64 bytes + 1 byte recovery id in base256
			// => 104 bytes in base32
			sigLength := (64 + 1) * 8 / 5
			checkSumLength := 6
			if len(*encoded) == sigLength+checkSumLength {
				*encoded = ""
				return true
			}
			return false
		},
	}

	for encoded != "" {
		match := false
		for i, matcher := range tfMatchers {
			if match = matcher(&encoded); match {
				// don't use matcher again
				tfMatchers = append(tfMatchers[:i], tfMatchers[i+1:]...)
				break
			}
		}
		if !match {
			assert.FailNow("unknown data in encoded payment request")
		}
	}

	assert.True(len(tfMatchers) == 0, "missing tagged fields in encoded payment request")
}

func TestPaymentRequest_EncodeBech32_Spec_001(t *testing.T) {
	// Please make a donation of any amount using payment_hash
	// 0001020304050607080900010203040506070809000102030405060708090102
	// to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad

	assert := assert.New(t)

	pr := NewPaymentRequest(
		0,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("Please consider supporting this project"),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)
	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_002(t *testing.T) {
	// Please send $3 for a cup of coffee to the same peer, within one minute

	assert := assert.New(t)

	pr := NewPaymentRequest(
		250_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("1 cup coffee"),
		WithExpiry(60*time.Second),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoMinFinalCLTVExpiryDelta(),
	)
	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_003(t *testing.T) {
	// Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯) to the same peer,
	// within one minute

	assert := assert.New(t)

	pr := NewPaymentRequest(
		250_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("ナンセンス 1杯"),
		WithExpiry(60*time.Second),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoMinFinalCLTVExpiryDelta(),
	)
	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_004(t *testing.T) {
	// Now send $24 for an entire list of things (hashed)

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_005(t *testing.T) {
	// The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithNetwork(lntypes.NetworkTestnet),
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithFallbackAddress("mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP"), // P2PKH
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_006(t *testing.T) {
	// On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T
	// with extra routing info to go via nodes
	// 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255
	// then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithFallbackAddress("1RustyRX2oai4EYYDpQGWvEL62BBGqN9T"), // P2PKH
		WithRoutingHint(
			lntypes.NewHopHint(
				lntypes.MustParseNodePublicKeyFromHex("029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"),
				lntypes.MustParseShortChannelID("66051x263430x1800"),
				lntypes.MilliSatoshi(1),
				20,
				3,
			),
			lntypes.NewHopHint(
				lntypes.MustParseNodePublicKeyFromHex("039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"),
				lntypes.MustParseShortChannelID("197637x395016x2314"),
				lntypes.MilliSatoshi(2),
				30,
				4,
			),
		),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_007(t *testing.T) {
	// On mainnet, with fallback (P2SH) address
	// 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithFallbackAddress("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"), // P2SH
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z99qrsgqz6qsgww34xlatfj6e3sngrwfy3ytkt29d2qttr8qz2mnedfqysuqypgqex4haa2h8fx3wnypranf3pdwyluftwe680jjcfp438u82xqphf75ym",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_008(t *testing.T) {
	// On mainnet, with fallback (P2WPKH) address
	// bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithFallbackAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), // P2WPKH
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7k9qrsgqt29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7hljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsqmrnsse",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_009(t *testing.T) {
	// On mainnet, with fallback (P2WSH) address
	// bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithFallbackAddress("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), // P2WSH
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_010(t *testing.T) {
	// On mainnet, with fallback (P2TR) address
	// bc1pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszse2s3lm

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescriptionHash(longDescriptionHash),
		WithFallbackAddress("bc1pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszse2s3lm"), // P2TR
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4pptdvg0d2nj99568qn6ssdy4cygnwuxgw2ukmnwgwz7jpqjz2kszs9qrsgqy606dznq28exnydt2r4c29y56xjtn3sk4mhgjtl4pg2y4ar3249rq4ajlmj9jy8zvlzw7cr8mggqzm842xfr0v72rswzq9xvr4hknfsqwmn6xd",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_011(t *testing.T) {
	// Please send 0.00967878534 BTC for a list of items
	// within one week, amount in pico-BTC

	assert := assert.New(t)

	paymentHashBytes, _ := hex.DecodeString("462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f")

	pr := NewPaymentRequest(
		967_878_534,
		WithTimestamp(time.Unix(1572468703, 0)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, \"Back In My Day\" Sticker x 2, \"I Got Lightning Working\" Sticker x 2 and 1 more items"),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithExpiry(604800*time.Second),
		WithMinFinalCLTVExpiryDelta(10),
		WithRoutingHint(
			lntypes.NewHopHint(
				lntypes.MustParseNodePublicKeyFromHex("03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7"),
				lntypes.MustParseShortChannelID("589390x3312x1"),
				lntypes.MilliSatoshi(1000),
				2500,
				40,
			),
		),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_012(t *testing.T) {
	// Please send $30 for coffee beans to the same peer,
	// which supports features 8, 14 and 99, using secret
	// 0x1111111111111111111111111111111111111111111111111111111111111111

	assert := assert.New(t)

	pr := NewPaymentRequest(
		2_500_000_000,
		WithTimestamp(timestamp),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("coffee beans"),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithFeatureBits(99, PaymentSecretRequired, VarOnionOptinRequired),
		WithNoExpiry(),
		WithNoMinFinalCLTVExpiryDelta(),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa",
		encoded,
	)
}

func TestPaymentRequest_DecodeBech32_Spec_013(t *testing.T) {
	// Same, but all upper case.

	// LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3SGPZ3UAPA

	t.Skip("decode not supported yet")
}

func TestPaymentRequest_DecodeBech32_Spec_014(t *testing.T) {
	// Same, but including fields which must be ignored.

	// lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x

	t.Skip("decode not supported yet")
}

func TestPaymentRequest_EncodeBech32_Spec_015(t *testing.T) {
	// Please send 0.01 BTC with payment metadata 0x01fafaf0

	t.Skip("tagged field m not supported yet")

	assert := assert.New(t)

	paymentHashBytes, _ := hex.DecodeString("462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f")

	pr := NewPaymentRequest(
		1_000_000_000,
		WithTimestamp(timestamp),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("payment metadata inside"),
		// TODO: add payment metadata (m) field from test vector
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithFeatureBits(48, PaymentSecretRequired, VarOnionOptinRequired),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc",
		encoded,
	)
}

func TestPaymentRequest_EncodeBech32_Spec_016(t *testing.T) {
	// Public-key recovery with high-S signature

	t.Skip("not sure why this doesn't work yet")

	assert := assert.New(t)

	pr := NewPaymentRequest(
		0,
		WithTimestamp(timestamp),
		WithPaymentSecret([32]byte(paymentSecretBytes)),
		WithPaymentHash([32]byte(paymentHashBytes)),
		WithDescription("Please consider supporting this project"),
		WithFeatureBits(PaymentSecretRequired, VarOnionOptinRequired),
		WithExpiry(0),
	)

	encoded, err := pr.EncodeBech32(&TestSigner{})

	assert.NoError(err)
	assert.Equal(
		"lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap2r09nt4ndd0unm3z9u5t48y6ucv4r5sg7lk98c77ctvjczkspk5qprc90gx",
		encoded,
	)
}
