package bolt08

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ekzyis/lnpilot/lib/secp256k1"
)

// Test vectors from BOLT #8:
// https://github.com/lightning/bolts/blob/master/08-transport.md#test-vectors
const (
	initiatorStaticHex    = "1111111111111111111111111111111111111111111111111111111111111111"
	initiatorEphemeralHex = "1212121212121212121212121212121212121212121212121212121212121212"
	responderStaticHex    = "2121212121212121212121212121212121212121212121212121212121212121"
	responderEphemeralHex = "2222222222222222222222222222222222222222222222222222222222222222"

	actOneHex   = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
	actTwoHex   = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"
	actThreeHex = "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"

	// Final transport keys (from the initiator's perspective).
	sendKeyHex  = "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
	recvKeyHex  = "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"
	chainKeyHex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], mustHex(t, s))
	return out
}

// fixedEphemeral returns a generator that always yields the given private key,
// so the deterministic spec vectors can be reproduced.
func fixedEphemeral(priv *secp256k1.PrivateKey) func() (*secp256k1.PrivateKey, error) {
	return func() (*secp256k1.PrivateKey, error) {
		return priv, nil
	}
}

func TestHandshake(t *testing.T) {
	initStatic := secp256k1.PrivKeyFromBytes(mustHex(t, initiatorStaticHex))
	initEphemeral := secp256k1.PrivKeyFromBytes(mustHex(t, initiatorEphemeralHex))
	respStatic := secp256k1.PrivKeyFromBytes(mustHex(t, responderStaticHex))
	respEphemeral := secp256k1.PrivKeyFromBytes(mustHex(t, responderEphemeralHex))

	initiator := NewInitiatorHandshake(initStatic, respStatic.PubKey())
	initiator.genEphemeral = fixedEphemeral(initEphemeral)

	responder := NewResponderHandshake(respStatic)
	responder.genEphemeral = fixedEphemeral(respEphemeral)

	// Act one: initiator -> responder.
	actOne, err := initiator.GenActOne()
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, actOneHex), actOne[:], "act one bytes")
	require.NoError(t, responder.RecvActOne(actOne))

	// Act two: responder -> initiator.
	actTwo, err := responder.GenActTwo()
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, actTwoHex), actTwo[:], "act two bytes")
	require.NoError(t, initiator.RecvActTwo(actTwo))

	// Act three: initiator -> responder.
	actThree, err := initiator.GenActThree()
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, actThreeHex), actThree[:], "act three bytes")
	require.NoError(t, responder.RecvActThree(actThree))

	// The responder must have learned and authenticated the initiator's
	// static key.
	assert.Equal(t,
		initStatic.PubKey().SerializeCompressed(),
		responder.RemoteStatic().SerializeCompressed(),
		"responder learns initiator static key",
	)

	// Both sides derive the same keys, mirrored.
	mi := initiator.Transport()
	mr := responder.Transport()

	assert.Equal(t, mustHex32(t, sendKeyHex), mi.sendKey, "initiator send key")
	assert.Equal(t, mustHex32(t, recvKeyHex), mi.recvKey, "initiator recv key")
	assert.Equal(t, mustHex32(t, chainKeyHex), mi.sendChain, "chaining key")

	assert.Equal(t, mi.sendKey, mr.recvKey, "initiator send == responder recv")
	assert.Equal(t, mi.recvKey, mr.sendKey, "initiator recv == responder send")

	// And the transport actually round-trips a message.
	ciphertext, err := mi.Encrypt([]byte("hello"))
	require.NoError(t, err)
	plaintext, err := mr.Decrypt(bytes.NewReader(ciphertext))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), plaintext)
}

// mustActTwo / mustActThree / mustActOne decode a spec hex string into the
// fixed-size act array the Recv* methods expect.
func mustActOne(t *testing.T, s string) [ActOneSize]byte {
	t.Helper()
	var out [ActOneSize]byte
	copy(out[:], mustHex(t, s))
	return out
}

func mustActTwo(t *testing.T, s string) [ActTwoSize]byte {
	t.Helper()
	var out [ActTwoSize]byte
	copy(out[:], mustHex(t, s))
	return out
}

func mustActThree(t *testing.T, s string) [ActThreeSize]byte {
	t.Helper()
	var out [ActThreeSize]byte
	copy(out[:], mustHex(t, s))
	return out
}

// newInitiator / newResponder build a handshake side with the deterministic
// spec ephemeral keys.
func newInitiator(t *testing.T) *Handshake {
	t.Helper()
	initStatic := secp256k1.PrivKeyFromBytes(mustHex(t, initiatorStaticHex))
	respStatic := secp256k1.PrivKeyFromBytes(mustHex(t, responderStaticHex))
	hs := NewInitiatorHandshake(initStatic, respStatic.PubKey())
	hs.genEphemeral = fixedEphemeral(secp256k1.PrivKeyFromBytes(mustHex(t, initiatorEphemeralHex)))
	return hs
}

func newResponder(t *testing.T) *Handshake {
	t.Helper()
	respStatic := secp256k1.PrivKeyFromBytes(mustHex(t, responderStaticHex))
	hs := NewResponderHandshake(respStatic)
	hs.genEphemeral = fixedEphemeral(secp256k1.PrivKeyFromBytes(mustHex(t, responderEphemeralHex)))
	return hs
}

// Negative vectors from BOLT #8 Appendix A. The "short read" vectors are
// omitted: the Recv* API takes fixed-size arrays, so truncation is enforced by
// the type and belongs to the (future) network read layer instead.

func TestInitiatorActTwoErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"bad version", "0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"},
		{"bad key serialization", "0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"},
		{"bad MAC", "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := newInitiator(t)
			_, err := hs.GenActOne()
			require.NoError(t, err)
			assert.Error(t, hs.RecvActTwo(mustActTwo(t, tt.input)))
		})
	}
}

func TestResponderActOneErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"bad version", "01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"},
		{"bad key serialization", "00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"},
		{"bad MAC", "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := newResponder(t)
			assert.Error(t, hs.RecvActOne(mustActOne(t, tt.input)))
		})
	}
}

func TestResponderActThreeErrors(t *testing.T) {
	const validActOne = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
	tests := []struct {
		name  string
		input string
	}{
		{"bad version", "01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"},
		{"bad MAC for ciphertext", "00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"},
		{"bad rs", "00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c"},
		{"bad MAC", "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := newResponder(t)
			require.NoError(t, hs.RecvActOne(mustActOne(t, validActOne)))
			_, err := hs.GenActTwo()
			require.NoError(t, err)
			assert.Error(t, hs.RecvActThree(mustActThree(t, tt.input)))
		})
	}
}

// Short-read vectors from BOLT #8 Appendix A (ACT1/2/3_READ_FAILED). Unlike the
// other negative vectors, these exercise the network read layer rather than the
// Recv* methods: the latter take fixed-size arrays, so a truncated act can't be
// expressed there. They belong to the Conn handshake (io.ReadFull on the
// stream), which surfaces a truncated act as a read error.
//
// Skipped until there's a mock net.Conn / truncated-stream harness to drive
// ClientHandshake / ServerHandshake against these inputs.
func TestHandshakeShortReads(t *testing.T) {
	tests := []struct {
		name  string
		input string // one byte short of a full act
	}{
		{"responder act1 short read", "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c"},
		{"initiator act2 short read", "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730"},
		{"responder act3 short read", "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Skip("short reads are handled by the Conn read layer; needs a truncated-stream harness")
		})
	}
}

// TestTransportDecryptVector independently verifies Decrypt against the spec's
// own ciphertext bytes (messages 0 and 1), not against our own Encrypt output.
// This catches a symmetric bug that a pure round-trip test would hide.
func TestTransportDecryptVector(t *testing.T) {
	rx := &Transport{
		recvKey:   mustHex32(t, sendKeyHex), // the sender's sk is our recv key
		recvChain: mustHex32(t, chainKeyHex),
	}
	for _, ctHex := range []string{
		"cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95",
		"72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1",
	} {
		pt, err := rx.Decrypt(bytes.NewReader(mustHex(t, ctHex)))
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), pt)
	}
}

// TestTransportDecryptRotation pairs an encryptor and decryptor and confirms
// Decrypt stays in sync with Encrypt across both key rotations.
func TestTransportDecryptRotation(t *testing.T) {
	tx := &Transport{sendKey: mustHex32(t, sendKeyHex), sendChain: mustHex32(t, chainKeyHex)}
	rx := &Transport{recvKey: mustHex32(t, sendKeyHex), recvChain: mustHex32(t, chainKeyHex)}
	for i := 0; i <= 1001; i++ {
		ct, err := tx.Encrypt([]byte("hello"))
		require.NoError(t, err)
		pt, err := rx.Decrypt(bytes.NewReader(ct))
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), pt, "message %d", i)
	}
}

func TestTransportKeyRotation(t *testing.T) {
	// Drive the initiator's sending side with the spec's final keys and verify
	// the encrypted "hello" at the message indices the spec pins, which span
	// two key rotations.
	m := &Transport{
		sendKey:   mustHex32(t, sendKeyHex),
		sendChain: mustHex32(t, chainKeyHex),
	}

	want := map[int]string{
		0:    "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95",
		1:    "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1",
		500:  "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8",
		501:  "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd",
		1000: "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09",
		1001: "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36",
	}

	for i := 0; i <= 1001; i++ {
		ciphertext, err := m.Encrypt([]byte("hello"))
		require.NoError(t, err)
		if expected, ok := want[i]; ok {
			assert.Equal(t, expected, hex.EncodeToString(ciphertext), "message %d", i)
		}
	}
}
