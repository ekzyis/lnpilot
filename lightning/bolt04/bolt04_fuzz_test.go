package bolt04

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/ekzyis/lnpilot/lib/secp256k1"
)

// FuzzBolt04_NewOnionPacket tests NewOnionPacket with random (fuzzed) inputs.
func FuzzBolt04_NewOnionPacket(f *testing.F) {
	// Seed inputs - valid session key, associated data, and at least one hop.
	f.Add(
		"404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f",   // session key (hex)
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",   // associated data (hex)
		"022e0d1d444bdd41b2770626dc8b023cbe1178f035827c4c161bf4025ae0c55355", // hop pubKey (hex)
		"abcdef0123456789", // payload (hex)
		1,                  // hops count
	)

	f.Fuzz(func(t *testing.T, sessionKeyHex, assocDataHex, pubkeyHex, payloadHex string, hopsCount int) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic recovered: %v", r)
			}
		}()
		sessionKeyBytes, _ := hex.DecodeString(sessionKeyHex)
		if len(sessionKeyBytes) != 32 {
			return // skip invalid for privkey
		}
		sessionKey := secp256k1.PrivKeyFromBytes(sessionKeyBytes)

		assocData, _ := hex.DecodeString(assocDataHex)
		if len(assocData) == 0 {
			return // skip empty associated data
		}

		pubKeyBytes, _ := hex.DecodeString(pubkeyHex)
		pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
		if err != nil {
			return // skip invalid pubkey
		}

		payload, _ := hex.DecodeString(payloadHex)
		if len(payload) == 0 {
			return // skip empty payload
		}

		// hopsCount fuzzed, ensure in range
		nHops := max(min(hopsCount, 4096), 1)

		// Construct hops
		hops := make([]Hop, nHops)
		rng := rand.New(rand.NewSource(0))
		for i := 0; i < nHops; i++ {
			payloadCopy := make([]byte, rng.Intn(4096))
			rng.Read(payloadCopy)
			hops[i] = Hop{
				PubKey:  pubKey,
				Payload: payloadCopy,
			}
		}

		_, _ = NewOnionPacket(sessionKey, assocData, hops)
	})
}
