package bolt08

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hexKey(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("bad key hex")
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

// FuzzBolt08_Decrypt feeds arbitrary wire bytes to Transport.Decrypt. The bytes
// on the wire are fully attacker-controlled, so Decrypt must never panic and
// must reject any input it cannot authenticate.
//
// The receive key here is the spec's rk while the seeds are ciphertexts that
// were produced under sk, so neither the seeds nor any mutation of them carry a
// valid MAC for this key: Decrypt must always return an error.
func FuzzBolt08_Decrypt(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 2+macSize)) // a full length frame, all zeroes
	seed, _ := hex.DecodeString("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95")
	f.Add(seed)

	recvKey := hexKey("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442")
	recvChain := hexKey("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01")

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic recovered: %v", r)
			}
		}()

		// Fresh Transport per iteration; the [32]byte keys are copied by value.
		tr := &Transport{recvKey: recvKey, recvChain: recvChain}
		if _, err := tr.Decrypt(bytes.NewReader(data)); err == nil {
			t.Errorf("Decrypt accepted unauthenticated input of %d bytes", len(data))
		}
	})
}

// FuzzBolt08_RoundTrip checks that any message survives Encrypt followed by
// Decrypt unchanged. Unlike the Decrypt fuzzer, this drives valid ciphertexts,
// so it reaches the length-prefix and payload-allocation paths for arbitrary
// message sizes (including empty and the maximum).
func FuzzBolt08_RoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0xff}, maxMessageSize))

	// A shared key for both ends: the sender encrypts with sk, the receiver
	// decrypts with the same key as its recv key.
	key := hexKey("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
	chain := hexKey("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01")

	f.Fuzz(func(t *testing.T, msg []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic recovered: %v", r)
			}
		}()

		sender := &Transport{sendKey: key, sendChain: chain}
		receiver := &Transport{recvKey: key, recvChain: chain}

		ciphertext, err := sender.Encrypt(msg)
		if len(msg) > maxMessageSize {
			if err == nil {
				t.Errorf("Encrypt accepted oversized message of %d bytes", len(msg))
			}
			return
		}
		if err != nil {
			t.Fatalf("Encrypt failed for %d-byte message: %v", len(msg), err)
		}

		got, err := receiver.Decrypt(bytes.NewReader(ciphertext))
		if err != nil {
			t.Fatalf("Decrypt failed for %d-byte message: %v", len(msg), err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("round-trip mismatch: got %x want %x", got, msg)
		}
	})
}
