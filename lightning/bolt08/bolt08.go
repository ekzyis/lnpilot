// BOLT #8: Encrypted and Authenticated Transport
// https://github.com/lightning/bolts/blob/master/08-transport.md

package bolt08

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/ekzyis/lnpilot/lib/secp256k1"
)

const (
	handshakeVersion    = byte(0x00)
	protocolName        = "Noise_XK_secp256k1_ChaChaPoly_SHA256"
	prologue            = "lightning"
	keyRotationInterval = 1000
	macSize             = 16
	maxMessageSize      = 65535
)

// Act sizes on the wire. Act one and two carry an ephemeral key; act three
// additionally carries the initiator's (encrypted) static key.
const (
	ActOneSize   = 50 // version(1) + ephemeral(33) + mac(16)
	ActTwoSize   = 50 // version(1) + ephemeral(33) + mac(16)
	ActThreeSize = 66 // version(1) + encrypted static key(33+16) + mac(16)
)

// makeNonce builds the 96-bit ChaCha20-Poly1305 nonce used throughout BOLT #8:
// four zero bytes followed by the 64-bit counter encoded little-endian.
func makeNonce(n uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}

// encryptWithAD encrypts plaintext with given key, nonce, associated data, returning
// ciphertext || mac.
func encryptWithAD(key [32]byte, nonce uint64, ad, plaintext []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		// only fails on wrong key length, which cannot happen here
		panic(err)
	}
	return aead.Seal(nil, makeNonce(nonce), plaintext, ad)
}

// decryptWithAD reverses encryptWithAD, verifying the authentication tag.
func decryptWithAD(key [32]byte, nonce uint64, ad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, makeNonce(nonce), ciphertext, ad)
}

// hkdf2 is the BOLT #8 key derivation function: HKDF-SHA256 with the chaining
// key as salt, empty info and a 64-byte output split into two 32-byte keys.
func hkdf2(salt [32]byte, ikm []byte) ([32]byte, [32]byte) {
	var out [64]byte
	r := hkdf.New(sha256.New, ikm, salt[:], nil)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		// reading from HKDF with a 64-byte output never fails
		panic(err)
	}
	var k1, k2 [32]byte
	copy(k1[:], out[:32])
	copy(k2[:], out[32:])
	return k1, k2
}

// symmetricState tracks the evolving handshake hash and chaining key, following
// the Noise "SymmetricState" object. The nonce resets to zero whenever a new
// key is mixed in and increments on each encrypt/decrypt with the current key.
type symmetricState struct {
	ck    [32]byte // chaining key
	h     [32]byte // handshake hash
	tempK [32]byte // current encryption key
	nonce uint64
}

func newSymmetricState() symmetricState {
	h := sha256.Sum256([]byte(protocolName))
	s := symmetricState{ck: h, h: h}
	s.mixHash([]byte(prologue))
	return s
}

// mixHash folds data into the handshake hash: h = SHA256(h || data).
func (s *symmetricState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(s.h[:])
	h.Write(data)
	copy(s.h[:], h.Sum(nil))
}

// mixKey derives a new chaining key and encryption key from the DH output and
// resets the nonce.
func (s *symmetricState) mixKey(ikm []byte) {
	s.ck, s.tempK = hkdf2(s.ck, ikm)
	s.nonce = 0
}

// encryptAndHash encrypts plaintext with the current key (using h as associated
// data) and mixes the resulting ciphertext into the handshake hash.
func (s *symmetricState) encryptAndHash(plaintext []byte) []byte {
	c := encryptWithAD(s.tempK, s.nonce, s.h[:], plaintext)
	s.nonce++
	s.mixHash(c)
	return c
}

// decryptAndHash reverses encryptAndHash.
func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := decryptWithAD(s.tempK, s.nonce, s.h[:], ciphertext)
	if err != nil {
		return nil, err
	}
	s.nonce++
	s.mixHash(ciphertext)
	return plaintext, nil
}

// Handshake drives the three-act Noise_XK handshake for either the initiator or
// the responder. After the final act, call Transport to obtain the transport.
type Handshake struct {
	symmetricState

	initiator bool

	localStatic     *secp256k1.PrivateKey
	localEphemeral  *secp256k1.PrivateKey
	remoteStatic    *secp256k1.PublicKey
	remoteEphemeral *secp256k1.PublicKey

	// genEphemeral produces ephemeral keys; overridable in tests to replay the
	// spec's deterministic test vectors.
	genEphemeral func() (*secp256k1.PrivateKey, error)
}

func newHandshake(initiator bool, localStatic *secp256k1.PrivateKey, remoteStatic *secp256k1.PublicKey) *Handshake {
	hs := &Handshake{
		symmetricState: newSymmetricState(),
		initiator:      initiator,
		localStatic:    localStatic,
		remoteStatic:   remoteStatic,
		genEphemeral:   secp256k1.GeneratePrivateKey,
	}

	// Both sides mix the responder's static public key into the hash. The
	// initiator knows it as the remote key; the responder uses its own.
	if initiator {
		hs.mixHash(remoteStatic.SerializeCompressed())
	} else {
		hs.mixHash(localStatic.PubKey().SerializeCompressed())
	}

	return hs
}

// NewInitiatorHandshake creates a handshake for the side that dials out and
// already knows the responder's static public key.
func NewInitiatorHandshake(localStatic *secp256k1.PrivateKey, remoteStatic *secp256k1.PublicKey) *Handshake {
	return newHandshake(true, localStatic, remoteStatic)
}

// NewResponderHandshake creates a handshake for the side that accepts a
// connection. The remote static key is learned during act three.
func NewResponderHandshake(localStatic *secp256k1.PrivateKey) *Handshake {
	return newHandshake(false, localStatic, nil)
}

// GenActOne is called by the initiator to produce the first message.
func (hs *Handshake) GenActOne() ([ActOneSize]byte, error) {
	var out [ActOneSize]byte

	e, err := hs.genEphemeral()
	if err != nil {
		return out, fmt.Errorf("act one: generate ephemeral: %w", err)
	}
	hs.localEphemeral = e

	ephemeral := e.PubKey().SerializeCompressed()
	hs.mixHash(ephemeral)

	es := secp256k1.ECDH(e, hs.remoteStatic)
	hs.mixKey(es[:])

	c := hs.encryptAndHash(nil)

	out[0] = handshakeVersion
	copy(out[1:34], ephemeral)
	copy(out[34:50], c)
	return out, nil
}

// RecvActOne is called by the responder to consume the initiator's first
// message and learn its ephemeral key.
func (hs *Handshake) RecvActOne(act [ActOneSize]byte) error {
	if act[0] != handshakeVersion {
		return fmt.Errorf("act one: unexpected version %d", act[0])
	}

	re, err := secp256k1.ParsePubKey(act[1:34])
	if err != nil {
		return fmt.Errorf("act one: parse ephemeral: %w", err)
	}
	hs.remoteEphemeral = re
	hs.mixHash(act[1:34])

	es := secp256k1.ECDH(hs.localStatic, re)
	hs.mixKey(es[:])

	if _, err := hs.decryptAndHash(act[34:50]); err != nil {
		return fmt.Errorf("act one: decrypt: %w", err)
	}
	return nil
}

// GenActTwo is called by the responder to reply with its ephemeral key.
func (hs *Handshake) GenActTwo() ([ActTwoSize]byte, error) {
	var out [ActTwoSize]byte

	e, err := hs.genEphemeral()
	if err != nil {
		return out, fmt.Errorf("act two: generate ephemeral: %w", err)
	}
	hs.localEphemeral = e

	ephemeral := e.PubKey().SerializeCompressed()
	hs.mixHash(ephemeral)

	ee := secp256k1.ECDH(e, hs.remoteEphemeral)
	hs.mixKey(ee[:])

	c := hs.encryptAndHash(nil)

	out[0] = handshakeVersion
	copy(out[1:34], ephemeral)
	copy(out[34:50], c)
	return out, nil
}

// RecvActTwo is called by the initiator to consume the responder's reply.
func (hs *Handshake) RecvActTwo(act [ActTwoSize]byte) error {
	if act[0] != handshakeVersion {
		return fmt.Errorf("act two: unexpected version %d", act[0])
	}

	re, err := secp256k1.ParsePubKey(act[1:34])
	if err != nil {
		return fmt.Errorf("act two: parse ephemeral: %w", err)
	}
	hs.remoteEphemeral = re
	hs.mixHash(act[1:34])

	ee := secp256k1.ECDH(hs.localEphemeral, re)
	hs.mixKey(ee[:])

	if _, err := hs.decryptAndHash(act[34:50]); err != nil {
		return fmt.Errorf("act two: decrypt: %w", err)
	}
	return nil
}

// GenActThree is called by the initiator to transmit its static key, proving
// its identity and completing the handshake.
func (hs *Handshake) GenActThree() ([ActThreeSize]byte, error) {
	var out [ActThreeSize]byte

	static := hs.localStatic.PubKey().SerializeCompressed()
	c := hs.encryptAndHash(static)

	se := secp256k1.ECDH(hs.localStatic, hs.remoteEphemeral)
	hs.mixKey(se[:])

	t := hs.encryptAndHash(nil)

	out[0] = handshakeVersion
	copy(out[1:50], c)
	copy(out[50:66], t)
	return out, nil
}

// RecvActThree is called by the responder to learn and authenticate the
// initiator's static key, completing the handshake.
func (hs *Handshake) RecvActThree(act [ActThreeSize]byte) error {
	if act[0] != handshakeVersion {
		return fmt.Errorf("act three: unexpected version %d", act[0])
	}

	staticBytes, err := hs.decryptAndHash(act[1:50])
	if err != nil {
		return fmt.Errorf("act three: decrypt static key: %w", err)
	}
	rs, err := secp256k1.ParsePubKey(staticBytes)
	if err != nil {
		return fmt.Errorf("act three: parse static key: %w", err)
	}
	hs.remoteStatic = rs

	se := secp256k1.ECDH(hs.localEphemeral, rs)
	hs.mixKey(se[:])

	if _, err := hs.decryptAndHash(act[50:66]); err != nil {
		return fmt.Errorf("act three: decrypt: %w", err)
	}
	return nil
}

// RemoteStatic returns the peer's static public key. For the responder this is
// only known once act three has been received.
func (hs *Handshake) RemoteStatic() *secp256k1.PublicKey {
	return hs.remoteStatic
}

// Transport derives the post-handshake transport keys and returns a Transport ready
// to encrypt and decrypt application messages.
func (hs *Handshake) Transport() *Transport {
	k1, k2 := hkdf2(hs.ck, nil)

	// The initiator's sending key is the responder's receiving key and vice
	// versa, so the two keys are assigned in opposite order on each side.
	sendKey, recvKey := k1, k2
	if !hs.initiator {
		sendKey, recvKey = k2, k1
	}

	return &Transport{
		sendKey:   sendKey,
		recvKey:   recvKey,
		sendChain: hs.ck,
		recvChain: hs.ck,
	}
}

// Transport encrypts and decrypts application messages over an established BOLT #8
// transport. It is not safe for concurrent use.
//
// Note: the key material held here (and the static/chaining keys in Handshake)
// is never zeroized after use. That is acceptable for this educational tool, but
// would need hardening before it protects real funds.
type Transport struct {
	sendKey   [32]byte
	recvKey   [32]byte
	sendChain [32]byte
	recvChain [32]byte
	sendNonce uint64
	recvNonce uint64
}

// rotateKey advances a transport key after keyRotationInterval messages.
func rotateKey(chain, key *[32]byte, nonce *uint64) {
	if *nonce == keyRotationInterval {
		*chain, *key = hkdf2(*chain, key[:])
		*nonce = 0
	}
}

// Encrypt produces the on-the-wire bytes for a message: an encrypted 2-byte
// length prefix followed by the encrypted payload, each with its own MAC.
func (m *Transport) Encrypt(msg []byte) ([]byte, error) {
	if len(msg) > maxMessageSize {
		return nil, fmt.Errorf("message length %d exceeds maximum of %d", len(msg), maxMessageSize)
	}

	var lengthBytes [2]byte
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(len(msg)))

	encLength := encryptWithAD(m.sendKey, m.sendNonce, nil, lengthBytes[:])
	m.sendNonce++
	encPayload := encryptWithAD(m.sendKey, m.sendNonce, nil, msg)
	m.sendNonce++
	rotateKey(&m.sendChain, &m.sendKey, &m.sendNonce)

	out := make([]byte, 0, len(encLength)+len(encPayload))
	out = append(out, encLength...)
	return append(out, encPayload...), nil
}

// Decrypt reads one encrypted message from r and returns the plaintext.
func (m *Transport) Decrypt(r io.Reader) ([]byte, error) {
	var encLength [2 + macSize]byte
	if _, err := io.ReadFull(r, encLength[:]); err != nil {
		return nil, err
	}
	lengthBytes, err := decryptWithAD(m.recvKey, m.recvNonce, nil, encLength[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt length: %w", err)
	}
	m.recvNonce++
	length := binary.BigEndian.Uint16(lengthBytes)

	encPayload := make([]byte, int(length)+macSize)
	if _, err := io.ReadFull(r, encPayload); err != nil {
		return nil, err
	}
	// On a payload MAC failure recvNonce has already been advanced for the
	// length field, leaving it desynced. That is acceptable: a transport MAC
	// failure is fatal, so the caller must tear down the connection rather than
	// attempt to decrypt any further messages.
	payload, err := decryptWithAD(m.recvKey, m.recvNonce, nil, encPayload)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	m.recvNonce++
	rotateKey(&m.recvChain, &m.recvKey, &m.recvNonce)

	return payload, nil
}
