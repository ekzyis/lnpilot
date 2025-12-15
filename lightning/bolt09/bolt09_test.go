package bolt09

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFeatureVector_Bytes(t *testing.T) {
	assert := assert.New(t)
	fv := NewFeatureVector(PaymentSecretRequired, VarOnionOptinRequired)
	assert.Equal([]byte{0b01000001, 0b00000000}, fv.Bytes())
}

func TestFeatureVector_EncodeBase32(t *testing.T) {
	assert := assert.New(t)
	fv := NewFeatureVector(PaymentSecretRequired, VarOnionOptinRequired)
	base32, err := fv.EncodeBase32()
	assert.NoError(err)
	assert.Equal([]byte{0b10000, 0b01000, 0b00000}, base32)
}
