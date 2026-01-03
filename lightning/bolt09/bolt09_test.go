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

func TestFeatureVector_EncodeBolt11(t *testing.T) {
	assert := assert.New(t)
	fv := NewFeatureVector(PaymentSecretRequired, VarOnionOptinRequired)
	base32, err := fv.EncodeBolt11()
	assert.NoError(err)
	assert.Equal([]byte{0b10000, 0b01000, 0b00000}, base32)
}
