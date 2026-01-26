package lntypes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBigSizeEncode(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		val      BigSize
		expected []byte
	}{
		// test vectors from bolt01
		{0, []byte{0x00}},
		{252, []byte{0xfc}},
		{253, []byte{0xfd, 0x00, 0xfd}},
		{65535, []byte{0xfd, 0xff, 0xff}},
		{65536, []byte{0xfe, 0x00, 0x01, 0x00, 0x00}},
		{4294967295, []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},
		{4294967296, []byte{0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, test := range tests {
		res := test.val.Encode()
		assert.Equal(test.expected, res)
	}
}
