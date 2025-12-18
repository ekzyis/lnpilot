package bolt11

import "github.com/ekzyis/lntutor/lib/bech32"

type Bolt11Encoder interface {
	EncodeBase32() ([]byte, error)
	EncodeBolt11() ([]byte, error)
}

// Every Bolt11Encoder must also implement bech32.Base32Encoder
var _ bech32.Base32Encoder = (Bolt11Encoder)(nil)

type StringBolt11Encoder struct {
	*bech32.BytesBase32Encoder
}

type VarUintBolt11Encoder struct {
	*bech32.VarUintBase32Encoder
}

type UintBolt11Encoder struct {
	*bech32.UintBase32Encoder
}

func (e StringBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func (e VarUintBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func (e UintBolt11Encoder) EncodeBolt11() ([]byte, error) {
	return e.EncodeBase32()
}

func NewStringBolt11Encoder(data string) Bolt11Encoder {
	encoder := bech32.NewStringBase32Encoder(data)
	return StringBolt11Encoder{BytesBase32Encoder: &encoder}
}

func NewUintBolt11Encoder(num, bitLen uint) Bolt11Encoder {
	encoder := bech32.NewUintBase32Encoder(num, bitLen)
	return UintBolt11Encoder{UintBase32Encoder: &encoder}
}

func NewVarUintBolt11Encoder(num uint) Bolt11Encoder {
	encoder := bech32.NewVarUintBase32Encoder(num)
	return VarUintBolt11Encoder{VarUintBase32Encoder: &encoder}
}
