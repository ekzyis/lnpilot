package lntypes

type BigSize uint64

func (bs BigSize) Encode() []byte {
	n := uint64(bs)
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{
			0xfe,
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	default:
		return []byte{
			0xff,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	}
}
