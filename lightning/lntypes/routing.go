package lntypes

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/ekzyis/lntutor/lib/bech32"
)

const (
	// The length of a hop hint in bytes.
	hopHintLength = 51
)

// RoutingHint contains a list of hops that a node can use for pathfinding.
type RoutingHint struct {
	HopHints []*HopHint
}

// HopHint is a single hop in a routing hint.
type HopHint struct {
	PubKey          *NodePublicKey  // 33 bytes
	ShortChannelID  *ShortChannelID // 8 bytes
	BaseFee         MilliSatoshi    // 4 bytes
	FeePPM          uint32          // 4 bytes
	CLTVExpiryDelta uint16          // 2 bytes
}

type ShortChannelID struct {
	BlockHeight uint32 // 3 bytes
	TxIndex     uint32 // 3 bytes
	OutIndex    uint16 // 2 bytes
}

func NewRoutingHint(hopHints []*HopHint) *RoutingHint {
	return &RoutingHint{HopHints: hopHints}
}

func (r *RoutingHint) EncodeBolt11() ([]byte, error) {
	routeHintBase256 := make([]byte, 0, len(r.HopHints)*hopHintLength)

	for _, hopHint := range r.HopHints {
		hopHintBase256 := make([]byte, hopHintLength)

		pubKeyBytes, err := hopHint.PubKey.SerializeCompressed()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize public key: %w", err)
		}
		copy(hopHintBase256[:33], pubKeyBytes)

		binary.BigEndian.PutUint64(hopHintBase256[33:41], hopHint.ShortChannelID.ToUint64())
		binary.BigEndian.PutUint32(hopHintBase256[41:45], uint32(hopHint.BaseFee))
		binary.BigEndian.PutUint32(hopHintBase256[45:49], uint32(hopHint.FeePPM))
		binary.BigEndian.PutUint16(hopHintBase256[49:51], uint16(hopHint.CLTVExpiryDelta))

		routeHintBase256 = append(routeHintBase256, hopHintBase256...)
	}

	return bech32.ConvertBits(routeHintBase256, 8, 5, true)
}

func NewHopHint(
	pubKey *NodePublicKey,
	scid *ShortChannelID,
	baseFee MilliSatoshi,
	feePPM uint32,
	cltvExpiryDelta uint16,
) *HopHint {
	return &HopHint{
		PubKey:          pubKey,
		ShortChannelID:  scid,
		BaseFee:         baseFee,
		FeePPM:          feePPM,
		CLTVExpiryDelta: cltvExpiryDelta,
	}
}

func NewShortChannelID(
	blockHeight uint32,
	txIndex uint32,
	vout uint16,
) *ShortChannelID {
	return &ShortChannelID{
		BlockHeight: blockHeight,
		TxIndex:     txIndex,
		OutIndex:    vout,
	}
}

func ParseShortChannelID(str string) (*ShortChannelID, error) {
	parts := strings.Split(str, "x")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid short channel ID format: %s", str)
	}

	blockHeight, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block height as uint32: %s: %w", parts[0], err)
	}

	txIndex, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx index as uint32: %s: %w", parts[1], err)
	}

	vout, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vout as uint16: %s: %w", parts[2], err)
	}

	return NewShortChannelID(uint32(blockHeight), uint32(txIndex), uint16(vout)), nil
}

func MustParseShortChannelID(str string) *ShortChannelID {
	scid, err := ParseShortChannelID(str)
	if err != nil {
		panic(err)
	}
	return scid
}

func (scid *ShortChannelID) ToUint64() uint64 {
	return (uint64(scid.BlockHeight) << 40) | (uint64(scid.TxIndex) << 16) | uint64(scid.OutIndex)
}
