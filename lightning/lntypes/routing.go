package lntypes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ekzyis/lnpilot/lib/bech32"
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

func (r *RoutingHint) DecodeBolt11(data []byte) error {
	dataBase256, err := bech32.NewBytesBase32Decoder(data).DecodeBase32()
	if err != nil {
		return err
	}

	if len(dataBase256)%hopHintLength != 0 {
		return fmt.Errorf("invalid routing hint data length: got %d, expected multiple of %d", len(data), hopHintLength)
	}

	reader := bytes.NewReader(dataBase256)
	var hopHints []*HopHint

	for reader.Len() >= hopHintLength {
		// pubkey
		pubKeyBytes := make([]byte, 33)
		if _, err := io.ReadFull(reader, pubKeyBytes); err != nil {
			return fmt.Errorf("failed to read pubkey in routing hint: %w", err)
		}
		pubKey, err := ParseNodePublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse pubkey in routing hint: %w", err)
		}

		// scid
		scidBytes := make([]byte, 8)
		if _, err := io.ReadFull(reader, scidBytes); err != nil {
			return fmt.Errorf("failed to read scid in routing hint: %w", err)
		}
		scid := NewShortChannelIDFromUint64(binary.BigEndian.Uint64(scidBytes))

		// base fee
		baseFeeBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, baseFeeBytes); err != nil {
			return fmt.Errorf("failed to read base fee in routing hint: %w", err)
		}
		baseFee := MilliSatoshi(binary.BigEndian.Uint32(baseFeeBytes))

		// fee ppm
		feePPMBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, feePPMBytes); err != nil {
			return fmt.Errorf("failed to read fee ppm in routing hint: %w", err)
		}
		feePPM := binary.BigEndian.Uint32(feePPMBytes)

		// cltv expiry delta
		cltvExpiryDeltaBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, cltvExpiryDeltaBytes); err != nil {
			return fmt.Errorf("failed to read cltv expiry delta in routing hint: %w", err)
		}
		cltvExpiryDelta := binary.BigEndian.Uint16(cltvExpiryDeltaBytes)

		hopHints = append(hopHints, NewHopHint(pubKey, scid, baseFee, feePPM, cltvExpiryDelta))
	}

	r.HopHints = hopHints
	return nil
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

func NewShortChannelIDFromUint64(num uint64) *ShortChannelID {
	return &ShortChannelID{
		BlockHeight: uint32(num>>40) & 0xffffff,
		TxIndex:     uint32(num>>16) & 0xffffff,
		OutIndex:    uint16(num & 0xffff),
	}
}
