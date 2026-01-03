package lntypes

type Bitcoin uint64

type PicoBitcoin uint64

type MilliSatoshi uint64

type Multiplier string

const (
	MultiplierMilli Multiplier = "m"
	MultiplierMicro Multiplier = "u"
	MultiplierNano  Multiplier = "n"
	MultiplierPico  Multiplier = "p"
)

var Multipliers = []Multiplier{MultiplierPico, MultiplierNano, MultiplierMicro, MultiplierMilli, ""}
