package lntypes

type Network string

const (
	NetworkMainnet Network = "mainnet"
	NetworkTestnet Network = "testnet"
	NetworkRegtest Network = "regtest"
	NetworkSignet  Network = "signet"
)

type NetworkPrefix string

const (
	NetworkPrefixMainnet NetworkPrefix = "lnbc"
	NetworkPrefixTestnet NetworkPrefix = "lntb"
	NetworkPrefixRegtest NetworkPrefix = "lnbcrt"
	NetworkPrefixSignet  NetworkPrefix = "lntbs"
)

func (n Network) Prefix() NetworkPrefix {
	switch n {
	case NetworkMainnet:
		return NetworkPrefixMainnet
	case NetworkTestnet:
		return NetworkPrefixTestnet
	case NetworkRegtest:
		return NetworkPrefixRegtest
	case NetworkSignet:
		return NetworkPrefixSignet
	}
	return NetworkPrefix("")
}
