package lntypes

import "errors"

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

func DecodeNetworkPrefix(prefix string) (Network, error) {
	switch prefix {
	case string(NetworkPrefixMainnet):
		return NetworkMainnet, nil
	case string(NetworkPrefixTestnet):
		return NetworkTestnet, nil
	case string(NetworkPrefixRegtest):
		return NetworkRegtest, nil
	case string(NetworkPrefixSignet):
		return NetworkSignet, nil
	}
	return Network(""), errors.New("unknown network prefix")
}
