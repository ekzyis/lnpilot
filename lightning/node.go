package lightning

import (
	"log"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ekzyis/lntutor/lightning/bolt11"
	"github.com/ekzyis/lntutor/lightning/lntypes"
)

type Node struct {
	privateKey *lntypes.NodePrivateKey
	publicKey  *lntypes.NodePublicKey
	network    lntypes.Network
}

func NewNode(options ...func(*Node)) *Node {
	node := &Node{}

	for _, option := range options {
		option(node)
	}

	if node.privateKey == nil {
		privateKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("failed to generate private key: %v", err)
		}
		node.privateKey = lntypes.NewNodePrivateKey(privateKey)
		node.publicKey = node.privateKey.PubKey()
	}

	if node.network == "" {
		node.network = lntypes.NetworkMainnet
	}

	return node
}

func WithPrivateKey(privateKey *lntypes.NodePrivateKey) func(*Node) {
	return func(node *Node) {
		node.privateKey = privateKey
	}
}

func WithNetwork(network lntypes.Network) func(*Node) {
	return func(node *Node) {
		node.network = network
	}
}

func (n *Node) CreatePaymentRequest(msats uint64) *bolt11.PaymentRequest {
	return bolt11.NewPaymentRequest(msats, bolt11.WithNetwork(n.network))
}
