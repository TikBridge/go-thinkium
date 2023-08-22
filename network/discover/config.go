package discover

import (
	"net"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/network/nat"
)

type P2PConfig struct {
	DatabasePath string

	BootstrapNodes []*Node

	StaticNodes []*Node

	TrustedNodes []*Node

	NetRestrict *Netlist

	ListenAddr string

	MaxPeersCount int

	MaxPendCount int

	DialRatio int

	Nat nat.Nat

	AnnounceAddr *net.UDPAddr

	DiscoveryType DiscoveryType

	ChainDataNodes []*ChainDataNodes

	Clock Clock
}

type ChainDataNodes struct {
	ChainId   common.ChainID
	DataNodes []*Node
}

func ToChainDataNodes(net common.NetType, bootId common.ChainID, infos []*common.ChainInfos) []*ChainDataNodes {
	if len(infos) == 0 {
		return nil
	}
	ret := make([]*ChainDataNodes, len(infos))
	for i, info := range infos {
		node := info2nodes(net, bootId, info)
		ret[i] = node
	}
	return ret
}

func info2nodes(nt common.NetType, bootId common.ChainID, info *common.ChainInfos) *ChainDataNodes {
	// Turn off here，because the sendToNode method needs query the chainId with nodeId when discovery type is sort
	// if info.ID != bootId {
	// 	return &ChainDataNodes{
	// 		ChainId: info.ID,
	// 	}
	// }
	var nodes []*Node
	for _, n := range info.BootNodes {
		nid, err := n.GetNodeID()
		if err != nil {
			continue
		}
		var node *Node
		switch nt {
		case common.BasicNet:
			node = NewNode(*nid, net.ParseIP(n.IP), n.BasicPort, n.BasicPort, n.DataRpcPort)
		case common.RootDataNet:
			node = NewNode(*nid, net.ParseIP(n.IP), n.DataPort0, n.DataPort0, n.DataRpcPort)
		case common.BranchDataNet:
			node = NewNode(*nid, net.ParseIP(n.IP), n.DataPort1, n.DataPort1, n.DataRpcPort)
		case common.ConsensusNet1:
			node = NewNode(*nid, net.ParseIP(n.IP), n.ConsensusPort0, n.ConsensusPort0, n.DataRpcPort)
		case common.ConsensusNet2:
			node = NewNode(*nid, net.ParseIP(n.IP), n.ConsensusPort1, n.ConsensusPort1, n.DataRpcPort)
		default:
			panic("unknown net type " + nt.String())
		}
		nodes = append(nodes, node)
	}

	return &ChainDataNodes{
		ChainId:   info.ID,
		DataNodes: nodes,
	}
}
