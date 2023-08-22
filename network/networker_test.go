package network

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type fuckEventer struct {
}

func (fe fuckEventer) Post(interface{}) {

}

func (fe fuckEventer) AddChainOpType(id common.ChainID, opType models.OperatorType) {

}
func (fe fuckEventer) RemoveChainOpType(id common.ChainID, opType models.OperatorType) {

}
func (fe fuckEventer) ReplaceChainOpTypes(id common.ChainID, fromType models.OperatorType, toType models.OperatorType) bool {
	return true
}

type dizhi struct {
	addr string
}

func (dz dizhi) Network() string {
	return "tcp"
}

func (dz dizhi) String() string {
	return dz.addr
}

/*
func TestNetWorker_DelayConnect(t *testing.T) {
	infos := scripts.ReadAndRecover(3, "../scripts/thinkeys.txt")
	ip0 := dizhi{"127.0.0.1:5088"}
	//	ip1 := "127.0.0.1:5188"
	//	ip2 := "127.0.0.1:5288"
	bootnodes := make(map[string]common.NodeID)
	bootnodes[ip0.String()] = *infos[0].Nid

	control0 := FakeEventer{}
	s0 := NewNetWorker(infos[0].Nid, 0, control0,
		&cryp.PrivateKey{infos[0].PriKey}, bootnodes, NewPortPool(6088, 6188))

	control1 := FakeEventer{}
	s1 := NewNetWorker(infos[1].Nid, 0, control1,
		&cryp.PrivateKey{infos[1].PriKey}, bootnodes, NewPortPool(6288, 6388))

	control2 := FakeEventer{}
	s2 := NewNetWorker(infos[2].Nid, 0, control2,
		&cryp.PrivateKey{infos[2].PriKey}, bootnodes, NewPortPool(6488, 6588))

	s0.Create(common.BasicNet, ip0, nil)
	time.Sleep(40 * time.Second)
	s1.Connect(common.BasicNet, ip0, nil)
	s2.Connect(common.BasicNet, ip0, nil)
	select {}

}
*/
