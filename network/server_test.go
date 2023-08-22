package network

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/ThinkiumGroup/go-thinkium/network/discover"
)

const (
	NumberOfPeers = 20
)

type FakeEventer struct {
	Peer        *Server
	MessagePool RecentMsgPool
}

func (fe *FakeEventer) Shutdown() {

}
func (fe *FakeEventer) HasChainOpTypes(chainid common.ChainID, opType models.OperatorType) bool {
	return true
}

/*
func (fe *FakeEventer) Post(pb interface{}) {
	if v, ok := pb.(*models.RawDataObj); ok {
		switch v.GetEventType() {
		case models.TextEvent:
			if m, err := models.UnmarshalEvent(v.GetEventType(), v.GetData()); err == nil {
				msg, _ := m.(*models.TextEMessage)
				h := common.EncodeHash(*msg)
				if _, ok := fe.MessagePool.Get(h); !ok {
					fe.MessagePool.Put(*msg)
					log.Info(fe.Peer.Id.String(), msg.Body)
					fe.Peer.Broadcast(msg)
				} else {
					log.Info("already in!")
				}

			} else {
				log.Info(err)
			}
		case models.ToOneEvent:
			if m, err := models.UnmarshalEvent(v.GetEventType(), v.GetData()); err == nil {
				msg, _ := m.(*models.ToOneEMessage)
				h := common.EncodeHash(*msg)
				if _, ok := fe.MessagePool.Get(h); !ok {
					fe.MessagePool.Put(*msg)
					realmsg, _ := models.UnmarshalEvent(msg.Type, msg.Body)
					log.Info(fe.Peer.Id.String(), msg.To)
					fe.Peer.Send(&msg.To, realmsg)
				} else {
					log.Info("already in!")
				}
			} else {
				log.Info(err)
			}
		default:
			log.Error("error message")
		}
	} else {
		log.Error("post error!")
	}
}
*/

func (fe *FakeEventer) AddChainOpType(id common.ChainID, opType models.OperatorType) {

}
func (fe *FakeEventer) RemoveChainOpType(id common.ChainID, opType models.OperatorType) {

}
func (fe *FakeEventer) ReplaceChainOpTypes(id common.ChainID, fromType models.OperatorType, toType models.OperatorType) bool {
	return true
}

type RW struct {
	Conn net.Conn
}

func (r RW) ReadMsg() (Msg, error) {
	b := make([]byte, 4)
	_, err := r.Conn.Read(b)
	if err != nil {
		return Msg{}, err
	}
	bytesBuffer := bytes.NewBuffer(b)
	var tmp int
	binary.Read(bytesBuffer, binary.BigEndian, &tmp)
	return Msg{}, nil
}

func (r RW) WriteMsg(msg Msg) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(msg.LoadSize()))
	_, err := r.Conn.Write(b)
	return err
}

//
// func TestP2PServer_Broadcast(t *testing.T) {
// 	infos := scripts.ReadAndRecover(NumberOfPeers, "../scripts/thinkeys.txt")
// 	ip := "127.0.0.1"
//
// 	bootaddr := ip + ":" + strconv.Itoa(5088)
// 	bootnodes := make(map[string]common.NodeID)
// 	bootnodes[bootaddr] = *infos[0].Nid
//
// 	servers := []models.Server{}
//
// 	for i := 0; i < NumberOfPeers; i++ {
// 		p, _ := NewP2PServer(infos[i].Nid, bootnodes, 0, uint16(5088+10*i),
// 			nil, &cryp.PrivateKey{infos[i].PriKey}, 0, 0, nil)
// 		/*
// 			p.Eventer = &FakeEventer{
// 				Peer:        p,
// 				MessagePool: RecentMsgPool{},
// 			}
// 		*/
//
// 		if err := p.Start(); err != nil {
// 			fmt.Println(err)
// 		}
// 		servers = append(servers, p)
// 	}
//
// 	time.Sleep(5 * time.Second)
//
// 	// check broadcastfull
// 	msgshort := models.TextEMessage{
// 		Body: "the dark knight rises",
// 	}
// 	servers[5].Broadcast("", msgshort, nil, nil)
//
// 	// wait for broadcastfull check to finish
// 	time.Sleep(5 * time.Second)
//
// 	// check broadcastpart
// 	b := [MaxBytesCanBroadcast]byte{}
// 	for i := 0; i < MaxBytesCanBroadcast; i++ {
// 		b[i] = '-'
// 	}
// 	msglong := models.TextEMessage{
// 		Body: "the dark knight rises" + string(b[:]),
// 	}
// 	fmt.Println(servers[3].NodeID().String()[:6])
// 	servers[3].Broadcast("", msglong, nil, nil)
//
// 	// wait for broadcastpart to finish
// 	time.Sleep(5 * time.Second)
//
// 	// // check send
// 	// for i := 0; i < NumberOfPeers; i++ {
// 	// 	if _, ok := servers[3].Peers.Load(*servers[i].NodeID()); ok {
// 	// 		servers[3].Send(servers[i].NodeID(), msglong)
// 	// 	}
// 	// }
//
// 	select {}
//
// }

func TestP2PServer_Send(t *testing.T) {

}

func IntToBytes(n int) []byte {
	data := int64(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func TestChainToPeer(t *testing.T) {

	t.Error("changed the orignal message")
	var (
		peers        = make(map[common.NodeID]*Peer)
		taskdone     = make(chan task, maxActiveDialTasks)
		chaintopeers []*Peer
		inboundCount = 0
		addpeer      chan *Peer
		delpeer      chan *Peer
		Peers        sync.Map

		ChainToPeers sync.Map
	)

	go func() {
		var testnode discover.Node
		for i := 0; i < 1; i++ {

			buf := IntToBytes(i + 888888)

			peer := NewPeer(testnode, common.ChainID(i), nil, inboundConn, nil, nil, nil, nil)
			peer.ID = common.BytesToNodeID(buf)
			peer.TCP = uint16(1024 + i)
			t.Errorf("--------ID-- %v chainId %d", peer.ID, peer.chainId)
			addpeer <- peer
		}

	}()

	for {
		select {
		case <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.

		case p := <-addpeer:

			peers[p.ID] = p
			Peers.Store(p.ID, p)
			t.Errorf("ID %v chainId %d", p.ID, p.chainId)

			//加载map数据
			if loadchaintopeers, err := Peers.Load(p.chainId); err {
				chaintopeers = append(loadchaintopeers.([]*Peer), p)
				ChainToPeers.Store(p.chainId, chaintopeers)
				t.Errorf("ID- %v chainId %d", p.ID, p.chainId)
			} else {
				chaintopeers = append(chaintopeers, p)
				ChainToPeers.Store(p.chainId, chaintopeers)
				t.Errorf("ID-- %v chainId %d", p.ID, p.chainId)
			}

		case p := <-delpeer:
			// A peer disconnected.
			Peers.Delete(p.ID)
			delete(peers, p.ID)
			if p.is(inboundConn) {
				inboundCount--
			}
		}
	}

}

func TestChainToPeer1(t *testing.T) {

	var (
		peers        = make(map[common.NodeID]*Peer)
		chaintopeers []*Peer

		Peers sync.Map

		ChainToPeers sync.Map
	)

	var testnode discover.Node

	buf := IntToBytes(1)
	t.Errorf("-++++++++++++ID-- %v ", buf)

	peer := NewPeer(testnode, common.ChainID(1), nil, inboundConn, nil, nil, nil, nil)
	peer.ID = common.BytesToNodeID(buf)
	peer.TCP = uint16(1024 + 1)
	t.Errorf("--------ID-- %s chainId %d", peer.ID.Bytes(), peer.chainId)

	peers[peer.ID] = peer
	Peers.Store(peer.ID, peer)
	t.Errorf("ID %v chainId %d", peer.ID, peer.chainId)

	//加载map数据
	if loadchaintopeers, err := ChainToPeers.Load(peer.chainId); err {
		t.Errorf("加载map数据-TCP-- %d chainId %d", peer.TCP, peer.chainId)
		chaintopeers = append(loadchaintopeers.([]*Peer), peer)
		ChainToPeers.Store(peer.chainId, chaintopeers)
		t.Errorf("ID- %v chainId %d", peer.ID, peer.chainId)
	} else {
		chaintopeers = append(chaintopeers, peer)
		ChainToPeers.Store(peer.chainId, chaintopeers)
		t.Errorf("首次加载-TCP-- %d chainId %d", peer.TCP, peer.chainId)

	}

	//加载map数据
	if loadchaintopeers, err := ChainToPeers.Load(peer.chainId); err {

		peer1 := NewPeer(testnode, peer.chainId, nil, inboundConn, nil, nil, nil, nil)
		peer1.TCP = uint16(1024 + 2)
		peer1.chainId = common.ChainID(2)
		t.Errorf("加载map数据-TCP-- %d chainId %d,节点数量:%d", peer.TCP, peer.chainId, len(loadchaintopeers.([]*Peer)))
		chaintopeers = append(loadchaintopeers.([]*Peer), peer1)
		t.Errorf("节点数量- %d,chainId %d", len(chaintopeers), peer.chainId)
		ChainToPeers.Store(peer1.chainId, chaintopeers)
		t.Errorf("节点数量- %d chainId %d", len(loadchaintopeers.([]*Peer)), peer.chainId)
	} else {
		chaintopeers = append(chaintopeers, peer)
		ChainToPeers.Store(peer.chainId, chaintopeers)
		t.Errorf("首次加载- %v chainId %d", peer.ID, peer.chainId)
	}

	if loadchaintopeers1, err := ChainToPeers.Load(peer.chainId); err {
		t.Errorf("-------加载map数据-TCP-- %d chainId %d,节点数量:%d", peer.TCP, peer.chainId, len(loadchaintopeers1.([]*Peer)))
		for count, test := range loadchaintopeers1.([]*Peer) {
			t.Errorf("count=[%d],测试节点- %d chainId %d", count+1, test.TCP, test.chainId)
		}
	}

}
