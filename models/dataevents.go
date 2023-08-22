package models

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
)

type (
	// The shard chain is used to send to other shards the AccountDelta list processed by this
	// shard should fall on the other shard. Including block header and the proof
	ShardDeltaMessage struct {
		ToChainID       common.ChainID
		FromBlockHeader *BlockHeader
		Proof           []common.Hash
		Deltas          []*AccountDelta
	}

	DeltaRequestMessage struct {
		FromID common.ChainID // source chain of requested delta
		ToID   common.ChainID // target chain of requested delta
		Start  common.Height  // The starting height of the source chain where the requested delta is located
		Length int            // The number of delta requested, starting from start (including start)
	}

	ShardTransaction struct {
		ToChainID common.ChainID
		Tx        *Transaction
	}
)

func (m *ShardDeltaMessage) GetChainID() common.ChainID {
	return m.ToChainID
}

func (m *ShardDeltaMessage) DestChainID() common.ChainID {
	return m.ToChainID
}

func (m *ShardDeltaMessage) String() string {
	return fmt.Sprintf("{To:%d, From:%s, len(Deltas):%d}",
		m.ToChainID, m.FromBlockHeader.Summary(), len(m.Deltas))
}

func (m *DeltaRequestMessage) GetChainID() common.ChainID {
	return m.FromID
}

func (m *DeltaRequestMessage) DestChainID() common.ChainID {
	return m.FromID
}

func (m *DeltaRequestMessage) A() common.Height {
	return m.Start
}

func (m *DeltaRequestMessage) B() common.Height {
	return m.Start + common.Height(m.Length)
}

func (m *DeltaRequestMessage) String() string {
	if m == nil {
		return "DeltaReq<nil>"
	}
	return fmt.Sprintf("DeltaReq{From:%d To:%d Start:%d Length:%d}", m.FromID, m.ToID, m.Start, m.Length)
}

func (s *ShardTransaction) GetChainID() common.ChainID {
	return s.ToChainID
}

type LastBlockMessage struct {
	BlockHeight
}

func (m *LastBlockMessage) String() string {
	if m.Height.IsNil() {
		return fmt.Sprintf("LastBlock{ChainID:%d NONE}", m.ChainID)
	} else {
		return fmt.Sprintf("LastBlock{ChainID:%d Height:%d Epoch:%d Block:%d}",
			m.ChainID, m.Height, m.GetEpochNum(), m.GetBlockNum())
	}
}

type LastHeightMessage struct {
	BlockHeight
	BlockHash common.Hash
	Pas       *PubAndSig
}

func NewLastHeightMessage(chainId common.ChainID, height common.Height, hash common.Hash) *LastHeightMessage {
	msg := &LastHeightMessage{
		BlockHeight: BlockHeight{ChainID: chainId, Height: height},
		BlockHash:   hash,
	}
	hom := msg.MessageHash()
	pas, err := new(PubAndSig).Sign(hom)
	if err != nil {
		log.Errorf("sign HashOf(%s)=%x failed: %v", msg, common.ForPrint(hom, 0, -1), err)
		return msg
	}
	msg.Pas = pas
	return msg
}

func (h *LastHeightMessage) MessageHash() []byte {
	if h == nil {
		return nil
	}
	bhbytes := h.BlockHeight.Bytes()
	bs := make([]byte, len(bhbytes)+common.HashLength)
	copy(bs, bhbytes)
	copy(bs[len(bhbytes):], h.BlockHash[:])
	return common.Hash256NoError(bs)
}

func (h *LastHeightMessage) String() string {
	if h == nil {
		return "LastHeight<nil>"
	}
	return fmt.Sprintf("LastHeigth{ChainID:%d Height:%s BlockHash:%x %s}",
		h.ChainID, &(h.Height), h.BlockHash[:5], h.Pas)
}

type SyncRequest struct {
	ChainID     common.ChainID
	NodeID      common.NodeID // Nodeid to request synchronization
	ToNode      common.NodeID
	AllBlock    bool          // true: indicates synchronization from the first block, false: Indicates that synchronization starts from the current state
	StartHeight common.Height // the last height in local database
	EndHeight   common.Height
	StartHash   common.Hash // the block hash of StartHeight. if StartHeight==0, could be ZeroHash(no data in local) or the hash of the block with Height=0
	RpcAddr     string
	Timestamp   int64
	Pas         *PubAndSig
}

func (s *SyncRequest) Source() common.NodeID {
	return s.NodeID
}

func (s *SyncRequest) GetChainID() common.ChainID {
	return s.ChainID
}

func (s *SyncRequest) MessageHash() []byte {
	if s == nil {
		v, _ := common.EncodeAndHash(s)
		return v
	}
	m := &SyncRequest{
		ChainID:     s.ChainID,
		NodeID:      s.NodeID,
		ToNode:      s.ToNode,
		AllBlock:    s.AllBlock,
		StartHeight: s.StartHeight,
		StartHash:   s.StartHash,
		RpcAddr:     s.RpcAddr,
		Timestamp:   s.Timestamp,
		Pas:         nil,
	}
	v, _ := common.EncodeAndHash(m)
	return v
}

func (s *SyncRequest) Sign() error {
	if s == nil {
		return common.ErrNil
	}
	pas, err := new(PubAndSig).Sign(s.MessageHash())
	if err != nil {
		return err
	}
	s.Pas = pas
	return nil
}

func (s *SyncRequest) Validate() error {
	if s == nil {
		return nil
	}
	nid, err := s.Pas.VerifiedNodeID(s.MessageHash())
	if err != nil {
		return err
	}
	if nid != s.NodeID {
		return errors.New("sig and nodeId not match")
	}
	return nil
}

func (s *SyncRequest) String() string {
	return fmt.Sprintf("SyncRequest{ChainID:%d NodeID:%s To:%s AllBlock:%t StartHeight:%d StartHash:%x EndHeight:%d RpcAddr:%s Timestamp:%d %s}",
		s.ChainID, s.NodeID, s.ToNode, s.AllBlock, s.StartHeight, common.ForPrint(s.StartHash[:]), s.EndHeight, s.RpcAddr, s.Timestamp, s.Pas)
}

type SyncFinish struct {
	ChainID   common.ChainID
	NodeID    common.NodeID // Nodeid to request synchronization
	EndHeight common.Height
	Timestamp int64
	Pas       *PubAndSig
}

func (s *SyncFinish) Source() common.NodeID {
	return s.NodeID
}

func (s *SyncFinish) GetChainID() common.ChainID {
	return s.ChainID
}

func (s *SyncFinish) MessageHash() []byte {
	if s == nil {
		v, _ := common.EncodeAndHash(s)
		return v
	}
	m := &SyncFinish{
		ChainID:   s.ChainID,
		NodeID:    s.NodeID,
		EndHeight: s.EndHeight,
		Timestamp: s.Timestamp,
		Pas:       nil,
	}
	v, _ := common.EncodeAndHash(m)
	return v
}

func (s *SyncFinish) Sign() error {
	if s == nil {
		return common.ErrNil
	}
	pas, err := new(PubAndSig).Sign(s.MessageHash())
	if err != nil {
		return err
	}
	s.Pas = pas
	return nil
}

func (s *SyncFinish) String() string {
	return fmt.Sprintf("SyncFinish{ChainID:%d NodeID:%s EndHeight:%d T:%d %s}",
		s.ChainID, s.NodeID, s.EndHeight, s.Timestamp, s.Pas)
}

type SyncFailure struct {
	ChainID   common.ChainID
	NodeID    common.NodeID
	Height    common.Height
	Hash      common.Hash
	Timestamp int64
	Pas       *PubAndSig
}

func (s *SyncFailure) GetChainID() common.ChainID {
	return s.ChainID
}

func (s *SyncFailure) MessageHash() []byte {
	if s == nil {
		return nil
	}
	bs := make([]byte, 4+common.NodeIDBytes+8+common.HashLength+8)
	binary.BigEndian.PutUint32(bs, uint32(s.ChainID))
	copy(bs[4:], s.NodeID[:])
	binary.BigEndian.PutUint64(bs[4+common.NodeIDBytes:], uint64(s.Height))
	copy(bs[4+common.NodeIDBytes+8:], s.Hash[:])
	binary.BigEndian.PutUint64(bs[4+common.NodeIDBytes+8+common.HashLength:], uint64(s.Timestamp))
	return common.Hash256NoError(bs)
}

func (s *SyncFailure) Sign() error {
	if s == nil {
		return common.ErrNil
	}
	pas, err := new(PubAndSig).Sign(s.MessageHash())
	if err != nil {
		return err
	}
	s.Pas = pas
	return nil
}

func (s *SyncFailure) String() string {
	if s == nil {
		return "SyncFailure<nil>"
	}
	return fmt.Sprintf("SyncFailure{ChainID:%d NID:%s Height:%s Hash:%x T:%d %s}",
		s.ChainID, s.NodeID, &(s.Height), common.ForPrint(s.Hash[:]), s.Timestamp, s.Pas)
}

// Pack deltas generated by multiple blocks together. It is sent to the target chain at one time.
// Proof chain：root of the trie generated with deltas in block A (1)-> A.BalanceDeltaRoot (2)-> A.BlockHeader.Hash
// 			(3)-> current block B.HashHistory (4)-> B.BlockHeader.Hash
// 			(5)-> (block C in main chain which confirmed block B).HdsRoot (6)-> C.BlockHeader.Hash
type (
	// Proof.Proof(MerkleHash(Deltas)) == BlockHash of Height (1)(2)
	// HistoryProof.Proof(BlockHash of Height) == BlockHash of DeltasPack.ProofedHeight (3)(4)
	OneDeltas struct {
		// the height of the block A where delta generated
		Height common.Height
		// All deltas in a block corresponding to a shard to another shard
		Deltas []*AccountDelta
		// The proof of this group of delta to the hash of block A at Height (1)(2)
		Proof trie.ProofChain
		// The proof to HashHistory of block B (specified by DeltasPack) used in this transmission (3).
		// You can use this proof.Key() judge the authenticity of Height. When Height==DeltasPack.ProofedHeight,
		// this proof is nil. At this time, verify with ProofedHeight in DeltasPack.
		// 到本次传输统一使用的块B(由DeltasPack指定)的HashHistory的证明(3)。可以用此proof.Key()判
		// 断Height的真实性。当Height==DeltasPack.ProofedHeight时，此证明为nil。此时与DeltasPack
		// 中的ProofedHeight做验证。
		HistoryProof trie.ProofChain
		// Proof from the HashHistory of block B to the Hash of block B (4).
		// When Height==DeltasPack.ProofedHeight, this proof is nil.
		// At this time, verify with ProofedHeight in DeltasPack.
		// 从块B的HashHistory到块B的Hash的证明(4)。当Height==DeltasPack.ProofedHeight时，此证明为nil。
		// 此时与DeltasPack中的ProofedHeight做验证。
		ProofToB trie.ProofChain
	}

	DeltasGroup []*OneDeltas

	// ProofToMain.Proof(BlockHash of ProofedHeight) == BlockHash of MainHeight (5)(6)
	DeltasPack struct {
		FromID        common.ChainID  // source chain id
		ToChainID     common.ChainID  // target shard id
		ProofedHeight common.Height   // block B of source shard was confirmed by the main chain
		ProofToMain   trie.ProofChain // proof from B.Hash to C.Hash
		MainHeight    common.Height   // the height of main chain block C which packed and confirmed block B
		Pack          DeltasGroup     // deltas of each block from source chain
	}
)

func (o *OneDeltas) String() string {
	if o == nil {
		return "OD<nil>"
	}
	return fmt.Sprintf("OD{H:%d Dlts:%d}", o.Height, len(o.Deltas))
}

func (g DeltasGroup) Len() int {
	return len(g)
}

func (g DeltasGroup) Swap(i, j int) {
	g[i], g[j] = g[j], g[i]
}

func (g DeltasGroup) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(g, i, j); needCompare {
		return g[i].Height < g[j].Height
	} else {
		return less
	}
}

func (g DeltasGroup) Summary() string {
	le := len(g)
	if le == 0 {
		return "DG{}"
	} else if le == 1 {
		s := ""
		if g[0] != nil {
			s = g[0].Height.String()
		}
		return fmt.Sprintf("DG{%s}", s)
	} else {
		s, e := "", ""
		if g[0] != nil {
			s = g[0].Height.String()
		}
		if g[le-1] != nil {
			e = g[le-1].Height.String()
		}
		return fmt.Sprintf("OD{%s-%s}", s, e)
	}
}

func (d *DeltasPack) GetChainID() common.ChainID {
	return d.ToChainID
}

func (d *DeltasPack) DestChainID() common.ChainID {
	return d.ToChainID
}

func (d *DeltasPack) String() string {
	if d == nil {
		return "DeltasPack<nil>"
	}
	return fmt.Sprintf("DeltasPack{From:%d To:%d ProofHeight:%d MainHeight:%d Proof:%s Pack:%s}",
		d.FromID, d.ToChainID, d.ProofedHeight, d.MainHeight, d.ProofToMain, d.Pack)
}
