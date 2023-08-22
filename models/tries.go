package models

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

var TrieCreate TrieCreator = trieCreator{}

type TrieCreator interface {
	AccountTrie(dbase db.Database, root []byte) *trie.Trie
	ChainInfosOrigin(dbase db.Database, root []byte) *trie.Trie
	ChainTrie(dbase db.Database, root []byte) *ChainTrie
	RRTrie(dbase db.Database, root []byte) *trie.Trie
	RRCTrie(dbase db.Database, root []byte) *trie.Trie
	GenesisRRTrie(dbase db.Database, genesisNodes map[common.Hash]common.NodeType,
		minConsensusRR, minDataRR *big.Int) (*trie.Trie, error)
}

var (
	rrInfoCodec, _   = rtl.NewStructCodec(reflect.TypeOf((*RRInfo)(nil)))
	rrChangeCodec, _ = rtl.NewStructCodec(reflect.TypeOf((*RRC)(nil)))
)

type trieCreator struct{}

func (c trieCreator) AccountTrie(dbase db.Database, root []byte) *trie.Trie {
	na := db.NewKeyPrefixedDataAdapter(dbase, KPAccountNode)
	nv := db.NewKeyPrefixedDataAdapter(dbase, KPAccountValue)
	return trie.NewTrieWithValueType(root, na, nv, TypeOfAccountPtr)
}

func (c trieCreator) ChainInfosOrigin(dbase db.Database, root []byte) *trie.Trie {
	na := db.NewKeyPrefixedDataAdapter(dbase, KPChainNode)
	nv := db.NewKeyPrefixedDataAdapter(dbase, KPChainValue)
	return trie.NewTrieWithValueType(root, na, nv, common.TypeOfChainInfosPtr)
}

func (c trieCreator) ChainTrie(dbase db.Database, root []byte) *ChainTrie {
	tr := c.ChainInfosOrigin(dbase, root)
	return NewChainTrie(tr)
}

func (c trieCreator) RRTrie(dbase db.Database, root []byte) *trie.Trie {
	return trie.NewTrieWithValueCodec(root, db.NewKeyPrefixedDataAdapter(dbase, KPRRNode),
		db.NewKeyPrefixedDataAdapter(dbase, KPRRValue), rrInfoCodec.Encode, rrInfoCodec.Decode)
}

func (c trieCreator) RRCTrie(dbase db.Database, root []byte) *trie.Trie {
	return trie.NewTrieWithValueCodec(root, db.NewKeyPrefixedDataAdapter(dbase, KPRRCNode),
		db.NewKeyPrefixedDataAdapter(dbase, KPRRCValue), rrChangeCodec.Encode, rrChangeCodec.Decode)
}

func (c trieCreator) GenesisRRTrie(dbase db.Database, genesisNodes map[common.Hash]common.NodeType,
	minConsensusRR, minDataRR *big.Int) (*trie.Trie, error) {
	t := c.RRTrie(dbase, nil)
	if genesisNodes == nil || len(genesisNodes) == 0 {
		return t, nil
	}
	consNodeCount := uint32(0)
	rrs := make([]*RRInfo, 0, len(genesisNodes))
	for nidh, nt := range genesisNodes {
		if nt != common.Consensus && nt != common.Data {
			continue
		}

		rr, err := CreateGenesisRRInfo(nidh, nt, minConsensusRR, minDataRR)
		if err != nil {
			return nil, err
		}

		rrs = append(rrs, rr)
		if nt == common.Consensus {
			consNodeCount++
		}
	}
	sum := big.NewInt(0)
	for _, rr := range rrs {
		if rr.Type == common.Consensus {
			sum.Add(sum, rr.Amount)
		}
	}
	for _, rr := range rrs {
		if rr.Type == common.Consensus {
			rr.Ratio = new(big.Rat).SetFrac(rr.Amount, sum)
			rr.NodeCount = consNodeCount
		}
		t.PutValue(rr)
	}
	if err := t.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

func TrieRootHashEqual(h *common.Hash, root []byte) bool {
	return TrieRootEqual(h.Slice(), root)
	// if h == nil {
	// 	if trie.IsEmptyTrieRoot(root) {
	// 		return true
	// 	} else {
	// 		return false
	// 	}
	// } else {
	// 	return h.SliceEqual(root)
	// }
}

func TrieRootEqual(a, b []byte) bool {
	an := trie.IsEmptyTrieRoot(a)
	bn := trie.IsEmptyTrieRoot(b)
	if an && bn {
		return true
	}
	if an || bn {
		return false
	}
	return bytes.Equal(a, b)
}

// two blocks (A and B) in one chain, A.Height < B.Height
// 1. Hash(A) -> B.HashHistory
// 2. B.HashHistory -> Hash(B)
type BlockHistoryProof trie.ProofChain

func (p BlockHistoryProof) Proof(heightOfA common.Height, hashOfA []byte) (hashOfB []byte, err error) {
	if len(p) == 0 {
		return nil, common.ErrNil
	}
	last := len(p) - 1
	historyProof := trie.ProofChain(p[:last])
	hisRoot, err := historyProof.HistoryProof(heightOfA, hashOfA)
	if err != nil {
		return nil, fmt.Errorf("proof(Height:%d Hob:%x) failed: %v",
			heightOfA, common.ForPrint(hashOfA), err)
	}
	return p[last].Proof(common.BytesToHash(hisRoot))
}
