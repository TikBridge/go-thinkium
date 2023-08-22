package models

import (
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

type AccountDeltaFromTrie struct {
	tries *trie.SmallCombinedTrie
	dbase db.Database
	lock  sync.RWMutex

	maxHeights map[common.ChainID]common.Height

	nodeAdapter  db.DataAdapter
	valueAdapter db.DataAdapter
	valueCodec   *rtl.StructCodec
}

func NewAccountDeltaFromTrie(dbase db.Database) *AccountDeltaFromTrie {
	combined := trie.NewCombinedTrie(db.NewKeyPrefixedDataAdapter(dbase, KPDeltaTrie))
	valueCodec, err := rtl.NewStructCodec(TypeOfAccountDeltaPtr)
	if err != nil {
		panic("create account delta trie code error: " + err.Error())
	}
	return &AccountDeltaFromTrie{
		tries:        combined,
		dbase:        dbase,
		maxHeights:   make(map[common.ChainID]common.Height),
		nodeAdapter:  db.NewKeyPrefixedDataAdapter(dbase, KPDeltaNodeNode),
		valueAdapter: db.NewKeyPrefixedDataAdapter(dbase, KPDeltaNodeValue),
		valueCodec:   valueCodec,
	}
}

func (d *AccountDeltaFromTrie) Put(shardId common.ChainID, height common.Height, t *trie.Trie) bool {
	d.lock.Lock()
	defer d.lock.Unlock()

	key := DeltaFromKey{ShardID: shardId, Height: height}
	keybytes := key.Bytes()
	return d.tries.Put(keybytes, t)
}

func (d *AccountDeltaFromTrie) getSubTrieByKey(tries *trie.SmallCombinedTrie, key DeltaFromKey, create bool) (subTrie *trie.Trie, ok bool) {
	keybytes := key.Bytes()
	subv, ok := tries.Get(keybytes)
	var sub *trie.Trie
	if !ok || subv == nil {
		if create {
			sub = trie.NewTrieWithValueCodec(nil, d.nodeAdapter, d.valueAdapter, d.valueCodec.Encode, d.valueCodec.Decode)
			tries.Put(keybytes, sub)
			return sub, true
		} else {
			return nil, false
		}
	} else {
		sub, ok = subv.(*trie.Trie)
		if !ok {
			panic("expecting a trie.ITrie")
		}
		return sub, true
	}
}

func (d *AccountDeltaFromTrie) getSubTrieByChainHeightKey(tries *trie.SmallCombinedTrie, fromId common.ChainID, height common.Height,
	create bool) (key DeltaFromKey, subTrie *trie.Trie, ok bool) {
	key = DeltaFromKey{ShardID: fromId, Height: height}
	subTrie, ok = d.getSubTrieByKey(tries, key, create)
	return
}

func (d *AccountDeltaFromTrie) FromDeltaFroms(deltaFroms DeltaFroms) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	subtries := trie.NewCombinedTrie(db.NewKeyPrefixedDataAdapter(d.dbase, KPDeltaTrie))

	for i := 0; i < len(deltaFroms); i++ {
		key := deltaFroms[i].Key
		deltas := deltaFroms[i].Deltas

		subTrie, ok := d.getSubTrieByKey(subtries, key, true)
		if !ok {
			panic("should not be here: getSubTrieByKey failed")
		}
		for j := 0; j < len(deltas); j++ {
			// log.Debugf("put %v: %v", key, deltas[j])
			subTrie.Put(deltas[j].Addr[:], deltas[j])
		}
	}
	d.tries = subtries
	return nil
}

func (d *AccountDeltaFromTrie) ToDeltaFroms() (DeltaFroms, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	it := d.tries.ValueIterator()
	deltaFroms := make(DeltaFroms, 0)

	for it.Next() {
		k, v := it.Current()
		if k == nil || v == nil {
			continue
		}
		deltaFromKey := BytesToDeltaFromKey(k)
		t, ok := v.(*trie.Trie)
		if !ok {
			panic("expecting a *trie.Trie")
		}
		deltas := make([]*AccountDelta, 0)
		deltaIt := t.ValueIterator()
		for deltaIt.Next() {
			dk, dv := deltaIt.Current()
			if dk == nil || dv == nil {
				continue
			}
			d, ok := dv.(*AccountDelta)
			if !ok {
				panic("expecting a *AccountDelta")
			}
			log.Debugf("get %v: %v", deltaFromKey, d)
			deltas = append(deltas, d)
		}
		ddeltas := make([]*AccountDelta, len(deltas))
		copy(ddeltas, deltas)
		deltaFroms = append(deltaFroms, DeltaFrom{Key: deltaFromKey, Deltas: ddeltas})
	}
	r := make(DeltaFroms, len(deltaFroms))
	copy(r, deltaFroms)
	return r, nil
}

func (d *AccountDeltaFromTrie) HashValue() (hashValue []byte, err error) {
	return d.tries.HashValue()
}
