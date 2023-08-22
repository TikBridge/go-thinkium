package models

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

type ntAndGen struct {
	chainid common.ChainID
	isGen   bool
	nt      common.NodeType
}

func (ng ntAndGen) String() string {
	if ng.isGen {
		return fmt.Sprintf("IsGen+%s@ChainID:%d", ng.nt, ng.chainid)
	} else {
		return fmt.Sprintf("NotGen+%s@ChainID:%d", ng.nt, ng.chainid)
	}
}

type ChainTrie struct {
	trie          *trie.RevertableTrie
	shardCache    map[common.ChainID]common.ShardInfo           // cache of ShardInfo
	indexCache    map[common.ChainID]common.ChainIDs            // cache of Parent.ChainID -> Children.ChainIDs
	reportCache   map[common.ChainID]common.ChainIDs            // cache of chain.ReportTo() -> []chain.IDs
	allId         common.ChainIDs                               // all chain ids deduplicated and orderred
	allVrfId      common.ChainIDs                               // all chains that need VRF election
	dataCache     map[common.ChainID]map[common.NodeID]struct{} // cache of ChainID -> DataNode.NodeID -> {}
	dataToChain   map[common.NodeID]common.ChainID              // cache of datanode to chainid，DataNode.NodeID -> ChainID
	rewardChainId *common.ChainID                               // cache of chain id of reward chain
	nodeTypes     map[common.NodeID]ntAndGen                    // all node types
	lock          sync.Mutex
}

func (c *ChainTrie) Rebase(dbase db.Database) (*ChainTrie, error) {
	if c == nil {
		return nil, nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	tr, err := c.trie.Rebase(dbase)
	if err != nil {
		return nil, err
	}
	return &ChainTrie{
		trie:       tr,
		shardCache: make(map[common.ChainID]common.ShardInfo),
	}, nil
}

func (c *ChainTrie) Copy() *ChainTrie {
	if c == nil {
		return nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	ret := new(ChainTrie)
	if c.trie != nil {
		ret.trie = c.trie.Copy()
	}
	ret.shardCache = make(map[common.ChainID]common.ShardInfo)
	// ret.dataCache = make(map[common.ChainID]map[common.NodeID]struct{})
	// ret.dataToChain = make(map[common.NodeID]common.ChainID)
	return ret
}

func NewChainTrie(origin *trie.Trie) *ChainTrie {
	return &ChainTrie{
		trie:       &trie.RevertableTrie{Origin: origin, Live: nil},
		shardCache: make(map[common.ChainID]common.ShardInfo),
		// dataCache:   make(map[common.ChainID]map[common.NodeID]struct{}),
		// dataToChain: make(map[common.NodeID]common.ChainID),
	}
}

func SetupChains(chains *ChainTrie, chaininfosMap map[common.ChainID]*common.ChainInfos) {
	for _, infos := range chaininfosMap {
		if infos == nil {
			continue
		}
		if err := chains.PutInfo(infos); err != nil {
			log.Errorf("SetupChains %s failed: %v", infos, err)
		} else {
			log.Infof("SetupChains: %s", infos)
		}
	}
	if err := chains.Commit(); err != nil {
		log.Errorf("chains putvalue Error: %v", err)
	}
}

func GenesisChainTrie(dbase db.Database, conf *config.Config, useConfigGenesis bool) *ChainTrie {
	infos := conf.GenerateChainInfos()
	var chainInfoRoot []byte
	if useConfigGenesis && conf.GenesisRoot.Include(common.MainChainID) &&
		conf.GenesisRoot.GetChainInfoRootHash() != nil {
		chainInfoRoot = conf.GenesisRoot.GetChainInfoRootHash().Bytes()
	}
	infoTrie := TrieCreate.ChainTrie(dbase, chainInfoRoot)
	if len(chainInfoRoot) > 0 {
		return infoTrie
	}
	for _, info := range infos {
		if info == nil {
			continue
		}
		if err := infoTrie.PutInfo(info); err != nil {
			panic(fmt.Errorf("genesisChainTrie %s failed: %v", info, err))
		}
	}
	return infoTrie
}

func (c *ChainTrie) clearCacheLocked() {
	if len(c.shardCache) > 0 {
		c.shardCache = make(map[common.ChainID]common.ShardInfo)
	}
	c.indexCache = nil
	c.reportCache = nil
	c.allId = nil
	c.allVrfId = nil
	c.dataCache = nil
	c.dataToChain = nil
	// if len(c.dataCache) > 0 {
	// 	c.dataCache = make(map[common.ChainID]map[common.NodeID]struct{})
	// }
	// if len(c.dataToChain) > 0 {
	// 	c.dataToChain = make(map[common.NodeID]common.ChainID)
	// }
	c.rewardChainId = nil
	c.nodeTypes = nil
}

func (c *ChainTrie) SetTo(newTrie *trie.Trie) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clearCacheLocked()
	return c.trie.SetTo(newTrie)
}

func (c *ChainTrie) HashValue() ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.trie.HashValue()
}

func _putChainId(m map[common.ChainID]map[common.ChainID]struct{}, pid, child common.ChainID) {
	mm, _ := m[pid]
	if mm == nil {
		mm = make(map[common.ChainID]struct{})
		m[pid] = mm
	}
	mm[child] = struct{}{}
}

func _chainIDMapToList(m map[common.ChainID]map[common.ChainID]struct{}) map[common.ChainID]common.ChainIDs {
	if m == nil {
		return nil
	}
	r := make(map[common.ChainID]common.ChainIDs, len(m))
	for pid, childrenmap := range m {
		childrens := make(common.ChainIDs, 0, len(childrenmap))
		for child, _ := range childrenmap {
			childrens = append(childrens, child)
		}
		if len(childrens) > 1 {
			sort.Sort(childrens)
		}
		r[pid] = childrens
	}
	return r
}

func _putDataNode(m1 map[common.ChainID]map[common.NodeID]struct{}, m2 map[common.NodeID]common.ChainID,
	chainId common.ChainID, dataNids common.NodeIDs) {
	m11, exist := m1[chainId]
	if !exist || m11 == nil {
		m11 = make(map[common.NodeID]struct{})
		m1[chainId] = m11
	}
	for _, nid := range dataNids {
		m11[nid] = struct{}{}
		m2[nid] = chainId
	}
}

func _copyChainDataMaps(m map[common.ChainID]map[common.NodeID]struct{}) map[common.ChainID]map[common.NodeID]struct{} {
	if m == nil {
		return nil
	}
	r := make(map[common.ChainID]map[common.NodeID]struct{}, len(m))
	for cid, mm := range m {
		r[cid] = _copyChainDataMap(mm)
	}
	return r
}

func _copyChainDataMap(m map[common.NodeID]struct{}) map[common.NodeID]struct{} {
	if m == nil {
		return nil
	}
	r := make(map[common.NodeID]struct{}, len(m))
	for nid, _ := range m {
		r[nid] = struct{}{}
	}
	return r
}

func _putNodeType(ntmap map[common.NodeID]ntAndGen, nodeids common.NodeIDs, isGen bool,
	chainid common.ChainID, nt common.NodeType) {
	for _, nid := range nodeids {
		if ng, exist := ntmap[nid]; exist {
			if ng.nt != nt {
				panic(fmt.Errorf("node %x found %s and %s@ChainID:%d both", nid[:], ng, nt, chainid))
			} else {
				if ng.nt != common.Consensus && ng.chainid != chainid {
					panic(fmt.Errorf("%s node %x cannot work for different chain: %d <> %d",
						nt, nid[:], ng.chainid, chainid))
				}
			}
		} else {
			ntmap[nid] = ntAndGen{
				chainid: chainid,
				isGen:   isGen,
				nt:      nt,
			}
		}
	}
}

func (c *ChainTrie) loadIndexMapLocked() {
	// c.indexCache = make(map[common.ChainID]common.ChainIDs)
	// c.reportCache = make(map[common.ChainID]common.ChainIDs)
	c.allId = nil
	c.allVrfId = nil
	c.dataCache = make(map[common.ChainID]map[common.NodeID]struct{})
	c.dataToChain = make(map[common.NodeID]common.ChainID)
	c.nodeTypes = make(map[common.NodeID]ntAndGen)
	if c.trie == nil {
		return
	}
	idmap := make(map[common.ChainID]struct{})
	vrfmap := make(map[common.ChainID]struct{})

	indexTemp := make(map[common.ChainID]map[common.ChainID]struct{})
	reportTemp := make(map[common.ChainID]map[common.ChainID]struct{})

	it := c.trie.ValueIterator()
	for it.Next() {
		_, v := it.Current()
		info, ok := v.(*common.ChainInfos)
		if info == nil || !ok {
			continue
		}
		if info != nil {
			// record all ChainID
			if !info.ID.IsNil() {
				idmap[info.ID] = struct{}{}
			}
			if !info.ParentID.IsNil() {
				idmap[info.ParentID] = struct{}{}
			}
			if info.Election == common.ETNone || info.Election == common.ETVrf {
				vrfmap[info.ID] = struct{}{}
			}
		}
		if info.ID.IsNil() {
			continue
		}
		reportTo := info.ReportTo()
		if !reportTo.IsNil() {
			_putChainId(reportTemp, reportTo, info.ID)
		}
		pid := info.ParentID
		if !pid.IsNil() {
			_putChainId(indexTemp, pid, info.ID)
		}
		_putDataNode(c.dataCache, c.dataToChain, info.ID, info.GenesisDatas)
		_putDataNode(c.dataCache, c.dataToChain, info.ID, info.Datas)

		_putNodeType(c.nodeTypes, info.GenesisCommIds, true, info.ID, common.Consensus)
		_putNodeType(c.nodeTypes, info.GenesisDatas, true, info.ID, common.Data)
		_putNodeType(c.nodeTypes, info.Datas, false, info.ID, common.Data)
	}
	c.indexCache = _chainIDMapToList(indexTemp)
	c.reportCache = _chainIDMapToList(reportTemp)

	c.allId = make(common.ChainIDs, 0, len(idmap))
	for id, _ := range idmap {
		c.allId = append(c.allId, id)
	}
	sort.Sort(c.allId)
	c.allVrfId = make(common.ChainIDs, 0, len(vrfmap))
	for id, _ := range vrfmap {
		c.allVrfId = append(c.allVrfId, id)
	}
	sort.Sort(c.allVrfId)
}

func (c *ChainTrie) getChainChildrenLocked(id common.ChainID) common.ChainIDs {
	chainmap := c.getChainMapsLocked()
	if len(chainmap) == 0 {
		return nil
	}
	chainids, _ := chainmap[id]
	return chainids
}

func (c *ChainTrie) GetChainChildren(id common.ChainID) common.ChainIDs {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.getChainChildrenLocked(id)
}

func (c *ChainTrie) getReportChildrenLocked(id common.ChainID) common.ChainIDs {
	reportMap := c.getReportMapsLocked()
	if len(reportMap) == 0 {
		return nil
	}
	ids, _ := reportMap[id]
	return ids
}

func (c *ChainTrie) GetReportChildren(id common.ChainID) common.ChainIDs {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.getReportChildrenLocked(id)
}

func (c *ChainTrie) GetChainList() common.ChainIDs {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.allId == nil {
		c.loadIndexMapLocked()
	}
	return c.allId
}

func (c *ChainTrie) GetVrfChainList() common.ChainIDs {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.allVrfId == nil {
		c.loadIndexMapLocked()
	}
	return c.allVrfId
}

func (c *ChainTrie) getChainMapsLocked() map[common.ChainID]common.ChainIDs {
	if c.indexCache == nil {
		c.loadIndexMapLocked()
	}
	return c.indexCache
}

//
// func (c *ChainTrie) GetChainMaps() map[common.ChainID]common.ChainIDs {
// 	c.lock.Lock()
// 	defer c.lock.Unlock()
// 	return c.getChainMapsLocked()
// }

func (c *ChainTrie) getReportMapsLocked() map[common.ChainID]common.ChainIDs {
	if c.indexCache == nil {
		c.loadIndexMapLocked()
	}
	return c.reportCache
}

func (c *ChainTrie) getChainInfosLocked(id common.ChainID) (*common.ChainInfos, bool) {
	if c.trie == nil {
		return nil, false
	}
	key := id.Formalize()
	v, ok := c.trie.Get(key)
	if !ok || v == nil {
		return nil, false
	}
	infos, ok := v.(*common.ChainInfos)
	if !ok {
		return nil, false
	}
	return infos.Clone(), true
}

func (c *ChainTrie) GetChainInfos(id common.ChainID) (*common.ChainInfos, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.getChainInfosLocked(id)
}

func (c *ChainTrie) GetShardInfo(id common.ChainID) (shardInfo common.ShardInfo) {
	if id.IsNil() {
		return nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	info, exist := c.shardCache[id]
	if exist {
		return info
	}
	defer func() {
		if shardInfo != nil {
			c.shardCache[id] = shardInfo
		}
	}()
	chaininfo, ok := c.getChainInfosLocked(id)
	if !ok {
		return nil
	}
	switch chaininfo.Mode {
	case common.Root:
		return nil
	case common.Branch:
		childrenids := c.getChainChildrenLocked(id)
		if len(childrenids) > 0 {
			return common.NewShardInfo(chaininfo.ChainStruct, chaininfo.ID, childrenids)
		} else {
			return nil
		}
	case common.Shard:
		parent, ok := c.getChainInfosLocked(chaininfo.ParentID)
		if ok && parent != nil {
			childrenids := c.getChainChildrenLocked(chaininfo.ParentID)
			return common.NewShardInfo(parent.ChainStruct, chaininfo.ID, childrenids)
		}
	}
	return nil
}

func (c *ChainTrie) rangeAllInfosLocked(oneInfosCallback func(oneInfos *common.ChainInfos)) {
	if c.trie == nil {
		return
	}

	it := c.trie.ValueIterator()
	for it.Next() {
		_, v := it.Current()
		info, ok := v.(*common.ChainInfos)
		if !ok || info == nil {
			continue
		}
		oneInfosCallback(info.Clone())
	}
}

func (c *ChainTrie) RangeAllInfos(oneInfosCallback func(oneInfos *common.ChainInfos)) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.rangeAllInfosLocked(oneInfosCallback)
}

func (c *ChainTrie) GetAllChainInfos() []*common.ChainInfos {
	infos := make([]*common.ChainInfos, 0)
	c.RangeAllInfos(func(oneInfos *common.ChainInfos) {
		infos = append(infos, oneInfos)
	})
	return infos
}

func (c *ChainTrie) GetDataNodeList(id common.ChainID) common.NodeIDs {
	info, ok := c.GetChainInfos(id)
	if !ok || info == nil {
		return nil
	} else {
		return info.Datas
	}
}

func (c *ChainTrie) GetDataNodes(id common.ChainID) (datas map[common.NodeID]struct{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.dataCache == nil {
		c.loadIndexMapLocked()
	}

	m, _ := c.dataCache[id]
	return _copyChainDataMap(m)

	// defer func() {
	// 	if datas != nil {
	// 		c.dataCache[id] = datas
	// 	}
	// }()
	// info, ok := c.getChainInfosLocked(id)
	// if !ok || info == nil {
	// 	return nil
	// } else {
	// 	datas = info.Datas.ToMap()
	// 	return datas
	// }
}

func (c *ChainTrie) GetGenesisDataNodeList(id common.ChainID) common.NodeIDs {
	info, ok := c.GetChainInfos(id)
	if !ok || info == nil {
		return nil
	} else {
		return info.GenesisDatas
	}
}

func (c *ChainTrie) GetDataNodeMap() map[common.ChainID]map[common.NodeID]struct{} {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.dataCache == nil {
		c.loadIndexMapLocked()
	}
	return _copyChainDataMaps(c.dataCache)
}

func (c *ChainTrie) PutInfo(info *common.ChainInfos) error {
	if info == nil {
		return common.ErrNil
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.dataToChain == nil {
		c.loadIndexMapLocked()
	}

	for _, nid := range info.GenesisDatas {
		cid, exist := c.dataToChain[nid]
		if exist {
			if cid == info.ID {
				// it's ok if it's current chain, this happens when the same info is put in repeatedly
				continue
			}
			return fmt.Errorf("genesis data node (%s) already used in ChainID:%d", nid, cid)
		}
	}

	for _, nid := range info.Datas {
		cid, exist := c.dataToChain[nid]
		if exist {
			if cid == info.ID {
				continue
			}
			return fmt.Errorf("data node (%s) already used in ChainID:%d", nid, cid)
		}
	}

	c.clearCacheLocked()
	c.trie.PutValue(info)
	return nil
}

func (c *ChainTrie) DeleteInfo(id common.ChainID) (changed bool, oldInfo *common.ChainInfos, err error) {
	if id.IsNil() || id == common.MainChainID {
		return false, nil, errors.New("nil chain or 0 chain could not be deleted")
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clearCacheLocked()
	changed, old := c.trie.Delete(id.Formalize())
	if changed && old != nil {
		oldInfo, _ = old.(*common.ChainInfos)
	}
	return changed, oldInfo, nil
}

// Whether the node is the data node in use. If yes, the chain ID and true are returned;
// otherwise, chainid is meaningless and false returned
func (c *ChainTrie) IsInUsingDataNode(nid common.NodeID) (common.ChainID, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.dataToChain == nil {
		c.loadIndexMapLocked()
	}

	cid, exist := c.dataToChain[nid]
	return cid, exist
}

func (c *ChainTrie) PreCommit() ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.trie.PreCommit()
}

func (c *ChainTrie) Commit() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clearCacheLocked()
	if c.trie != nil {
		return c.trie.Commit()
	}
	return nil
}

// According to ChainTrie data, all genesis consensus nodes and genesisi data nodes are obtained
// to generate the genesis required reserve tree
func (c *ChainTrie) GenesisNodes() map[common.NodeID]common.NodeType {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.nodeTypes == nil {
		c.loadIndexMapLocked()
	}
	m := make(map[common.NodeID]common.NodeType)
	for nid, ng := range c.nodeTypes {
		if ng.isGen {
			m[nid] = ng.nt
		}
	}
	// if c.trie != nil {
	// 	it := c.trie.ValueIterator()
	// 	for it.Next() {
	// 		_, v := it.Current()
	// 		if v == nil {
	// 			continue
	// 		}
	// 		info, _ := v.(*common.ChainInfos)
	// 		if info == nil {
	// 			continue
	// 		}
	// 		if len(info.GenesisCommIds) > 0 {
	// 			for _, nid := range info.GenesisCommIds {
	// 				if nt, exist := m[nid]; exist {
	// 					if nt != common.Consensus {
	// 						panic(fmt.Sprintf("duplicate genesis node %s found with %x and %s", nid[:], nt, common.Consensus))
	// 					}
	// 				}
	// 				m[nid] = common.Consensus
	// 			}
	// 		}
	// 		if len(info.GenesisDatas) > 0 {
	// 			for _, nid := range info.GenesisDatas {
	// 				if _, exist := m[nid]; exist {
	// 					panic(fmt.Sprintf("duplicate genesis data node %s found", nid[:]))
	// 				}
	// 				m[nid] = common.Data
	// 			}
	// 		}
	// 	}
	// }
	return m
}

func (c *ChainTrie) GetNodeType(nid common.NodeID) (isGen bool, nt common.NodeType, chainid common.ChainID, exist bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.nodeTypes == nil {
		c.loadIndexMapLocked()
	}
	ng, ok := c.nodeTypes[nid]
	if !ok {
		exist = false
		return
	}
	return ng.isGen, ng.nt, ng.chainid, true
}

func (c *ChainTrie) GetRewardChainID() common.ChainID {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.rewardChainId != nil {
		return *c.rewardChainId
	}
	if c.trie == nil {
		return common.NilChainID
	}
	it := c.trie.ValueIterator()
	for it.Next() {
		_, v := it.Current()
		info, ok := v.(*common.ChainInfos)
		if !ok || info == nil {
			continue
		}
		if info.IsRewardChain() {
			id := info.ID
			c.rewardChainId = &id
			return info.ID
		}
	}
	return common.NilChainID
}

func (c *ChainTrie) Rollback() {
	if c == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.trie.Rollback()
}

func (c *ChainTrie) GetLiveChainInfos(id common.ChainID) (*common.ChainInfos, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.trie == nil {
		return nil, false
	}
	key := id.Formalize()
	v, ok := c.trie.GetLive(key)
	if !ok || v == nil {
		return nil, false
	}
	infos, ok := v.(*common.ChainInfos)
	if !ok {
		return nil, false
	}
	return infos.Clone(), true
}

func (c *ChainTrie) CheckPoint() (checkpoint int, root []byte, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.trie == nil {
		return -2, nil, common.ErrNil
	}
	return c.trie.CheckPoint()
}

func (c *ChainTrie) RevertTo(checkpoint int, root []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.trie == nil {
		return common.ErrNil
	}
	return c.trie.RevertTo(checkpoint, root)
}

func (c *ChainTrie) String() string {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c == nil {
		return "ChainTrie<nil>"
	}
	root, err := c.trie.Origin.HashValue()
	if err != nil {
		root = nil
	}
	return fmt.Sprintf("ChainTrie{root:%x %s}", common.ForPrint(root, 0, -1), c.trie.Origin.PrintValues())
}

// Whether the chain does not need pay gas feed. If true, the second value returns the chain
// ID with the AttrNoGas attribute
func (c *ChainTrie) IsNoGas(chainId common.ChainID) (bool, common.ChainID) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for !chainId.IsNil() {
		info, ok := c.getChainInfosLocked(chainId)
		if !ok || info == nil {
			return false, common.NilChainID
		}
		if info.HasAttribute(common.AttrNoGas) {
			return true, chainId
		}
		chainId = info.ParentID
	}
	return false, common.NilChainID
}
