package cmd

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type cursorto struct {
	DynamicCmd
}

func (c *cursorto) Match(line string) error {
	tostr := []byte(line)[len(c.DynamicCmd):]
	_, err := strconv.Atoi(string(tostr))
	if err != nil {
		return fmt.Errorf("usage: %s[newheight]", string(c.DynamicCmd))
	}
	return nil
}

func (c *cursorto) Run(line string, ctx RunContext) error {
	tostr := []byte(line)[len(c.DynamicCmd):]
	toint, err := strconv.Atoi(string(tostr))
	if err != nil {
		return fmt.Errorf("usage: %s[newheight]", c.DynamicCmd)
	}
	to := common.Height(toint)
	if err = ctx.DataManager().SetCursorManually(to); err != nil {
		return fmt.Errorf("set cursor error: %v", err)
	}
	log.Warnf("set cursor manually to %d", to)
	return nil
}

func parseLists(cmd string, line string) (chainid, height int, err error) {
	tostr := []byte(line)[len(cmd):]
	if len(tostr) == 0 {
		return 0, 0, fmt.Errorf("need: %s[chain-height]", cmd)
	}
	toints := strings.Split(string(tostr), "-")
	if len(toints) != 2 {
		return 0, 0, fmt.Errorf("need: %s[chain-height]", cmd)
	}
	tochain, err := strconv.Atoi(toints[0])
	if err != nil {
		return 0, 0, fmt.Errorf("chainid parse error: %v", err)
	}
	toheight, err := strconv.Atoi(toints[1])
	if err != nil {
		return 0, 0, fmt.Errorf("height parse error: %v", err)
	}
	return tochain, toheight, nil
}

type listtxs struct {
	DynamicCmd
}

func (l *listtxs) Match(line string) error {
	if _, _, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	}
	return nil
}

func (l *listtxs) Run(line string, ctx RunContext) error {
	if tochain, toheight, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	} else {
		chain := common.ChainID(tochain)
		to := common.Height(toheight)
		dh, err := ctx.DataManager().GetChainData(chain)
		if err != nil || dh == nil {
			return fmt.Errorf("get chain data %d error %v", chain, err)
		} else {
			block, err := dh.GetBlock(to)
			if err != nil || block == nil {
				return fmt.Errorf("get chain %d block %d error %v", chain, to, err)
			} else {
				txs := block.BlockBody.Txs
				log.Info("++++++++++++++++++++TX LIST++++++++++++++++++++++")
				for _, tx := range txs {
					log.Infof("%s", tx.FullString())
				}
				log.Info("++++++++++++++++++++TX LIST++++++++++++++++++++++")
			}
		}
	}
	return nil
}

type listacs struct {
	DynamicCmd
}

func (l *listacs) Match(line string) error {
	if _, _, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	}
	return nil
}

func (l *listacs) Run(line string, ctx RunContext) error {
	if tochain, toheight, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	} else {
		chain := common.ChainID(tochain)
		to := common.Height(toheight)
		dh, err := ctx.DataManager().GetChainData(chain)
		if err != nil || dh == nil {
			return fmt.Errorf("get chain data %d error %v", chain, err)
		} else {
			block, err := dh.GetBlock(to)
			if err != nil || block == nil {
				return fmt.Errorf("get chain %d block %d error %v", chain, to, err)
			}
			trie := dh.CreateAccountTrie(block.BlockHeader.StateRoot.Bytes())
			sum := big.NewInt(0)
			count := 0
			trie.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
				r, ok := value.(*models.Account)
				if ok {
					log.Infof("[ACC] %v", r)
					count++
					if r.Balance != nil && r.Balance.Sign() > 0 {
						sum.Add(sum, r.Balance)
					}
				} else {
					log.Warnf("[ACC] not an Account for %x", key)
				}
				return true
			})
			log.Infof("[ACC] listacs: count:%d sumOfBalance:%s", count, sum)
		}
	}
	return nil
}

type listrrs struct {
	DynamicCmd
}

func (l *listrrs) Match(line string) error {
	if _, _, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	}
	return nil
}

func (l *listrrs) Run(line string, ctx RunContext) error {
	if tochain, toheight, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	} else {
		chain := common.ChainID(tochain)
		to := common.Height(toheight)
		dh, err := ctx.DataManager().GetChainData(chain)
		if err != nil || dh == nil {
			return fmt.Errorf("get chain data %d error %v", chain, err)
		} else {
			block, err := dh.GetBlock(to)
			if err != nil || block == nil {
				return fmt.Errorf("get chain %d block %d error %v", chain, to, err)
			}
			var root []byte
			if block.BlockHeader != nil && block.BlockHeader.RRRoot != nil {
				root = block.BlockHeader.RRRoot[:]
			}
			tr := dh.CreateRRTrie(root)
			count := 0
			tr.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
				r, ok := value.(*models.RRInfo)
				if ok {
					log.Infof("[RRINFO] %s", r)
					count++
				} else {
					log.Warnf("[RRINFO] not a RRInfo found at %x", key)
				}
				return true
			})
			log.Infof("[RRINFO] listrrs: count:%d", count)
		}
	}
	return nil
}

type listvccs struct {
	DynamicCmd
}

func (l *listvccs) Match(line string) error {
	if _, _, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	}
	return nil
}

func (l *listvccs) Run(line string, ctx RunContext) error {
	if tochain, toheight, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	} else {
		chain := common.ChainID(tochain)
		to := common.Height(toheight)
		dh, err := ctx.DataManager().GetChainData(chain)
		if err != nil || dh == nil {
			return fmt.Errorf("get chain data %d error %v", chain, err)
		} else {
			block, err := dh.GetBlock(to)
			if err != nil || block == nil {
				return fmt.Errorf("get chain %d block %d error %v", chain, to, err)
			}
			var root []byte
			if block.BlockHeader != nil && block.BlockHeader.VCCRoot != nil {
				root = block.BlockHeader.VCCRoot[:]
			}
			tr := dh.CreateVCCTrie(root)
			count := 0
			tr.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
				log.Infof("[VCC] %x", key)
				count++
				return true
			})
			log.Infof("[VCC] listvccs: count:%d", count)
		}
	}
	return nil
}

type listcccs struct {
	DynamicCmd
}

func (l *listcccs) Match(line string) error {
	if _, _, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	}
	return nil
}

func (l *listcccs) Run(line string, ctx RunContext) error {
	if tochain, toheight, err := parseLists(string(l.DynamicCmd), line); err != nil {
		return err
	} else {
		chain := common.ChainID(tochain)
		to := common.Height(toheight)
		dh, err := ctx.DataManager().GetChainData(chain)
		if err != nil || dh == nil {
			return fmt.Errorf("get chain data %d error %v", chain, err)
		} else {
			block, err := dh.GetBlock(to)
			if err != nil || block == nil {
				return fmt.Errorf("get chain %d block %d error %v", chain, to, err)
			}
			var root []byte
			if block.BlockHeader != nil && block.BlockHeader.CashedRoot != nil {
				root = block.BlockHeader.CashedRoot[:]
			}
			tr := dh.CreateCCCTrie(root)
			count := 0
			tr.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
				log.Infof("[CCC] %x", key)
				count++
				return true
			})
			log.Infof("[CCC] listcccs: count:%d", count)
		}
	}
	return nil
}

type sendSyncFinish struct {
	DynamicCmd
}

func (s *sendSyncFinish) parse(line string) (common.ChainID, common.NodeID, error) {
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return common.NilChainID, common.NodeID{}, fmt.Errorf("%s <ChainID> <NodeID>", s.DynamicCmd)
	}
	if parts[0] != string(s.DynamicCmd) {
		return common.NilChainID, common.NodeID{}, fmt.Errorf("%s <ChainID> <NodeID>", s.DynamicCmd)
	}
	cid, err := strconv.Atoi(parts[1])
	if err != nil {
		return common.NilChainID, common.NodeID{}, fmt.Errorf("%s <ChainID> <NodeID>", s.DynamicCmd)
	}
	bs, err := hexutil.Decode(parts[2])
	if err != nil {
		return common.NilChainID, common.NodeID{}, fmt.Errorf("%s <ChainID> <NodeID>", s.DynamicCmd)
	}
	if len(bs) != common.NodeIDBytes {
		return common.NilChainID, common.NodeID{}, fmt.Errorf("%s <ChainID> <NodeID>", s.DynamicCmd)
	}
	return common.ChainID(cid), common.BytesToNodeID(bs), nil
}

func (s *sendSyncFinish) Match(line string) error {
	if _, _, err := s.parse(line); err != nil {
		return err
	}
	return nil
}

func (s *sendSyncFinish) Run(line string, ctx RunContext) error {
	if cid, nid, err := s.parse(line); err != nil {
		return err
	} else {
		dh, err := ctx.DataManager().GetChainData(cid)
		if err != nil || dh == nil {
			return fmt.Errorf("get chain data %d error %v", cid, err)
		} else {
			currentHeight := dh.GetCurrentHeight()
			finish := &models.SyncFinish{
				ChainID:   cid,
				NodeID:    nid,
				EndHeight: currentHeight,
				Timestamp: time.Now().UnixNano(),
			}
			if err := finish.Sign(); err != nil {
				return err
			}
			networker := ctx.NetworkManager().GetNetworker(cid)
			_, _, err := networker.SendToNode("COMMAND", common.BasicNet, common.NodeIDs{nid}, finish, nil, nil)
			if err != nil {
				return err
			}
			log.Infof("%s sent", finish)
		}
	}
	return nil
}

var SnapshotChain = common.NilChainID

type snapshot struct {
	DynamicCmd
}

func (c *snapshot) Match(line string) error {
	tostr := []byte(line)[len(c.DynamicCmd):]
	_, err := strconv.Atoi(string(tostr))
	if err != nil {
		return fmt.Errorf("usage: %s[chainId]", string(c.DynamicCmd))
	}
	return nil
}

func (c *snapshot) Run(line string, ctx RunContext) error {
	if !SnapshotChain.IsNil() {
		return fmt.Errorf("Refuse! snapshot is running on chain %d ", SnapshotChain)
	}
	param := []byte(line)[len(c.DynamicCmd):]
	id, err := strconv.Atoi(string(param))
	if err != nil {
		return fmt.Errorf("usage: %s[chainId]", c.DynamicCmd)
	}
	chainId := common.ChainID(id)
	if !chainId.IsMain() && ctx.DataManager().IsDataOrMemo() && ctx.DataManager().DataOrMemoOf() != chainId {
		return fmt.Errorf("Refuse! snapshot chain %d can not run on data node of chain %d ", chainId, ctx.DataManager().DataOrMemoOf())
	}
	SnapshotChain = chainId
	return nil
}
