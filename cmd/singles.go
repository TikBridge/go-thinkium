package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type join struct {
	SingleCmd
}

func (j join) Run(line string, ctx RunContext) error {
	req := &models.SyncRequest{
		ChainID:   common.MainChainID,
		NodeID:    common.SystemNodeID,
		AllBlock:  false,
		Timestamp: time.Now().UnixNano(),
	}
	ctx.Eventer().Post(req)
	return nil
}

type queue struct {
	SingleCmd
}

func (q queue) Run(line string, ctx RunContext) error {
	ctx.Eventer().PrintCounts()
	return nil
}

type status struct {
	SingleCmd
}

func (s status) Run(line string, ctx RunContext) error {
	ctx.NetworkManager().Status()
	return nil
}

type synccmd struct {
	SingleCmd
}

func (s synccmd) Run(line string, ctx RunContext) error {
	if common.NdType != nil && *common.NdType == common.Memo {
		ctx.Eventer().AddChainOpType(*common.ForChain, models.MemoOp)
	}
	var chainId common.ChainID
	if ctx.DataManager().IsDataNode() {
		chainId = ctx.DataManager().DataNodeOf()
	} else {
		if common.ForChain == nil {
			return errors.New("no forchain configuration found")
		}
		chainId = *common.ForChain
	}
	req := &models.SyncRequest{
		ChainID:   chainId,
		NodeID:    common.SystemNodeID,
		AllBlock:  common.FullData,
		RpcAddr:   ctx.Config().NetworkConf.RPCs.GetRpcAddress(),
		Timestamp: time.Now().UnixNano(),
	}
	ctx.Eventer().Post(req)
	return nil
}

type replay struct {
	SingleCmd
}

func (r replay) Run(line string, ctx RunContext) error {
	// It can only be executed by the data node. Starting from the current height of the chain,
	// it searches forward in order whether there is a block of the next height. If there is,
	// it will be executed until there is no continuous next block
	if ctx.DataManager().IsDataNode() {
		cid := ctx.DataManager().DataNodeOf()
		holder, err := ctx.DataManager().GetChainData(cid)
		if err != nil {
			panic(fmt.Sprintf("ChainID:%d holder get error: %v", cid, err))
		}
		h := holder.GetCurrentHeight()
		log.Warnf("======= start restoring from ChainID:%d Height:%d =======", cid, h)
		for {
			h = h + 1
			block, err := holder.GetBlock(h)
			if err != nil {
				log.Warnf("get block of Height:%d error: %v", h, err)
				break
			}
			if block == nil {
				log.Warnf("block Height:%d not found", h)
				break
			}
			ctx := (&models.ConsensusContext{ChainID: cid, Replaying: true}).SetCommitting()
			if err := holder.PutBlock(ctx, block, nil, nil); err != nil {
				log.Errorf("Height:%d error: %v", h, err)
				break
			}
			log.Infof("%s replayed", block)
		}
		log.Warnf("======= stopped restoring at ChainID:%d Height:%d =======", cid, h)
		return nil
	}
	return errors.New("not a data node")
}
