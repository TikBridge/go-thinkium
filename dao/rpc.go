package dao

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
)

var (
	TryRpcGetBlock func(chain models.DataHolder, h common.Height) (ret *models.BlockEMessage, err error)
	RpcReplayBlock func(target string, request *models.SyncRequest, holder models.DataHolder, end common.Height, logger logrus.FieldLogger)
	RpcGetRRProof  func(rewardChainInfo *common.ChainInfos, rrRoot []byte, logger logrus.FieldLogger) (*models.RRProofs, error)
)
