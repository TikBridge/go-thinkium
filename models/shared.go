package models

import (
	"fmt"
	"plugin"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/sirupsen/logrus"
)

var VMPlugin *plugin.Plugin

func NewConsensusEngine(enginePlug *plugin.Plugin, eventer Eventer, nmanager NetworkManager,
	dmanager DataManager, conf *config.Config) Engine {
	NewEngine, err := enginePlug.Lookup("NewEngine")
	if err != nil {
		panic(err)
	}
	return NewEngine.(func(Eventer, NetworkManager, DataManager, *config.Config) Engine)(eventer, nmanager, dmanager, conf)
}

func NewEventer(eventerPlug *plugin.Plugin, queueSize, barrelSize, workerSize int, shutingdownFunc func(), isInComm IsInCommitteeFunc) Eventer {
	NewEventController, err := eventerPlug.Lookup("NewEventController")
	if err != nil {
		panic(err)
	}
	return NewEventController.(func(int, int, int, func(), IsInCommitteeFunc) Eventer)(queueSize, barrelSize, workerSize, shutingdownFunc, isInComm)
}

func NewDManager(dataPlugin *plugin.Plugin, path string, eventer Eventer) (DataManager, error) {
	NewDManager, err := dataPlugin.Lookup("NewManager")
	if err != nil {
		panic(err)
	}
	return NewDManager.(func(string, Eventer) (DataManager, error))(path, eventer)
}

func NewStateDB(chainID common.ChainID, shardInfo common.ShardInfo, t *trie.Trie, dbase db.Database,
	dmanager DataManager) StateDB {

	NewStateDB, err := VMPlugin.Lookup("NewStateDB")
	if err != nil {
		panic(err)
	}
	return NewStateDB.(func(common.ChainID, common.ShardInfo, *trie.Trie, db.Database, DataManager) StateDB)(
		chainID, shardInfo, t, dbase, dmanager)
}

func LoadNoticer(sopath string, queueSize int, chainID common.ChainID, redisAddr string, redisPwd string,
	redisDB int, redisQueue string) Noticer {
	p, err := common.InitSharedObjectWithError(sopath)
	if err != nil {
		log.Warnf("load Noticer failed at %s: %v", sopath, err)
		return nil
	}
	newMethod, err := p.Lookup("NewNotice")
	if err != nil {
		log.Warnf("bind NewNotice with plugin at %s failed: %v", sopath, err)
		return nil
	}
	m, ok := newMethod.(func(int, common.ChainID, string, string, int, string) Noticer)
	if !ok || m == nil {
		log.Warnf("binding NewNotice with plugin at %s failed: %v", sopath, err)
		return nil
	}
	return m(queueSize, chainID, redisAddr, redisPwd, redisDB, redisQueue)
}

type IsInCommitteeFunc func(DataManager, common.Seed, [32]byte, common.ChainID, *RRInfo, byte, logrus.FieldLogger) bool

func LocateIsInCommittee(consensusPlugin *plugin.Plugin) IsInCommitteeFunc {
	iicf, err := consensusPlugin.Lookup("IsInCommittee")
	if err != nil {
		panic(err)
	}
	return iicf.(func(DataManager, common.Seed, [32]byte, common.ChainID, *RRInfo, byte, logrus.FieldLogger) bool)
}

type ChainStats struct {
	ChainID            common.ChainID    `json:"chainid"`            // id of current chain
	CurrentHeight      uint64            `json:"currentheight"`      // current height of the chain
	SumTxCount         uint64            `json:"txcount"`            // The number of current chain transactions after this launch
	AllTps             uint64            `json:"tps"`                // Current chain TPS after this launch
	LastEpochTps       uint64            `json:"tpsLastEpoch"`       // TPS of the previous epoch after this launch
	LastNTps           uint64            `json:"tpsLastN"`           // TPS of previous %N blocks
	Lives              uint64            `json:"lives"`              // Running time after this launch (in seconds)
	AccountCount       uint64            `json:"accountcount"`       // 0
	EpochLength        uint64            `json:"epochlength"`        // The number of blocks in one epoch
	AvgEpochDuration   uint64            `json:"epochduration"`      // Average time of an epoch (in seconds)
	LastEpochDuration  uint64            `json:"lastepochduration"`  // The time spent in the last epoch (in seconds)
	LastNDuration      uint64            `json:"lastNduration"`      // Time spent in the previous %N blocks (in seconds)
	LastEpochBlockTime uint64            `json:"lastEpochBlockTime"` // The average block time of the last epcoh (in milliseconds)
	LastNBlockTime     uint64            `json:"lastNBlockTime"`     // Average block time of previous %N blocks (in milliseconds)
	N                  uint64            `json:"N"`                  // The value of N
	GasLimit           uint64            `json:"gaslimit"`           // Current chain default GasLimit
	GasPrice           string            `json:"gasprice"`           // Current chain default GasPrice
	CurrentComm        []common.NodeID   `json:"currentcomm"`        // The node list of the current committee of the chain
	LastConfirmed      []*ChainConfirmed `json:"confirmed"`          // last confirmed infos of sub-chains
	Version            string            `json:"version"`            // Version of current node
}

func (s *ChainStats) String() string {
	if s == nil {
		return "ChainStats<nil>"
	}
	return fmt.Sprintf("ChainStats{ChainID:%d Current:%d Version:%s}", s.ChainID, s.CurrentHeight, s.Version)
}

func (s *ChainStats) InfoString(level common.IndentLevel) string {
	if s == nil {
		return "ChainStats<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("ChainStats{"+
		"\n%s\tCurrentHeight: %d"+
		"\n%s\tSumTxCount: %d"+
		"\n%s\tAllTps: %d"+
		"\n%s\tLastEpochTps: %d"+
		"\n%s\tLastNTps: %d"+
		"\n%s\tLives: %d"+
		"\n%s\tAccountCount: %d"+
		"\n%s\tEpochLength: %d"+
		"\n%s\tAvgEpochDuration: %d"+
		"\n%s\tLastEpochDuration: %d"+
		"\n%s\tLastNDuration: %d"+
		"\n%s\tLastEpochBlockTime: %d"+
		"\n%s\tLastNBlockTime: %d"+
		"\n%s\tN: %d"+
		"\n%s\tGasLimit: %d"+
		"\n%s\tGasPrice: %s"+
		"\n%s\tCurrentComm: %s"+
		"\n%s\tLastConfirmed: %s"+
		"\n%s\tVersion: %s"+
		"}",
		base, s.CurrentHeight,
		base, s.SumTxCount,
		base, s.AllTps,
		base, s.LastEpochTps,
		base, s.LastNTps,
		base, s.Lives,
		base, s.AccountCount,
		base, s.EpochLength,
		base, s.AvgEpochDuration,
		base, s.LastEpochDuration,
		base, s.LastNDuration,
		base, s.LastEpochBlockTime,
		base, s.LastNBlockTime,
		base, s.N,
		base, s.GasLimit,
		base, s.GasPrice,
		base, common.NodeIDs(s.CurrentComm).InfoString(next),
		base, next.InfoString(s.LastConfirmed),
		base, s.Version,
	)
}
