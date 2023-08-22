package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"gopkg.in/yaml.v2"
)

type LogType uint8

const (
	BasicLog LogType = iota
	NetLog
	NetDebugLog
	ConsensusLog
	ConsensusDebugLog
	DataLog
	DataDebugLog
	QueueLog
	QueueDebugLog
	VmLog
	VmDebugLog
	BalanceLog
	RpcLog
	SimulatingVmLog
	LengthOfLogType
)

const (
	SettleTrieDebugLog = true
)

func (l LogType) String() string {
	switch l {
	case BasicLog:
		return "BasicLog"
	case NetLog:
		return "NetLog"
	case NetDebugLog:
		return "NetDebugLog"
	case ConsensusLog:
		return "ConsensusLog"
	case ConsensusDebugLog:
		return "ConsensusDebugLog"
	case DataLog:
		return "DataLog"
	case DataDebugLog:
		return "DataDebugLog"
	case QueueLog:
		return "QueueLog"
	case QueueDebugLog:
		return "QueueDebugLog"
	case VmLog:
		return "VmLog"
	case VmDebugLog:
		return "VmDebugLog"
	case BalanceLog:
		return "BalanceLog"
	case RpcLog:
		return "RPCLog"
	case SimulatingVmLog:
		return "SimVmLog"
	default:
		return "LogType-" + strconv.Itoa(int(l))
	}
}

var (
	logTypeArray [LengthOfLogType]bool
	SystemConf   *Config

	validatorInterface = reflect.TypeOf(new(ConfValidator)).Elem()
)

type ElectConf struct {
	ChainID   common.ChainID      `yaml:"chainid"`   // ID of the chain
	Election  common.ElectionType `yaml:"election"`  // Election type, default NONE
	SyncBlock bool                `yaml:"syncblock"` // no use
}

func (cc ElectConf) String() string {
	return fmt.Sprintf("{ChainID:%d Election:%s SyncBlock:%t}", cc.ChainID, cc.Election, cc.SyncBlock)
}

type DConfig struct {
	Path string `yaml:"datapath"` // db path
}

func (conf *DConfig) GetRealPath(chainId common.ChainID) string {
	configPath := common.FormalizeBasePath(conf.Path)
	dbPath := common.DatabasePath(configPath, chainId)
	if dataDir, err := os.Open(configPath); err == nil {
		dbDirs, err := dataDir.Readdirnames(0)
		if err != nil || len(dbDirs) == 0 {
			return dbPath
		}
		sort.Strings(dbDirs)
		prefix := "db" + strconv.Itoa(int(chainId))
		latestSuffix := int64(0)
		for _, dbName := range dbDirs {
			strs := strings.Split(dbName, "_")
			if len(strs) < 1 || strs[0] != prefix {
				continue
			}
			suffix := int64(0)
			if len(strs) > 1 {
				suffix, err = strconv.ParseInt(strs[1], 10, 64)
				if err != nil {
					continue
				}
			}
			if suffix > latestSuffix {
				dbPath = configPath + dbName
			}
		}
	}
	return dbPath
}

type ConfValidator interface {
	Validate() error
}

const DefaultLoadLimit = 1

type Config struct {
	PriKeyString       string               `yaml:"priKey"`             // hex string of private key of the node
	LoadLimit          int                  `yaml:"loadlimit"`          // Load upper limit. Configure the current node to make consensus on several chains at the same time. Default loadlimit = 2
	NetworkConf        NConfig              `yaml:"network"`            // network config
	DataConf           DConfig              `yaml:"data"`               // data node config
	LogTypes           []LogType            `yaml:"logs"`               // log types should print
	LogPath            string               `yaml:"logpath"`            // log file path
	Chains             ChainConfs           `yaml:"chains"`             // configs for genesis chains
	TxCount            uint64               `yaml:"txCount"`            //
	NetDelay           []int                `yaml:"netDelay"`           // range of network delay (for debugging)
	WaitingTime        *time.Duration       `yaml:"waitingTime"`        // delay for consensus
	NodeType           *common.NodeType     `yaml:"nodetype"`           // type of node: Consensus:0, Data:1, Memo:2
	ForChain           *common.ChainID      `yaml:"forchain"`           // specifies the chain of node services
	FullData           bool                 `yaml:"fulldata"`           // whether a full data node
	CheckData          bool                 `yaml:"checkdata"`          // whether need to check old data
	Compatible         *bool                `yaml:"compatible"`         // Compatibility with historical data (due to historical reasons, some data in the early stage are missing, which makes some data unable to be verified, or the function cannot be realized. The switch is used to open and close the forced verification)
	Nid                *common.NodeID       `yaml:"-"`                  // The nodeid object obtained by parsing Nodeidstring
	PrivKey            cipher.ECCPrivateKey `yaml:"-"`                  // The private key object obtained by parsing PriKeyString
	StandAlone         bool                 `yaml:"standAlone"`         // whether start in single chain mode
	Noticer            *NoticeConf          `yaml:"notice"`             //
	Starter            *Starter             `yaml:"starter"`            // starter private key
	Releases           ReleaseDefs          `yaml:"releases"`           // release definations
	Auditor            *AuditorConf         `yaml:"auditor"`            // Auditor config
	DownloadUrl        string               `yaml:"downloadUrl"`        //
	CheckNodeValueHash bool                 `yaml:"checkNodeValueHash"` // whether to check value hash in trie.node.expandValue
	BlocksInEpoch      uint64               `yaml:"blocksInEpoch"`      // blocks in epoch, default 1000
	EpochsInEra        uint64               `yaml:"epochsInEra"`        // epochs in era, default 36
	BaseChainID        uint64               `yaml:"baseChainID"`        // base chain id for ETH-ChainID
	GenesisRoot        GenesisRootInfos     `yaml:"genesisRoot"`
	TmpDBPath          string               `yaml:"tmpDBPath"` // for cmd
}

func LoadConfig(path string) (*Config, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("reading config ", path, " error: ", err)
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(contents, &config)
	if err != nil {
		log.Error("unmarshal config ", path, " error: ", err)
		return nil, err
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if err := config.checkethrpc(); err != nil {
		return nil, err
	}
	// log.Info("load config from ", path, " success")
	SystemConf = &config
	return &config, nil
}

func (c *Config) checkethrpc() error {
	ethrpcmapids := make(map[*common.ChainID]struct{}, len(c.NetworkConf.ETHRPC))
	ethrpcmapaddrs := make(map[string]struct{}, len(c.NetworkConf.ETHRPC))
	for _, item := range c.NetworkConf.ETHRPC {
		if item.ChainID != nil {
			if _, ok := ethrpcmapids[item.ChainID]; ok {
				return errors.New("config file set the same ethrpc chainid")
			} else {
				ethrpcmapids[item.ChainID] = struct{}{}
			}
		}

		if _, ok := ethrpcmapaddrs[item.ETHRPCServer.Address]; ok {
			return errors.New("config file set the same ethrpcserver address")
		} else {
			ethrpcmapaddrs[item.ETHRPCServer.Address] = struct{}{}
		}
	}
	return nil
}

func (c *Config) validate() error {
	prikeybytes, err := hex.DecodeString(c.PriKeyString)
	if err != nil {
		return common.NewDvppError("parse private key error: ", err)
	}
	// ecsk, err := common.ToECDSAPrivateKey(prikeybytes)
	ecsk, err := cipher.RealCipher.BytesToPriv(prikeybytes)
	if err != nil {
		return common.NewDvppError("unmarshal private key error: ", err)
	}
	c.PrivKey = ecsk

	pnid := common.BytesToNodeID(c.PrivKey.GetPublicKey().ToNodeIDBytes())
	c.Nid = &pnid

	if c.Starter == nil {
		c.Starter = &Starter{}
	}
	if err := c.GenesisRoot.validate(); err != nil {
		return err
	}
	// validate all ConfValidators
	val := reflect.ValueOf(c).Elem()
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Implements(validatorInterface) {
			// if val.FieldByName(f.Name).IsNil() {
			// 	continue
			// }
			validator := val.FieldByName(f.Name).Interface().(ConfValidator)
			if validator != nil {
				// fmt.Println(fmt.Sprintf("[CONFIG] field %s validating", f.Name))
				err = validator.Validate()
				if err != nil {
					panic(fmt.Errorf("[CONFIG] validate field %s with error: %v", f.Name, err))
					return err
				}
				// fmt.Println(fmt.Sprintf("[CONFIG] field %s validated", f.Name))
			}
		}
	}
	//
	// if err := c.Chains.validate(); err != nil {
	// 	return err
	// }
	//
	// if c.Noticer != nil {
	// 	err = c.Noticer.validate()
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	trie.CheckNodeValueHash = c.CheckNodeValueHash
	return nil
}

func (c *Config) IsCompatible() bool {
	if c.Compatible == nil {
		return common.DefaultCompatible
	}
	return *c.Compatible
}

func (c *Config) MakeLogTypeMap() {
	ver := make([]string, 0)

	for i := 0; i < len(c.LogTypes); i++ {
		if c.LogTypes[i] < 0 || c.LogTypes[i] >= LengthOfLogType {
			continue
		}
		logTypeArray[c.LogTypes[i]] = true
		ver = append(ver, c.LogTypes[i].String())
	}
	log.Infof("LogTypes: %v", ver)
}

func IsLogOn(logType LogType) bool {
	return logTypeArray[logType]
}

func (c *Config) GenerateChainInfos() map[common.ChainID]*common.ChainInfos {
	chaininfos := make(map[common.ChainID]*common.ChainInfos)

	for _, item := range c.Chains {
		cs, err := common.NewChainStruct(item.ID, item.ParentID)
		if err != nil {
			panic(fmt.Sprintf("create ChainStruct failed: %v", err))
		}
		if !item.ElectType.IsValid() {
			panic(fmt.Sprintf("invalid election type: %d", item.ElectType))
		}
		// Use copy to prevent the sequence number error of the node after the slice is sorted
		commNids := make(common.NodeIDs, len(item.CommitteeIds))
		copy(commNids, item.CommitteeIds)
		if len(commNids) > 1 {
			sort.Sort(commNids)
		}
		gDataNids := make(common.NodeIDs, len(item.GenesisDataserverIds))
		copy(gDataNids, item.GenesisDataserverIds)
		if len(gDataNids) > 1 {
			sort.Sort(gDataNids)
		}
		dataNids := make(common.NodeIDs, len(item.DataserverIds))
		copy(dataNids, item.DataserverIds)
		if len(dataNids) > 1 {
			sort.Sort(dataNids)
		}
		// for _, dataNid := range dataNids {
		// 	if dataNid == common.SystemNodeID {
		// 		m.isDataNode = true
		// 		m.chainIDOfData = item.ID
		// 		common.FullData = true
		// 	}
		// }

		cc := &common.ChainInfos{
			HaveSecondCoin: !common.CoinID(item.SecondCoinId).IsSovereign(),
			SecondCoinId:   common.CoinID(item.SecondCoinId),
			GenesisCommIds: commNids,
			ChainStruct:    *cs,
			BootNodes:      make([]common.Dataserver, 0),
			Syncblock:      false,
			Election:       item.ElectType,
			GenesisDatas:   gDataNids,
			Datas:          dataNids,
			ChainVersion:   "",
		}
		cc.Attributes = make(common.ChainAttrs, 0)
		_ = cc.Attributes.AddByName(item.Attributes...)

		if item.SecondCoinId != 0 {
			cc.SecondCoinName = item.SecondCoinName
		}
		for _, saddr := range item.Admins {
			addr := common.Hex2Bytes(saddr)

			cc.AdminPubs = append(cc.AdminPubs, addr)
		}
		// // Sort the content of info after reading from the configuration file
		// Because of the newly added sorting function, it is likely to be inconsistent with
		// the chain structure written in the genesis block, leading in failure to rebuild
		// cc.Sort()
		chaininfos[item.ID] = cc
	}

	// validate structure
	for cid, info := range chaininfos {
		if info.ParentID.IsNil() {
			if !cid.IsMain() {
				panic("illegal main chain setting")
			}
		} else {
			_, ok := chaininfos[info.ParentID]
			if !ok {
				panic(fmt.Errorf("no parent chain %d set of chain %d", info.ParentID, cid))
			}
		}
	}
	if _, exist := chaininfos[common.MainChainID]; !exist {
		panic("no main chain config found")
	}

	// set all boot servers
	for _, bootserver := range c.NetworkConf.DataServers {
		info, ok := chaininfos[common.ChainID(bootserver.ChainID)]
		if ok && info != nil {
			info.BootNodes = append(info.BootNodes, bootserver)
		}
	}

	return chaininfos
}

// TODO: Because it is estimated according to the number of effective pledged nodes, the number of chains
//
//	and the upper limit of consensus committee size, but the number of nodes actually participating in the
//	election is likely to be less than the number of effective pledged nodes. At this time, we need other
//	means to ensure their online services or to obtain the accurate number of nodes participating in the
//	consensus. For example, the number of nodes participating in consensus can be roughly inferred by
//	detecting the past period of rewards on the reward chain.
//
// TODO: 因为是根据当前有效质押节点个数、链个数以及共识委员会size上限估算的比例，但
//
//	是实际参与选举的节点个数很可能小于有效质押节点个数。此时需要其他手段尽量保证他们
//	在线服务或尽量获取准确的参与共识的节点个数。如：在奖励链上检测过去一段时间的奖励，
//	可以大致推断出接下来参与共识的节点个数。
func GetPofChosen(vrfChainCount int64, nodeCount uint32) *big.Rat {
	if nodeCount == 0 {
		return big.NewRat(1, 1)
	}
	number := int64(nodeCount)
	min := consts.MinimumCommSize * vrfChainCount
	if number < min {
		// TODO: It is less than the minimum requirement. At this time, the number of hash value
		//  partitions should be less than the number of candidate chains. However, this situation
		//  has not been adapted, return 1 for convenience
		return big.NewRat(1, 1)
	}
	max := consts.MaximumCommSize * vrfChainCount
	if number <= max {
		return big.NewRat(1, 1)
	}
	return big.NewRat(max, number)
}

func GetCurrentPath() (string, error) {
	dir := filepath.Dir(os.Args[0])
	path, err := filepath.Abs(dir)
	return path, err
}
