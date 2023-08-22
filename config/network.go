package config

import (
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/consts"
)

var (
	VersionInfo = NewVersionInfo()

	ExecutableFile  = "gtkm"
	FileNames       = []string{"data.so", "notice.so", "sysq.so", "vm.so", "consensus.so", ExecutableFile}
	DownloadOffset  = 0
	RestartNotified = false
)

type VersionData struct {
	Versions   [2]common.Version
	Beginning  common.Height
	Deadline   common.Height
	Sum        []byte
	Url        string
	Downloaded bool
}

func NewVersionInfo() *VersionData {
	return &VersionData{
		Versions:  [2]common.Version{consts.Version, consts.Version},
		Beginning: common.NilHeight,
		Deadline:  common.NilHeight,
	}
}

var (
	DefaultEthRpcEndpoint = common.Endpoint{NetType: "tcp", Address: common.DefaultEthRpcAddress}
)

type NConfig struct {
	DataServers []common.Dataserver `yaml:"bootservers" json:"bootservers"`
	P2Ps        *P2PConfig          `yaml:"p2p",omitempty json:"p2p"`
	RPCs        *RPCConfig          `yaml:"rpc",omitempty json:"rpc"`
	ETHRPC      []ETHRPCConfig      `yaml:"ethrpcs",omitempty json:"ethrpc"`
	Pprof       *string             `yaml:"pprof",omitempty json:"pprof"`

	DataServerMap map[common.NodeID][]common.Dataserver `yaml:"-" json:"-"` // nodeid -> []Dataserver
}

type P2PConfig struct {
	PortRange *[2]uint16 `yaml:"portRange",omitempty json:"portRange"`
}

func (p *P2PConfig) GetPortRange() *[2]uint16 {
	if p == nil {
		return nil
	}
	return p.PortRange
}

type RPCConfig struct {
	MessageBufferSize uint16           `yaml:"buffersize" json:"-"`
	KeepaliveInterval int64            `yaml:"keepaliveinterval" json:"-"`
	RPCServerAddr     *common.Endpoint `yaml:"rpcserver" json:"rpcserver"`
}

func (rpc *RPCConfig) GetRpcEndpoint() common.Endpoint {
	if rpc == nil || rpc.RPCServerAddr == nil {
		return common.DefaultRpcEndpoint
	}
	return *rpc.RPCServerAddr
}

func (rpc *RPCConfig) GetRpcAddress() string {
	if rpc == nil || rpc.RPCServerAddr == nil {
		return common.DefaultRpcAddress
	}
	return rpc.RPCServerAddr.Address
}

func (v *VersionData) VersionChanged() bool {
	return v.Versions[0] != v.Versions[1]
}

func (v *VersionData) UpdateVersion() {
	v.Versions[0] = v.Versions[1]
}

func (v *VersionData) GetVersion() uint64 {
	return uint64(v.Versions[0])
}

func (v *VersionData) GetNewVersion() uint64 {
	return uint64(v.Versions[1])
}

func (v *VersionData) ContainsVersion(version uint64) bool {
	return uint64(v.Versions[0]) == version || uint64(v.Versions[1]) == version
}

func (v *VersionData) IsNeedDownload() bool {
	return !v.Downloaded
}

func (v *VersionData) SetDownloaded() {
	v.Downloaded = true
}

func (v *VersionData) SetNeedDownload() {
	v.Downloaded = false
}

func (v *VersionData) OnNewVersion() bool {
	return consts.Version == v.Versions[1]
}

func (v *VersionData) TakeEffect() bool {
	return consts.Version == v.Versions[1] && consts.Version == v.Versions[0]
}

func (v *VersionData) VersionString() string {
	return fmt.Sprintf("%s - %s", v.Versions[0], v.Versions[1])
}

func (v *VersionData) String() string {
	return fmt.Sprintf("version %s - %s, beginning %d, deadline %d, md5 %x, url %s, download %t",
		v.Versions[0], v.Versions[1], v.Beginning, v.Deadline, v.Sum, v.Url, v.Downloaded)
}

type ETHRPCConfig struct {
	MessageBufferSize uint16           `yaml:"buffersize" json:"-"`
	KeepaliveInterval int64            `yaml:"keepaliveinterval" json:"-"`
	ChainID           *common.ChainID  `yaml:"chainID"`
	ETHRPCServer      *common.Endpoint `yaml:"ethrpcserver"`
}

func (rpc *ETHRPCConfig) GetChainID() common.ChainID {
	return *rpc.ChainID
}

func (rpc *ETHRPCConfig) GetRpcEndpoint() common.Endpoint {
	if rpc == nil || rpc.ETHRPCServer == nil {
		return DefaultEthRpcEndpoint
	}
	return *rpc.ETHRPCServer
}
