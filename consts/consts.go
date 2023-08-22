package consts

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

// program auto update

// Minimum epoch count for program auto update
func MinimumAutoUpdateBlocksCount() uint64 {
	return 120 * common.BlocksInEpoch
}

// Consensus node stop elect to wait for restart
func StopElectForNewVersionBlockCount() uint64 {
	return 10 * common.BlocksInEpoch
}

// Data node restart one by one with this interval
func RestartForNewVersionInterval() uint64 {
	return 3 * common.BlocksInEpoch
}

const (
	// Change this version on every edition, so that you can join in the network by using this version as default
	Version common.Version = 3003001 // node version

	// consensus related constants
	MinimumCommSize        = 4   // bft 3f+1. If you want to have one fault tolerance, you need at least 3*1+1=4 nodes, and there is no fault tolerance below 3 nodes
	MaximumCommSize        = 100 // Maximum number of members of consensus committee
	DefaultTBFTWaitingTime = 500 // The default waiting time of consensus processing. (ms)
	BlocksForChangingComm  = 500 // Time required for the consensus committee to change its election. (blocks)
	BlocksForPreElecting   = 50  // Time required for register for the preelection. (blocks)

	DeltaStep       = 4    // The interval blocks (n) of the delta information of the current shard sent to other shards (broadcast once every n blocks)
	DeltasNeedProof = true // Whether to provide proof and verification for DeltasPack
	MaxDeltaStep    = 10   // The most number of OneDeltas in one DeltasPack, to avoid too much data one time

	T = 3 // Maximum network latency (blocks)
	// Threshold of the subchain is suspected to stop
	// 子链重启后的第一个块未被确认时，此时主链已经过去很久，此时应该与重启选举高度相比，此时阈值需要高过最后一个
	// ElectedHeight足够多，给予子链重启足够的时间。
	// When the first block after the restart of the sub-chain is not confirmed, the main chain
	// has passed for a long time. At this time, it should be compared with the height of the
	// restart election. The threshold needs to be higher than the last ElectedHeight enough to
	// give enough time for the restart of the sub-chain.
	TD  = 600
	TDN = 20
	// The number of blocks that need to be delayed for the confirmed block of the sub-chain,
	// which is mainly used to prevent other consensus nodes from receiving the block during
	// consensus
	ReportN = 1

	TransferGas            uint64 = 25000
	RRContractGas          uint64 = 10000
	WriteCCContractGas     uint64 = 200000
	CashCCContractGas      uint64 = 0
	CancelCCContractGas    uint64 = 0
	ChainManageContractGas uint64 = 0 // change management, chain setting
	ExchangerContractGas   uint64 = 100000
	MinterContractGas      uint64 = 10000
	ManageCommitteeGas     uint64 = 0
	SRContractGas          uint64 = 0
	UpdateVersionGas       uint64 = 0
	SysBridgeGas           uint64 = 200000
	SysForwardGas          uint64 = 10000

	P2PNeedMAC          = true      // whether network message need MAC verification
	P2PMacLen           = 3         // length of MAC
	P2PMaxMsgLoadLength = 100000000 // 100MB

	// max chainid slots for election
	MaxElectionSlotSize = 2048
	// when a sub-chain has not been confirmed for N>=ChainStoppedThreshold consecutive blocks
	// on the main chain, it is considered that the sub-chain has stopped.
	ChainStoppedThreshold = 1000

	// In VM, the value of blockhash(block.number-MaxBlockHashHisInVM) can be obtained correctly,
	// otherwise zero value returned
	MaxBlockHashHisInVM = 2048

	FullSyncLimits = 100000

	// when the time exceeds this threshold, no new block is confirmed, it means that the
	// current node is timed out on the chain
	BlockTimeOutSeconds = 120
	// the number of blocks that the node may miss when it is found timed out on the chain
	BlocksInTimeOut = BlockTimeOutSeconds / 3
)

func init() {
	log.Infof("Version: %s", Version)
}
