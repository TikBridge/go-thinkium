package models

import (
	"errors"
	"math/big"

	"github.com/ThinkiumGroup/go-thinkium/config"
)

const (
	// Data forwarding mode
	RelayBroadcast     RelayType = iota // broadcast
	RelaySendTo                         // Directional transmission to a specific node
	RelayRandBroadcast                  // Random sending
)

const (
	// The identity type of the node on the chain
	CtrlOp      OperatorType = iota // Control class. The context has no chain information when the control event is executed
	DataOp                          // Data node
	CommitteeOp                     // Consensus node
	ReviveOp                        // Revive class
	InitialOp                       // Initial class of consensus node
	PreelectOp                      // Preelect class, higher than SPEC and lower than COMM
	RestartOp                       // Restarting class
	SpectatorOp                     // Spectator class
	MemoOp                          // Full class
	StartOp                         // Starting class
	FailureOp                       // Failure class
)

const (
	// Number of bytes occupied by event type
	EventTypeLength = 2

	// delta pool related
	MaxPopOfOneShardDelta = 10 // Delta number threshold per chain

	// The maximum number of transactions packed in a block
	MaxTxCountPerBlock = 2000
	// The maximum number of deltas that can be merged in each block is twice the maximum number of TX
	MaxDeltasPerBlock = MaxTxCountPerBlock << 1

	TxVersion0 = 0
	// compatible with Ethereum's transaction hash, pay attention to the tx.Hash() and tx.HashValue()
	// methods when upgrading the version
	ETHHashTxVersion      = 2
	NewBaseChainTxVersion = 3
	ETHConvertVersion     = 4
	// 1: There is a bug in V0, which leads to insufficient amount when creating or invoking the
	//    contract, and the transaction will be packaged, but the nonce value does not increase
	// 2: ETH compatible, add base chain id for conversion to ETH chainid
	// 3: update base chain id from 100007 to 70000
	// 4: convert Transaction to ETHTransaction with correct TxType even if there is no TxType in Extras
	//    DyanamicFeeTx: if GasTipCap or GasFeeCap not nil, or
	//    AccessListTxType: if AccessList it not nil, or
	//    LegacyTxType: else
	TxVersion = ETHConvertVersion

	// V0's BlockSummary.Hash Only a through transmission of BlockHash, can't reflect the location
	// information of the block, and can't complete the proof of cross chain. V1 adds chainid and
	// height to hash
	SummaryVersion0 = 0 // original version
	SummaryVersion1 = 1 // add chainid and height to hash
	SummaryVersion2 = 2 // add HistoryProof and AuditorPass for auditing, use Header instead of chainid+height+BlockHash
	SummaryVersion3 = 3 // HashValue changes
	SummaryVersion4 = 4 // rollback to original version (ChainID+Height+HoB+Comm)
	SummaryVersion5 = 5 // use HistoryProof to proof NextComm.Hash() -> BlockHash, if NextComm exists
	SummaryVersion  = SummaryVersion5

	// RRInfoVersion:
	// 1: NodeCount
	// 2: statue
	// 3: newpos (Avail, Voted, VotedAmount, Settles)
	// 4: PoSv3 (Voted/VotedAmount removed, add Delegated)
	RRInfoVersion = 4
	RRInfoVNewPos = 3
	// RRActVersion: 1: Account
	RRActVersion = 1

	// BlockHeader version
	// 1: add RRReceiptRoot reserved for v2.11.0
	//    make merkle trie root with all properties in the object
	//    make receipt root as merkle trie hash of receipts
	//    Calculate blockHeader.TransactionRoot using transaction hash value with signature
	//    modify the calculation method of ElectedNextRoot
	// 2: since v2.11.03, add ConfirmedRoot
	// 3: since v2.12.0, add RewardedEra
	// 4: since v3.1.0, placeholder in v2.14.2, add BridgeRoot
	// 5: since v3.2.0, placeholder in v2.14.2, add Random
	// 6: since v3.2.1, placeholder in v2.14.2, new strategy of generating seed (Header.FactorRoot=Sign(Body.SeedFactor), NewCommitteeSeed=Header.FactorRoot[:SeedLength]|BlockNum>=SeedBlock)
	// 7: since v2.14.2, parameters generated by proposer for transactions: TxParams
	// 8: since v2.14.4, all integer fields use the hash value of uint64 big-endian serialized bytes (for the convenience of solidity)
	BlockVersionV0 = 0
	BlockVersionV1 = 1
	BlockVersionV2 = 2
	BlockVersionV3 = 3
	BlockVersionV4 = 4
	BlockVersionV5 = 5
	BlockVersionV6 = 6
	BlockVersionV7 = 7
	BlockVersionV8 = 8
	BlockVersion   = BlockVersionV8

	// RewardReqeust version
	// 1: add SubProof/MainProof/ProofedHeight/Version
	RewardReqV0      = 0
	RewardReqV1      = 1
	RewardReqVersion = RewardReqV1

	ReceiptV0      = 0
	ReceiptV1      = 1 // use RLP to serialize the Receipt object
	ReceiptV2      = 2 // use the merkle root of Logs to calculate the hash value of Receipt
	ReceiptVersion = ReceiptV2
)

const (
	MinDataNodes = 1
	MinBootNodes = 1
	MinAdmins    = 3
)

// Required Reserve related
const (
	MaxPenalizedTime      = 3 // After the penalty exceeds this number of times, the pledge percentage is cleared to 0
	WithdrawDelayEras     = 2 // Withdraw lags 2 eras
	DepositTakeEffectEras = 2 // The time from the submission of the pledge request to the effective date of the pledge
)

const (
	// the highest value reached by the total amount of all deposits
	RRMaxDepositSumName = "rr_max_deposit_sum"

	// default RRInfo.MaxDeposit when RRInfo.MaxDeposit==nil
	RRBaseDepositSumName  = "rr_base_deposit_sum"
	DefaultBaseDepositSum = 0

	// factor for calculating various attenuation coefficients
	RRDepositFactorName  = "rr_deposit_factor"
	DefaultDepositFactor = 500000000

	// Coefficient = max( (BaseCoefficient - AttenuationFactor * CoefficientFactor), CoefficientLowerLimit )
	// basic attenuation coefficient
	RRBaseCoefficientName  = "rr_base_coefficient"
	DefaultBaseCoefficient = "1/1"

	RRCoefficientFactorName  = "rr_coefficient_factor"
	DefaultCoefficientFactor = "1/10"

	RRCoefficientLowerLimitName  = "rr_coefficient_lower_limit"
	DefaultCoefficientLowerLimit = "3/10"

	RRErasPerYearName  = "rr_eras_per_year"
	DefaultErasPerYear = 266

	RRConsensusDepSumName = "rr_consensus_dep_sum"
	RRDelegatedSumName    = "rr_delegated_sum"
	RRDataDepSumName      = "rr_data_dep_sum"

	// Consensus node reward factor
	RRConsensusRewardFactorName  = "rr_consensus_reward_factor"
	DefaultConsensusRewardFactor = "18/100"

	// Delegated reward factor
	RRDelegatedRewardFactorName  = "rr_delegated_reward_factor"
	DefaultDelegatedRewardFactor = "15/100"

	// Data node reward factor
	RRDataRewardFactorName  = "rr_data_reward_factor"
	DefaultDataRewardFactor = "15/100"

	// Auditor reward factor
	RRAuditorRewardFactorName  = "rr_auditor_reward_factor"
	DefaultAuditorRewardFactor = "1/100"

	// The upper and lower limit of consensus node pledge
	RRConsensusMinName    = "rr_consensus_minimum_deposit"
	RRConsensusMaxName    = "rr_consensus_maximum_deposit"
	DefaultMinConsensusRR = 10000 // Lower limit of consensus node pledges, (202012: from 50000->10000）
	DefaultMaxConsensusRR = 10000 // The consensus node pledges is calculated at most according to this，(202012: from 50000->10000)

	// The upper and lower limits of the available amount of data nodes
	RRDataMinName    = "rr_data_minimum_deposit"
	RRDataMaxName    = "rr_data_maximum_deposit"
	DefaultMinDataRR = 50000  // Lower limit of data node pledges, (202012: from 200000->50000）
	DefaultMaxDataRR = 500000 // The data node pledges is calculated at most according to this, (202012: from 200000->50000, 202201: -> 500000）

	RRDelegateLimitName  = "rr_delegate_limit"
	DefaultDelegateLimit = 500000

	RRWhiteListAddrName = "rr_white_list_addr"
)

var (
	DefaultBaseDepositSumBig           = new(big.Int).Mul(big.NewInt(DefaultBaseDepositSum), BigTKM)
	DefaultDepositFactorBig            = new(big.Int).Mul(big.NewInt(DefaultDepositFactor), BigTKM)
	DefaultBaseCoefficientBig, _       = new(big.Rat).SetString(DefaultBaseCoefficient)
	DefaultCoefficientFactorBig, _     = new(big.Rat).SetString(DefaultCoefficientFactor)
	DefaultCoefficientLowerLimitBig, _ = new(big.Rat).SetString(DefaultCoefficientLowerLimit)
	DefaultConsensusRewardFactorBig, _ = new(big.Rat).SetString(DefaultConsensusRewardFactor)
	DefaultDelegatedRewardFactorBig, _ = new(big.Rat).SetString(DefaultDelegatedRewardFactor)
	DefaultDataRewardFactorBig, _      = new(big.Rat).SetString(DefaultDataRewardFactor)
	DefaultAuditorRewardFactorBig, _   = new(big.Rat).SetString(DefaultAuditorRewardFactor)
	DefaultMinConsensusRRBig           = new(big.Int).Mul(big.NewInt(DefaultMinConsensusRR), BigTKM) // Pledge threshold for consensus nodes
	DefaultMaxConsensusRRBig           = new(big.Int).Mul(big.NewInt(DefaultMaxConsensusRR), BigTKM)
	DefaultMinDataRRBig                = new(big.Int).Mul(big.NewInt(DefaultMinDataRR), BigTKM) // Pledge threshold for data node
	DefaultMaxDataRRBig                = new(big.Int).Mul(big.NewInt(DefaultMaxDataRR), BigTKM)

	DefaultDelegateLimitBig = new(big.Int).Mul(big.NewInt(DefaultDelegateLimit), BigTKM)

	ErrLittleEra      = errors.New("era lesser than trie era")
	ErrMuchBigEra     = errors.New("era much bigger than trie era")
	ErrNeedSwitchEra  = errors.New("need to switch era")
	ErrWithdrawingAll = errors.New("withdrawing all in queue")
)

const (
	GasPriceName             = "gasprice"
	GasPrice                 = "400000000000"
	GasLimitName             = "gaslimit"
	GasLimit          uint64 = 2500000
	GasBonusRatioName        = "gas_bonus_ratio"
	GasBonusRatio            = "3/10"
	MaxGasLimit       uint64 = 30000000
	CallGasLimit      uint64 = 30000000
)

var (
	DefaultGasPriceBig, _      = new(big.Int).SetString(GasPrice, 10)
	DefaultGasBonusRatioBig, _ = new(big.Rat).SetString(GasBonusRatio)
)

var (
	BigShannon = big.NewInt(1000000000)
	BigTKM     = big.NewInt(0).Mul(BigShannon, BigShannon)
	BigBillion = big.NewInt(0).Mul(BigShannon, BigTKM)

	SystemNoticer Noticer
	SystemConfig  *config.Config
)

const (
	// property names for chain settings
	PocDeadlineAddrName            = "pocdeadline"
	PocTryNewBlockContractAddrName = "poctrynewblockcontract"
	PocTryNewBlockMethodName       = "poctrynewblockmethod"
	PocDeadlinePrefixName          = "pocdeadlineprefix"
	PocDeadlineAbiJson             = "pocdeadlineabijson"
	PocBindAddrName                = "pocbind"
	PocBindPrefixName              = "pocbindprefix"
	PocBindAbiJson                 = "pocbindabijson"

	// // PosCommNodeRewardName = "poscommnodereward"
	// PosCommNodeRewardName = "poscommnodereward1w.202012"
	PosCommNodeRewardName = "poscommnodereward1k.202107"
	PosDataNodeRewardName = "posdatanodereward5w.202012"
	RRStatusAuthName      = "rrstatusauth"
	BannedAddressesName   = "banned_addresses"
	RRPenaltyType         = "penalty_types" // longStorage key only of AddressOfRequiredReserve in REWARD chain

	// property names for managed committee
	ManagedCommNodeIdsName = "managedcommnodeids"
)

const (
	RewardDelayEpochs      = 2 // epoch number of delayed reward payment
	MaxErasForOnceReward   = 10
	MaxBlocksForOnceReport = 50
)

const (
	LengthOfSignature  = 65
	LengthOfPublicKey  = 65
	LengthOfPrivateKey = 32
)
