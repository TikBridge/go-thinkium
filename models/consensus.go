package models

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
)

type (
	Engine interface {
		common.Service
		ChainComm(ChainID common.ChainID) (*Committee, error)
		ChainNextComm(ChainID common.ChainID) (*Committee, error)
		StartConsensus()
		CreateSubChain(chainID common.ChainID) bool // return true if new sub chain created, return false if the subchain already exists
		RemoveSubChain(chainID common.ChainID)
		// ResetChainHeightAndComm(id common.ChainID, height common.Height, comm *Committee, next *Committee) error
		// SetChainComm(cid common.ChainID, epoch common.EpochNum, nids *Committee) error
		GetWorkingChains() (map[common.ChainID]bool, error)
		ReviveMainChain() error
		ResetChainHeight(id common.ChainID, height common.Height) error
		// SetChainComm(cid common.ChainID, epoch common.EpochNum, nids *Committee) error
		ChainStats(chainID common.ChainID) string
	}

	ElectCallback func(keepComm bool, oldcomm *Committee, newcomm *Committee)

	Elector interface {
		// Returns whether the election of current chain is dynamic. False means that dynamic election is not needed
		IsDynamic() bool
		// Is the current node a legal candidate
		IsCandidate() bool
		// Filter for receiving block data
		BlockReceived(ctx *Context, block *BlockEMessage)
		// Filter for generating block data
		BlockGenerated(block *BlockEMessage) error
		BlockVerifying(block *BlockEMessage) error
		// Set callback function after successful election
		RegisterElectedCallback(callback ElectCallback)
		// Election message processing
		Electioneer(ctx *Context, msg interface{}) error
		// Switch epoch, return whether switched to a new epoch with new committee
		SwitchEpoch(oldEpoch common.EpochNum) (keepComm bool)
		// Electing according to electMsg
		ElectToChain(ctx *Context, electMsg interface{}) error
		// Preelect according to electMsg
		PreElectToChain(ctx *Context, electMsg interface{}) error
		// Is the current node elected as the member of committee which specified by epoch number: epoch
		Chosen(ctx *Context, epoch common.EpochNum) bool
		// Returns committee of next epoch, return nil when the current election is not completed
		// NextComm() *Committee
		// hasNextComm() bool
		// SetNextCommittee(comm *Committee)
	}
)

var (
	ErrIllegalChainID   = errors.New("illegal chain id")
	ErrDelayEpochNum    = errors.New("delay epoch num")
	ErrDelayBlockNum    = errors.New("delay block num")
	ErrWrongState       = errors.New("wrong state")
	ErrShouldIgnore     = errors.New("should ignore this error")
	ErrWrongEvent       = errors.New("wrong event")
	ErrNeedBuffer       = errors.New("need to buf")
	ErrUnexpectingEvent = errors.New("unexpecting event")
	ErrBufferByState    = errors.New("bufferred by state")
	ErrNoMatching       = errors.New("no matching event")
	ErrConsensusFailed  = errors.New("consensus failed")
	ErrHeightExceeded   = errors.New("height exceeded")
	ErrBlockNotFound    = errors.New("block not found")
)

func ReachPrepare(commSize, prepared int) bool {
	return prepared > commSize*2/3
}

func ReachCommit(commSize, committed int) bool {
	// To avoid the situation of that when the size of the committee is small, the condition of
	// failing to meet the commit condition due to excessive concentration of Prepare Events
	// 避免当committee size比较小时，出现由于prepare消息过度集中导致无法满足commit条件的情况
	return committed > (commSize-1)/2
	// return committed > commSize*2/3
}

func ReachConfirm(commSize, confirmed int) bool {
	return confirmed > commSize*2/3
}

func ReachAudited(auditorSize, auditedSize int) bool {
	return auditedSize > auditorSize*2/3
}

func ReachRevealed(auditorSize, revealedSize int) bool {
	return revealedSize > auditorSize*1/2
}

//
// // Deprecated
// func ParseToAddress(bitLength uint, shardPos uint16, nodePos uint16, index uint64) (addr common.Address) {
// 	src := make([]byte, 2+2+8)
// 	src[0] = byte(shardPos >> 8)
// 	src[1] = byte(shardPos)
// 	src[2] = byte(nodePos >> 8)
// 	src[3] = byte(nodePos)
// 	for i := uint(0); i < 8; i++ {
// 		src[4+i] = byte(index >> (8 * i))
// 	}
//
// 	hashOfSrc, _ := common.Hash256s(src)
// 	copy(addr[:], hashOfSrc[common.HashLength-common.AddressLength:])
//
// 	shardPos <<= 16 - bitLength
//
// 	if bitLength > 8 {
// 		addr[0] = byte(shardPos >> 8)
// 		masklen := bitLength & 0x7
// 		mask := byte(0xff) >> masklen
// 		addr[1] &= mask
// 		addr[1] |= byte(shardPos)
// 	} else {
// 		mask := byte(0xff) >> bitLength
// 		addr[0] &= mask
// 		addr[0] |= byte(shardPos >> 8)
// 	}
// 	return
// }

type BlockValidateError struct {
	err    error
	failed bool
}

func (e *BlockValidateError) Error() string {
	return fmt.Sprintf("BlockValidateError: %s", e.err.Error())
}

func (e *BlockValidateError) ValidateFailed() bool {
	return e.failed
}

func ValidateFailed(err error) error {
	if err == nil {
		return &BlockValidateError{
			err:    errors.New("empty block validate error"),
			failed: true,
		}
	}
	if v, ok := err.(*BlockValidateError); ok {
		return &BlockValidateError{
			err:    v.err,
			failed: true,
		}
	}
	return &BlockValidateError{
		err:    err,
		failed: true,
	}
}

func IsBlockValidateError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*BlockValidateError)
	return ok
}

func IsBlockValidateFailed(err error) bool {
	if err == nil {
		return false
	}
	if v, ok := err.(*BlockValidateError); ok {
		return v.ValidateFailed()
	}
	return false
}

type MaliciousType int

const (
	MTDoubleSign            = MaliciousType(401) // signing for different blocks at the same height in the same chain
	MTDoubleAuditing        = MaliciousType(501) // double sign Audited and Revealed for the same block
	MTOneBlockMultiAuditing = MaliciousType(502) // Audited different blocks at the same height in the same chain
)

type MaliciousError struct {
	err error
	typ MaliciousType
}

func (m *MaliciousError) Error() string {
	return fmt.Sprintf("MaliciousError(%d): %v", m.typ, m.err)
}

func ToMalicious(err error, typ MaliciousType) error {
	if err == nil {
		return &MaliciousError{
			err: errors.New("empty malicious error"),
			typ: typ,
		}
	}
	if v, ok := err.(*MaliciousError); ok {
		return &MaliciousError{
			err: v.err,
			typ: typ,
		}
	}
	return &MaliciousError{
		err: err,
		typ: typ,
	}
}

func IsMalicious(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*MaliciousError)
	return ok
}

var PbftBlockNumer func(bn common.BlockNum) PbftBlockNum

type PbftBlockNum interface {
	ElectionStarted() bool
	NeedElection() bool
	EmitElection() bool
	SyncStarting() bool
	SyncStarted() bool
	SyncingOrSynced() bool
	IsSendVrf() bool
	JustBeforeElected() bool
	Elected() bool
	ElectionEnded() bool
	ShouldGenSeed() bool
}

type (
	ConsensusStage uint8

	ConsensusContext struct {
		ChainID   common.ChainID
		Stage     ConsensusStage
		Reviving  bool // reviving consensus
		Replaying bool // replaying blocks in data node
		Syncing   bool // syncing blocks for get world state of the chain
	}
)

const (
	CSProposing ConsensusStage = iota
	CSPreparing
	CSCommitting
)

func (s ConsensusStage) Proposing() bool {
	return s == CSProposing
}

func (s ConsensusStage) Preparing() bool {
	return s == CSPreparing
}

func (s ConsensusStage) Committing() bool {
	return s == CSCommitting
}

func (s ConsensusStage) String() string {
	switch s {
	case CSProposing:
		return "PROPOSING"
	case CSPreparing:
		return "PREPARING"
	case CSCommitting:
		return "COMMITTING"
	default:
		return "UNKNOWN-STAGE"
	}
}

func (s ConsensusStage) Short() string {
	switch s {
	case CSProposing:
		return "GEN"
	case CSPreparing:
		return "VER"
	case CSCommitting:
		return "CO"
	default:
		return "UA"
	}
}

func (ctx *ConsensusContext) String() string {
	if ctx == nil {
		return fmt.Sprintf("ConsCtx<nil>")
	}
	buf := new(bytes.Buffer)
	buf.WriteString("ConsCtx{")
	buf.WriteString(ctx.Stage.String())
	if ctx.Reviving {
		buf.WriteString(" REVIVING")
	}
	if ctx.Replaying {
		buf.WriteString(" REPLAYING")
	}
	if ctx.Syncing {
		buf.WriteString(" SYNCING")
	}
	buf.WriteByte('}')
	return buf.String()
}

func (ctx *ConsensusContext) RealTime() bool {
	return ctx != nil && ctx.Reviving == false && ctx.Replaying == false && ctx.Syncing == false
}

func (ctx *ConsensusContext) Restoring() bool {
	return ctx.Replaying || ctx.Syncing
}

func (ctx *ConsensusContext) SetProposing() *ConsensusContext {
	ctx.Stage = CSProposing
	return ctx
}

func (ctx *ConsensusContext) SetPreparing() *ConsensusContext {
	ctx.Stage = CSPreparing
	return ctx
}

func (ctx *ConsensusContext) SetCommitting() *ConsensusContext {
	ctx.Stage = CSCommitting
	return ctx
}
