package models

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/sirupsen/logrus"
)

type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	// Engine() consensus.Engine   //

	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *BlockHeader
}

// TODO: all callbacks should add a Context parameter to identify different event calls

// When the data block is generated, before or after the pooled transactions are executed, the
// callback function executed before the stateRoot is generated
// can be used to generate transactions outside of the transaction pool
// header: generating block header
// result: proposing data
type TxGenerateCallback func(ctx *ConsensusContext, header *BlockHeader, result *ProposeResult) (
	genTxs Txs, genPass PubAndSigs, err error)

// when the execution of the packaged transactions is completed, the callback method used to
// generate other data in block and header
type GenerateCallback func(ctx *ConsensusContext, header *BlockHeader, result *ProposeResult) error

// verify whether the transactions are generated correctly according to the block in the parameters
// and the number of transactions that have been processed so far
type TxVerifyCallback func(ctx *ConsensusContext, block *BlockEMessage, processed int) (
	genTxs Txs, genPass PubAndSigs, err error)

// The callback function executed after the transaction is executed when the data block is verified
// block: verifying block
type VerifyCallback func(ctx *ConsensusContext, block *BlockEMessage) error

// When the data block is confirmed, the callback function executed after the transaction is executed.
// At this time the block has been confirmed by the committee and all nodes must execute
type CommitCallback func(ctx *ConsensusContext, block *BlockEMessage) error

// StateDB is an EVM database for full state querying.
type StateDB interface {
	ChainID() common.ChainID
	// Whether there is a local currency, if so, the last one method will return the local currency
	// information. Otherwise, the latter one method return basic currency information
	HasLocalCurrency() bool
	GetChainLocalCurrencyInfo(chainID common.ChainID) (common.CoinID, string)
	// Get the list of administrator public keys of the current chain. If there is a valid value,
	// the second return value will return true, otherwise it will return false
	GetAdmins() ([][]byte, bool)
	ResetState(stateTrie *trie.Trie)

	CreateAccount(common.Address, *common.Address)
	Account(addr common.Address) *Account

	HasToken(addr common.Address) bool

	NoBalance(addr common.Address) bool
	SubBalance(common.Address, *big.Int) bool
	AddBalance(common.Address, *big.Int)
	GetBalance(common.Address) *big.Int

	NoLocalCurrency(addr common.Address) bool
	SubLocalCurrency(common.Address, *big.Int) bool
	AddLocalCurrency(common.Address, *big.Int)
	GetLocalCurrency(common.Address) *big.Int

	CanTransfer(addr common.Address, useLocal bool, amount *big.Int) bool
	Transfer(sender, recipient common.Address, useLocal bool, amount *big.Int) (ok bool)

	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)

	GetCodeHash(common.Address) common.Hash
	GetCode(common.Address) []byte
	SetCode(common.Address, []byte)
	GetCodeByHash(codeHash common.Hash) []byte
	GetCodeSize(common.Address) int

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)

	GetLong(addr common.Address, key common.Hash) []byte
	GetConsistantLong(addr common.Address, key common.Hash) []byte
	SetLong(addr common.Address, key common.Hash, value []byte)

	GetLongAsObject(addr common.Address, key common.Hash, obj interface{}) error
	SetLongAsObject(addr common.Address, key common.Hash, obj interface{}) error

	Suicide(common.Address) bool
	HasSuicided(common.Address) bool

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for suicided accounts.
	Exist(common.Address) bool
	Empty(common.Address) bool

	ClearObjectCache()

	RevertToSnapshot(int)
	Snapshot() int

	AddLog(common.Hash, uint, *Log)
	AddPreimage(common.Hash, []byte)

	GetOrNewStateObject(addr common.Address) AccountState

	GetLogs(hash common.Hash) []*Log

	// Finalise(deleteEmptyObjects bool)

	Propose(ctx *ConsensusContext, froms DeltaFroms, deltaTrie *AccountDeltaTrie, txs []*Transaction, pas []*PubAndSig,
		header *BlockHeader, result *ProposeResult, txGens []TxGenerateCallback, afters []GenerateCallback) (err error)
	Prepare(ctx *ConsensusContext, block *BlockEMessage, txVerifis []TxVerifyCallback, verifies []VerifyCallback) error
	Commit(ctx *ConsensusContext, block *BlockEMessage, txVerifis []TxVerifyCallback,
		verifies []VerifyCallback, commits []CommitCallback) error

	RestoreDeltasLocked()
	ListAllDeltaFroms() DeltaFroms
	PutAllDeltaFroms(deltaFroms DeltaFroms)
	SyncWaterlines(waterlines []ShardWaterline, logger logrus.FieldLogger)
	GetDeltaToBeSent() common.Height
	SetDeltaToBeSent(height common.Height)
	ProposeWaterlines() (Waterlines, error)

	GetOriginHash() ([]byte, error)
	DeltasSnapShot() []ShardWaterline
	SaveReceivedDelta(fromID common.ChainID, height common.Height, deltas []*AccountDelta) (
		overflow bool, waterline common.Height, overflowed []*DeltaFrom, missing bool,
		missingLength int, err error)
	SaveDeltasGroup(fromID common.ChainID, group DeltasGroup) (overflow bool,
		waterline common.Height, overflowed []*DeltaFrom, missing bool, missingLength int, err error)
	GetWaterLine(fromID common.ChainID) common.Height
	PopDeltaFroms() DeltaFroms
	ReadOnlyCall(tx *Transaction, senderSig *PubAndSig, blockHeader *BlockHeader) (interface{}, error)
	ReadOnly() StateDB
	ForceCommit() error
	GetOriginAccount(addr common.Address) (*Account, bool)
	CreateTestAccount(addr common.Address, balance *big.Int) error
	Rollback()
	GetSettingGasLimit(tx *Transaction) uint64
	GetSettingGasPrice(tx *Transaction) *big.Int
	Estimate(tx *Transaction, header *BlockHeader) (uint64, error)
	Simulating() bool
	IsReadOnly() bool
}

type AccountState interface {
	Address() common.Address
	GetAccount() *Account
}
type (
	cipherer struct {
		priv, pub []byte
	}

	identity struct {
		cipherer
		addr common.Address
	}

	nodeIdentity struct {
		cipherer
		nodeid common.NodeID
	}
)

func (c cipherer) Priv() []byte {
	return common.CopyBytes(c.priv)
}

func (c cipherer) Pub() []byte {
	return common.CopyBytes(c.pub)
}

func (id *identity) Address() common.Address {
	return id.addr
}

func (id *identity) AddressP() *common.Address {
	a := id.addr
	return &a
}

func (id *identity) String() string {
	if id == nil {
		return "ID<nil>"
	}
	return fmt.Sprintf("ID{Addr:%s}", id.addr)
}

func (n *nodeIdentity) NodeID() common.NodeID {
	return n.nodeid
}

func (n *nodeIdentity) NodeIDP() *common.NodeID {
	a := n.nodeid
	return &a
}

func (n *nodeIdentity) String() string {
	if n == nil {
		return "NID<nil>"
	}
	return fmt.Sprintf("NID{NodeID:%s}", n.nodeid)
}

func NewIdentifier(priv []byte) (common.Identifier, error) {
	pub, err := PrivateToPublicSlice(priv)
	if err != nil {
		return nil, err
	}
	addr, err := common.AddressFromPubSlice(pub)
	if err != nil {
		return nil, err
	}
	return &identity{
		cipherer: cipherer{
			priv: priv,
			pub:  pub,
		},
		addr: addr,
	}, nil
}

func NewIdentifierByHex(privHexString string) (common.Identifier, error) {
	p, err := hex.DecodeString(privHexString)
	if err != nil {
		return nil, err
	}
	return NewIdentifier(p)
}

func NewIdentifierByHexWithoutError(privHexString string) common.Identifier {
	id, err := NewIdentifierByHex(privHexString)
	if err != nil {
		panic(err)
	}
	return id
}

func NewNodeIdentifier(priv []byte) (common.NodeIdentifier, error) {
	pub, err := PrivateToPublicSlice(priv)
	if err != nil {
		return nil, err
	}
	nid, err := PubToNodeID(pub)
	if err != nil {
		return nil, err
	}
	return &nodeIdentity{
		cipherer: cipherer{
			priv: priv,
			pub:  pub,
		},
		nodeid: nid,
	}, nil
}

func NewNodeIdentifierByHex(privHexString string) (common.NodeIdentifier, error) {
	p, err := hex.DecodeString(privHexString)
	if err != nil {
		return nil, err
	}
	return NewNodeIdentifier(p)
}

func NewNodeIdentifierByHexWithoutError(privHexString string) common.NodeIdentifier {
	ni, err := NewNodeIdentifierByHex(privHexString)
	if err != nil {
		panic(err)
	}
	return ni
}

type Accounts []*Account

func (a Accounts) Len() int {
	return len(a)
}

func (a Accounts) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a Accounts) Less(i, j int) bool {
	if a[i] == nil || a[j] == nil {
		if a[i] == a[j] {
			return false
		} else if a[i] == nil {
			return true
		} else {
			return false
		}
	}
	return bytes.Compare(a[i].Addr[:], a[j].Addr[:]) < 0
}

type EntryHashHash struct {
	K common.Hash
	V common.Hash
}

type StorageEntry struct {
	All int
	Num int
	K   common.Hash
	V   []EntryHashHash
}

func (e StorageEntry) Count() int {
	return len(e.V)
}

type StorageEntries []StorageEntry

func (es StorageEntries) String() string {
	if len(es) == 0 {
		return "0"
	}
	sum, max := 0, 0
	for _, entry := range es {
		c := entry.Count()
		if c > 0 {
			sum += c
			if c > max {
				max = c
			}
		}
	}
	return fmt.Sprintf("(Count:%d Sum:%d Max:%d)", len(es), sum, max)
}

type CodeEntry struct {
	K common.Hash
	V []byte
}

type LongEntry struct {
	K common.Hash
	V []*LongValue
}
