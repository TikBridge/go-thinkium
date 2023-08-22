package tkmrpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/stephenfire/go-rtl"
)

type (
	AccountChange struct {
		TxHash    *common.Hash      `json:"txhash,omitempty"`
		ChainID   common.ChainID    `json:"chainid"`   // Chain ID of from. When from is empty, it is the chain ID of delta.
		Height    common.Height     `json:"height"`    // Block height of the chain in which the transaction is executed
		From      *common.Address   `json:"from"`      // When the account change is delta, from is empty. Otherwise, it is the transfer out account address
		To        *common.Address   `json:"to"`        // Transfer in account address
		Nonce     uint64            `json:"nonce"`     // Nonce when a transfer out account performs a transaction. This value is meaningless when the account changes to delta.
		Val       *big.Int          `json:"value"`     // Account change amount
		Input     hexutil.Bytes     `json:"input"`     // Transaction input information
		UseLocal  bool              `json:"uselocal"`  // Is it a second currency transaction? False: base currency, true: second currency
		Extra     hexutil.Bytes     `json:"extra"`     // It is currently used to save transaction types. If it does not exist, it is a normal transaction. Otherwise, it will correspond to special operations
		Version   uint16            `json:"version"`   // Version number used to distinguish different execution methods when the transaction execution is incompatible due to upgrade
		TimeStamp uint64            `json:"timestamp"` // The timestamp of the block in which it is located
		Hash      []byte            `json:"hash"`      // transaction hash
		MultiSigs models.PubAndSigs `json:"multiSigs"`
		Sig       *models.PubAndSig `json:"signature"`
	}

	AccountChanges []*AccountChange

	AccountWithCode struct {
		Addr            common.Address  `json:"address"`         // Address of account
		Creator         *common.Address `json:"creator"`         // creator of the contract
		Nonce           uint64          `json:"nonce"`           // Nonce of account
		Balance         *big.Int        `json:"balance"`         // Base currency，can't be nil
		LocalCurrency   *big.Int        `json:"localCurrency"`   // Second currency（if exists），could be nil
		StorageRoot     []byte          `json:"storageRoot"`     // Storage root of contract，Trie(key: Hash, value: Hash)
		CodeHash        []byte          `json:"codeHash"`        // Hash of contract code
		LongStorageRoot []byte          `json:"longStorageRoot"` // System contracts are used to hold more flexible data structures, Trie(key: Hash, value: []byte)
		Code            []byte          `json:"code"`
	}

	AccountHeight struct {
		Height          common.Height  `json:"height"`          // Current height of chain
		Addr            common.Address `json:"address"`         // Address of account
		Nonce           uint64         `json:"nonce"`           // Nonce of account
		Balance         *big.Int       `json:"balance"`         // Base currency，can't be nil
		LocalCurrency   *big.Int       `json:"localCurrency"`   // Second currency（if exists），could be nil
		StorageRoot     []byte         `json:"storageRoot"`     // Storage root of contract，Trie(key: Hash, value: Hash)
		CodeHash        []byte         `json:"codeHash"`        // Hash of contract code
		LongStorageRoot []byte         `json:"longStorageRoot"` // System contracts are used to hold more flexible data structures, Trie(key: Hash, value: []byte)
		Code            []byte         `json:"code"`
	}

	BlockMessage struct {
		Elections      []*models.ElectMessage `json:"elections"`      // start election msg
		AccountChanges []*AccountChange       `json:"accountchanges"` // transaction
	}

	TransactionReceipt struct {
		Transaction     *models.Transaction `json:"tx"`                                  // Transaction data object
		Sig             *models.PubAndSig   `json:"signature"`                           // transaction signature
		PostState       []byte              `json:"root"`                                // It is used to record the information of transaction execution in JSON format, such as gas, cost "gas", and world state "root" after execution.
		Status          uint64              `json:"status"`                              // Transaction execution status, 0: failed, 1: successful. (refers to whether the execution is abnormal)
		Logs            []*models.Log       `json:"logs" gencodec:"required"`            // The log written by the contract during execution
		GasBonuses      []*models.Bonus     `json:"gasBonuses"`                          // gas bonuses if the tx is a contract call
		TxHash          common.Hash         `json:"transactionHash" gencodec:"required"` // Transaction Hash
		ContractAddress common.Address      `json:"contractAddress"`                     // If you are creating a contract, save the address of the created contract here
		Out             hexutil.Bytes       `json:"out"`                                 // Return value of contract execution
		Height          common.Height       `json:"blockHeight"`                         // The block where the transaction is packaged is high and will not be returned when calling
		GasUsed         uint64              `json:"gasUsed"`                             // The gas value consumed by transaction execution is not returned in call
		GasFee          string              `json:"gasFee"`                              // The gas cost of transaction execution is not returned in call
		PostRoot        []byte              `json:"postroot"`                            // World state root after transaction execution (never return, always empty)
		Error           string              `json:"errorMsg"`                            // Error message in case of transaction execution failure
		Param           []byte              `json:"txParam"`                             // tx param generated by block proposer
	}

	TxReceipts []*TransactionReceipt

	RRTx struct {
		TxReceipt *TransactionReceipt
		RRReceipt *models.RRActReceipt
	}

	MerkleItem struct {
		HashVal   hexutil.Bytes `json:"hash"`
		Direction uint8         `json:"direction"`
	}

	MerkleItems []MerkleItem

	TxProof struct {
		TransactionReceipt
		Proof MerkleItems `json:"proof"`
	}

	BlockInfo struct {
		Hash             common.Hash    `json:"hash"`          // Big hash, that is, big hash
		PreviousHash     common.Hash    `json:"previoushash"`  // Hash of last block
		ChainID          common.ChainID `json:"chainid"`       // Current chain ID
		Height           common.Height  `json:"height"`        // Block height
		Empty            bool           `json:"empty"`         // Whether it is an empty block, that is, whether it is a skipped block
		RewardAddress    common.Address `json:"rewardaddress"` // The reward address bound to the packing node (it can be any value, and the basis for issuing rewards is in the reward chain pledge contract, not depending on this value)
		MergedDeltaRoot  *common.Hash   `json:"mergeroot"`     // Root hash of delta merged from other partitions
		BalanceDeltaRoot *common.Hash   `json:"deltaroot"`     // The root hash of the delta tree generated by the current block transaction of the current partition needs to be sent to other partitions
		StateRoot        common.Hash    `json:"stateroot"`     // Hash root of the chain account
		RREra            *common.EraNum `json:"rrera"`         // Charging cycle of current block (main chain and reward chain)
		RRCurrent        *common.Hash   `json:"rrcurrent"`     // Pledge tree root hash (main chain and reward chain) when the current block is located
		RRNext           *common.Hash   `json:"rrnext"`        // Pledge tree root hash (main chain and reward chain) in the next billing cycle
		TxCount          int            `json:"txcount"`       // Transaction count in block
		TimeStamp        uint64         `json:"timestamp"`     // The time stamp of Proposer proposal can not be used as a basis
	}

	NodeInfo struct {
		NodeId        common.NodeID                    `json:"nodeId"`
		Version       string                           `json:"version"`
		IsDataNode    bool                             `json:"isDataNode"`
		DataNodeOf    common.ChainID                   `json:"dataNodeOf"`
		LastMsgTime   int64                            `json:"lastMsgTime"`
		LastEventTime int64                            `json:"lastEventTime"`
		LastBlockTime int64                            `json:"lastBlockTime"`
		Overflow      bool                             `json:"overflow"`
		LastBlocks    map[common.ChainID]common.Height `json:"lastBlocks"`
		OpTypes       map[common.ChainID][]string      `json:"opTypes"`
	}

	// information of a chain
	ChainInfo struct {
		ChainId   common.ChainID   `json:"chainId"`   // Chain ID
		Mode      common.ChainMode `json:"mode"`      // Root？Branch？Shard？
		ParentId  common.ChainID   `json:"parent"`    // Parent chain
		DataNodes []DataNodeInfo   `json:"datanodes"` // Data node list
	}

	DataNodeInfo struct {
		DataNodeId   common.NodeID `json:"dataNodeId"`   // Node ID
		DataNodeIp   string        `json:"dataNodeIp"`   // IP
		DataNodePort uint16        `json:"dataNodePort"` // RPC port
	}

	CashedCheckExistence struct {
		Existence bool   `json:"existence"` // Check exists in cashed tree and can be cancelled if it does not exist (other conditions must be met)
		Input     string `json:"input"`     // The data to be provided when canceling a check is the serialization of cancelcashcheckrequest
	}

	RRNodeInfo struct {
		Era                                  common.EraNum
		Root                                 common.Hash
		Info                                 *models.RRInfo
		Changing                             *models.RRC
		MaxDeposit                           *big.Int
		ConsDepSum, DelegatedSum, DataDepSum *big.Int
	}

	BTxs struct {
		Txs   TxReceipts
		Start common.Height
		End   common.Height
	}

	BlockWithAuditings struct {
		BlockHeader *models.BlockHeader
		BlockBody   *models.BlockBody
		BlockPass   models.PubAndSigs
		Auditings   models.AuditorPass
	}

	RRNodeChanging struct {
		Info     *models.RRInfo
		Changing *models.RRC
	}

	RRNodeChangings []*RRNodeChanging

	RRChanges struct {
		Era          common.EraNum
		Root         common.Hash
		Next         common.Hash
		Changing     common.Hash
		MaxDeposit   *big.Int
		ConsDepSum   *big.Int
		DelegatedSum *big.Int
		DataDepSum   *big.Int
		Changes      RRNodeChangings
	}

	Confirmeds struct {
		At   common.Height
		Root []byte
		Data models.ChainConfirmeds
	}
)

func (r *TransactionReceipt) Reset() {
	if r == nil {
		return
	}
	r.Transaction = nil
	r.Sig = nil
	r.PostState = nil
	r.Status = 0
	r.Logs = nil
	r.TxHash = common.Hash{}
	r.ContractAddress = common.Address{}
	r.Out = nil
	r.Height = 0
	r.GasUsed = 0
	r.GasFee = ""
	r.PostRoot = nil
	r.Error = ""
}

func (r *TransactionReceipt) Parse(outputParser func(out []byte) error, logParsers ...func(logs []*models.Log) error) error {
	if r == nil {
		return errors.New("nil receipt")
	}
	fmt.Println(r.InfoString(0))
	if r.Status == models.ReceiptStatusSuccessful {
		if outputParser != nil {
			if err := outputParser(r.Out); err != nil {
				return err
			}
		}
		if len(logParsers) > 0 && logParsers[0] != nil {
			if err := logParsers[0](r.Logs); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%s", r.Error)
}

func (r *TransactionReceipt) PartReceipt(tx *models.Transaction, pas *models.PubAndSig, rpt *models.Receipt) *TransactionReceipt {
	tr := r
	if r == nil {
		tr = new(TransactionReceipt)
	} else {
		r.Reset()
	}
	tr.Transaction = tx
	tr.Sig = pas.Clone()
	if rpt == nil {
		return tr
	}
	tr.PostState = rpt.PostState
	tr.Status = rpt.Status
	tr.Logs = rpt.Logs
	tr.GasBonuses = rpt.GasBonuses
	tr.TxHash = rpt.TxHash
	if rpt.ContractAddress != nil {
		tr.ContractAddress = *(rpt.ContractAddress)
	}
	tr.Out = rpt.Out
	tr.GasUsed = rpt.GasUsed
	tr.GasFee = rpt.GasFeeString()
	tr.PostRoot = rpt.GetPostRoot()
	tr.Error = rpt.Error
	return tr
}

func (r *TransactionReceipt) FullReceipt(tx *models.Transaction, pas *models.PubAndSig, blockHeight common.Height,
	rpt *models.Receipt) *TransactionReceipt {
	tr := r
	if r == nil {
		tr = new(TransactionReceipt)
	} else {
		r.Reset()
	}
	tr.Transaction = tx
	tr.Sig = pas.Clone()
	tr.Height = blockHeight
	if rpt == nil {
		return tr
	}
	tr.PostState = rpt.PostState
	tr.Status = rpt.Status
	tr.Logs = rpt.Logs
	tr.GasBonuses = rpt.GasBonuses
	tr.TxHash = rpt.TxHash
	if rpt.ContractAddress != nil {
		tr.ContractAddress = *(rpt.ContractAddress)
	}
	tr.Out = rpt.Out
	tr.GasUsed = rpt.GasUsed
	tr.GasFee = rpt.GasFeeString()
	tr.PostRoot = rpt.GetPostRoot()
	tr.Error = rpt.Error
	return tr
}

func (r *TransactionReceipt) Revert() []byte {
	if r.Error != models.ErrExecutionReverted.Error() {
		return nil
	}
	return common.CopyBytes(r.Out)
}

func (r *TransactionReceipt) RevertError() error {
	return models.NewRevertError(r.Revert())
}

func (r *TransactionReceipt) Success() bool {
	return r.Status == models.ReceiptStatusSuccessful
}

func (r *TransactionReceipt) Err() error {
	if r.Success() {
		return nil
	}
	if r.Error == "" {
		return nil
	}
	if r.Error == models.ErrExecutionReverted.Error() {
		return models.NewRevertError(common.CopyBytes(r.Out))
	} else {
		return errors.New(r.Error)
	}
}

func (r *TransactionReceipt) InfoString(level common.IndentLevel) string {
	base := level.IndentString()
	if r == nil {
		return "RPT<nil>"
	}
	next := level + 1
	indent := next.IndentString()
	outputStr := fmt.Sprintf("\n%sOut: %x", indent, []byte(r.Out))
	if r.Transaction != nil && models.SysContractLogger.Has(r.Transaction.To) && len(r.Transaction.Input) > 0 {
		outputStr += fmt.Sprintf("\n%sreturn: %s", indent,
			models.SysContractLogger.ReturnsString(*(r.Transaction.To), r.Transaction.Input, r.Out))
	}
	errStr := fmt.Sprintf("\n%sError: %s", indent, r.Error)
	if revertMsg := r.Revert(); len(revertMsg) > 0 {
		errStr += fmt.Sprintf(" (%s)", r.RevertError().Error())
	}
	txparamStr := ""
	if len(r.Param) > 0 {
		txparam := new(models.TxParam)
		if err := rtl.Unmarshal(r.Param, txparam); err == nil {
			txparamStr = fmt.Sprintf("\n%sTxParam: %s", indent, txparam.InfoString(level+1))
		}
	}
	return fmt.Sprintf("RPT{"+
		"\n%sTx: %s"+
		"\n%sSignature: %s"+
		"\n%sPostState: %s"+
		"\n%sStatus: %d"+
		"\n%sLogs: %s"+
		"\n%sGasBonuses: %s"+
		"\n%sTxHash: %x"+
		"\n%sContractAddress: %x"+
		"%s"+
		"\n%sHeight: %s"+
		"\n%sGasUsed: %d"+
		"\n%sGasFee: %s"+
		"%s"+
		"\n%sParam: %x%s"+
		"\n%s}",
		indent, r.Transaction.InfoString(level+1),
		indent, r.Sig.InfoString(level+1),
		indent, string(r.PostState),
		indent, r.Status,
		indent, next.InfoString(r.Logs),
		indent, next.InfoString(r.GasBonuses),
		indent, r.TxHash[:],
		indent, r.ContractAddress[:],
		outputStr,
		indent, &(r.Height),
		indent, r.GasUsed,
		indent, math.BigStringForPrint(r.GasFee),
		errStr,
		indent, r.Param, txparamStr,
		base)
}

func (r *TransactionReceipt) String() string {
	return r.InfoString(0)
}

func (ts TxReceipts) InfoString(level common.IndentLevel) string {
	return level.InfoString(ts)
}

func (t *RRTx) InfoString(level common.IndentLevel) string {
	if t == nil {
		return "RRTx<nil>"
	}
	base := level.IndentString()
	indent := (level + 1).IndentString()
	return fmt.Sprintf("RRTx{"+
		"\n%sTx: %s"+
		"\n%sRR: %s"+
		"\n%s}",
		indent, t.TxReceipt.InfoString(level+1),
		indent, t.RRReceipt.InfoString(level+1),
		base)
}

func (m MerkleItem) String() string {
	return fmt.Sprintf("Merkle{Hash:%x Direction:%d}", []byte(m.HashVal), m.Direction)
}

func (m MerkleItem) Proof(toBeProof []byte) ([]byte, error) {
	order := true
	if m.Direction != 0 {
		order = false
	}
	return common.HashPairOrder(order, m.HashVal, toBeProof)
}

func (ms MerkleItems) InfoString(level common.IndentLevel) string {
	return level.InfoString(ms)
}

func (ms MerkleItems) Proof(toBeProof []byte) ([]byte, error) {
	r := toBeProof
	var err error
	for _, item := range ms {
		r, err = item.Proof(r)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (t *TxProof) InfoString(level common.IndentLevel) string {
	if t == nil {
		return "TxProof<nil>"
	}
	base := level.IndentString()
	indent := level + 1
	return fmt.Sprintf("TxProof{"+
		"\n%s\t%s"+
		"\n%s\tProof: %s"+
		"\n%s}",
		base, t.TransactionReceipt.InfoString(indent),
		base, t.Proof.InfoString(indent),
		base)
}

func (c *AccountChange) String() string {
	return c.InfoString(0)
}

func (c *AccountChange) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "Tx<nil>"
	}
	tx := &models.Transaction{
		ChainID:   c.ChainID,
		From:      c.From,
		To:        c.To,
		Nonce:     c.Nonce,
		UseLocal:  c.UseLocal,
		Val:       c.Val,
		Input:     c.Input,
		Extra:     c.Extra,
		Version:   c.Version,
		MultiSigs: c.MultiSigs,
	}
	base := level.IndentString()
	return fmt.Sprintf("TxHash: %x"+
		"\n%s%s\n%s%s",
		common.ForPrint(c.TxHash, 0, -1),
		base, tx.InfoString(level), base, c.Sig.InfoString(level))
}

func (cs AccountChanges) InfoString(level common.IndentLevel) string {
	return level.InfoString(cs)
}

func (c *AccountWithCode) String() string {
	return c.InfoString(0)
}

func (c *AccountWithCode) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "Acc<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("Acc{"+
		"\n%s\tAddr: %x"+
		"\n%s\tCreator: %x"+
		"\n%s\tNonce: %d"+
		"\n%s\tBalance: %s"+
		"\n%s\tLocal: %s"+
		"\n%s\tStorageRoot: %x"+
		"\n%s\tCodeHash: %x"+
		"\n%s\tLongStorageRoot: %x"+
		"\n%s\tCode: %x"+
		"\n%s}",
		base, c.Addr[:],
		base, common.ForPrint(c.Creator, 0, -1),
		base, c.Nonce,
		base, math.BigForPrint(c.Balance),
		base, math.BigForPrint(c.LocalCurrency),
		base, c.StorageRoot,
		base, c.CodeHash,
		base, c.LongStorageRoot,
		base, c.Code,
		base)
}

func (m *BlockMessage) String() string {
	return m.InfoString(0)
}

func (m *BlockMessage) InfoString(level common.IndentLevel) string {
	if m == nil {
		return "Msg<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("Msg{"+
		"\n%s\tElections: %s"+
		"\n%s\tTxs: %s"+
		"\n%s}",
		base, models.ElectMessages(m.Elections).InfoString(level+1),
		base, AccountChanges(m.AccountChanges).InfoString(level+1),
		base)
}

func (m *RpcAddress) PrintString() string {
	if m == nil {
		return "RpcAddress{nil}"
	}
	return fmt.Sprintf("RpcAddress{%d:%x}", m.Chainid, m.Address)
}

func (x *RpcAddress) MarshalJSON() ([]byte, error) {
	type ra struct {
		Cid  uint32 `json:"chainid"`
		Addr string `json:"address"`
	}
	r := ra{
		Cid:  x.Chainid,
		Addr: hexutil.Encode(x.Address),
	}
	return json.Marshal(r)
}

func (x *RpcTx) PrintString() string {
	return fmt.Sprintf("RpcTx{Chainid:%d From:%s To:%s Nonce:%d Val:%s len(Input):%d Local:%t len(Extra):%d}",
		x.Chainid, x.From.PrintString(), x.To.PrintString(), x.Nonce, x.Val, len(x.Input), x.Uselocal, len(x.Extra))
}

func (x *RpcTx) InfoString(level common.IndentLevel) string {
	if x == nil {
		return "RpcTx<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("RpcTx {"+
		"\n\t%sChainID: %d"+
		"\n\t%sFrom: %s"+
		"\n\t%sTo: %s"+
		"\n\t%sNonce: %d"+
		"\n\t%sVal: %s"+
		"\n\t%sInput: %x"+
		"\n\t%sPub: %x"+
		"\n\t%sSig: %x"+
		"\n\t%sUselocal: %t"+
		"\n\t%sExtra: %x"+
		"\n\t%sMultipubs: %s"+
		"\n\t%sMultisigs: %s"+
		"\n%s}",
		base, x.Chainid,
		base, x.From.PrintString(),
		base, x.To.PrintString(),
		base, x.Nonce,
		base, math.BigStringForPrint(x.Val),
		base, x.Input,
		base, x.Pub,
		base, x.Sig,
		base, x.Uselocal,
		base, x.Extra,
		base, level.DoubleByteSlice(x.Multipubs),
		base, level.DoubleByteSlice(x.Multisigs),
		base)
}

func (x *RpcTx) HashValue() ([]byte, error) {
	if tx, err := x.ToTx(); err != nil {
		return nil, err
	} else {
		return tx.HashValue()
	}
}

func (x *RpcTx) GetSignature() *models.PubAndSig {
	if x == nil {
		return nil
	}
	return &models.PubAndSig{PublicKey: x.Pub, Signature: x.Sig}
}

func (x *RpcTx) ToTx() (*models.Transaction, error) {
	if x == nil {
		return nil, common.ErrNil
	}
	var from, to *common.Address
	if x.From != nil && len(x.From.Address) > 0 {
		if len(x.From.Address) != common.AddressLength {
			return nil, errors.New("illegal from address")
		}
		from = common.BytesToAddressP(x.From.Address)
	} else {
		from = new(common.Address)
	}
	if x.To != nil && len(x.To.Address) > 0 {
		if len(x.To.Address) != common.AddressLength {
			return nil, errors.New("illegal to address")
		}
		to = common.BytesToAddressP(x.To.Address)
	}
	var val *big.Int
	if len(x.Val) > 0 {
		var ok bool
		if val, ok = math.ParseBig256(x.Val); !ok {
			return nil, errors.New("invalid value")
		}
	}
	var msigs models.PubAndSigs
	var err error
	if msigs, err = msigs.FromPubsAndSigs(x.Multipubs, x.Multisigs); err != nil {
		return nil, err
	}
	tx := &models.Transaction{
		ChainID:   common.ChainID(x.Chainid),
		From:      from,
		To:        to,
		Nonce:     x.Nonce,
		UseLocal:  x.Uselocal,
		Val:       val,
		Input:     common.CopyBytes(x.Input),
		Extra:     nil,
		Version:   models.TxVersion,
		MultiSigs: msigs,
	}
	// generate tx.extra
	if len(x.Sig) == cipher.RealCipher.LengthOfSignature() || len(x.Extra) > 0 {
		extras := &models.Extra{Type: models.LegacyTxType}
		if len(x.Sig) == cipher.RealCipher.LengthOfSignature() {
			r, s, v, err := models.ETHSigner.SignatureValues(tx.ETHChainID(), models.LegacyTxType, x.Sig)
			if err != nil {
				return nil, err
			}
			extras.R = r
			extras.S = s
			extras.V = v
		}
		if err := tx.SetExtraKeys(extras); err != nil {
			return nil, err
		}
		if len(x.Extra) > 0 {
			if err := tx.SetTkmExtra(x.Extra); err != nil {
				return nil, err
			}
		}
	}

	if len(x.Sig) == cipher.RealCipher.LengthOfSignature() {
		if err := tx.VerifySig(&models.PubAndSig{PublicKey: x.Pub, Signature: x.Sig}); err != nil {
			return nil, fmt.Errorf("tx verify failed: %v", err)
		}
	}
	return tx, nil
}

func (x *RpcTx) FromTx(tx *models.Transaction, pas ...*models.PubAndSig) (rtx *RpcTx, err error) {
	if tx == nil {
		return nil, nil
	}
	rtx = new(RpcTx)
	rtx.Chainid = uint32(tx.ChainID)
	if tx.From != nil {
		rtx.From = &RpcAddress{Chainid: uint32(tx.ChainID), Address: tx.From.Clone().Bytes()}
	}
	if tx.To != nil {
		rtx.To = &RpcAddress{Chainid: uint32(tx.ChainID), Address: tx.To.Clone().Bytes()}
	}
	rtx.Nonce = tx.Nonce
	rtx.Val = (*math.BigInt)(tx.Val).MustInt().String()
	rtx.Input = common.CopyBytes(tx.Input)
	var ps *models.PubAndSig
	if len(pas) == 0 || pas[0] == nil {
		ps, err = tx.GetSignature()
		if err != nil {
			return nil, err
		}
	} else {
		ps = pas[0]
	}
	if ps != nil {
		rtx.Pub = common.CopyBytes(ps.PublicKey)
		rtx.Sig = common.CopyBytes(ps.Signature)
	}
	rtx.Uselocal = tx.UseLocal
	rtx.Extra, err = tx.ExtraKeys().GetTkmExtra()
	if err != nil {
		return nil, err
	}
	if len(tx.MultiSigs) > 0 {
		for _, p := range tx.MultiSigs {
			if p != nil {
				rtx.Multipubs = append(rtx.Multipubs, common.CopyBytes(p.PublicKey))
				rtx.Multisigs = append(rtx.Multisigs, common.CopyBytes(p.Signature))
			}
		}
	}
	return rtx, nil
}

func (m *RpcCashCheck) ToCashCheck() (*models.CashCheck, error) {
	if m == nil {
		return nil, nil
	}
	if m.From == nil || m.To == nil {
		return nil, common.ErrNil
	}
	amount := new(big.Int)
	amount, ok := big.NewInt(0).SetString(m.Amount, 10)
	if !ok {
		return nil, errors.New("illegal amount")
	}
	return &models.CashCheck{
		ParentChain:  common.ChainID(m.ParentChain),
		IsShard:      m.IsShard,
		FromChain:    common.ChainID(m.From.Chainid),
		FromAddress:  common.BytesToAddress(m.From.Address),
		Nonce:        m.Nonce,
		ToChain:      common.ChainID(m.To.Chainid),
		ToAddress:    common.BytesToAddress(m.To.Address),
		ExpireHeight: common.Height(m.ExpireHeight),
		Amount:       amount,
		UserLocal:    m.Uselocal,
		CurrencyID:   common.CoinID(m.CurrencyId),
	}, nil
}

func (m *RpcCashCheck) FromCashCheck(vcc *models.CashCheck) error {
	if vcc == nil {
		return common.ErrNil
	}
	m.ParentChain = uint32(vcc.ParentChain)
	m.IsShard = vcc.IsShard
	m.From = &RpcAddress{Chainid: uint32(vcc.FromChain), Address: vcc.FromAddress[:]}
	m.To = &RpcAddress{Chainid: uint32(vcc.ToChain), Address: vcc.ToAddress[:]}
	m.Nonce = vcc.Nonce
	m.ExpireHeight = uint64(vcc.ExpireHeight)
	m.Amount = "0"
	if vcc.Amount != nil {
		m.Amount = vcc.Amount.String()
	}
	m.Uselocal = vcc.UserLocal
	m.CurrencyId = int32(vcc.CurrencyID)
	return nil
}

func (b *BlockInfo) String() string {
	if jsons, err := json.Marshal(b); err != nil {
		return "!!!json marshal failed!!!"
	} else {
		return string(jsons)
	}
}

func (m *RpcRRProofReq) HashValue() ([]byte, error) {
	hasher := cipher.RealCipher.Hasher()
	if _, err := m.HashSerialize(hasher); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (m *RpcRRProofReq) HashSerialize(w io.Writer) (int, error) {
	str := []string{
		common.ChainID(m.ChainId).String(),
		hex.EncodeToString(m.RootHash),
		hex.EncodeToString(m.NodeHash),
	}
	// Multiple non fixed length bytes links must have a separator, otherwise the combination of different chains + era will have the same serialization
	p := strings.Join(str, ",")
	return w.Write([]byte(p))
}

func (m *RpcRRProofReq) Verify() error {
	nid, err := models.PubToNodeID(m.Pub)
	if err != nil {
		return err
	}
	nidh := nid.Hash()
	if !bytes.Equal(nidh[:], m.NodeHash) {
		return fmt.Errorf("public key and NodeIDHash not match")
	}
	objectHash, err := common.HashObject(m)
	if err != nil {
		return fmt.Errorf("hash object failed: %v", err)
	}
	if !models.VerifyHash(objectHash, m.Pub, m.Sig) {
		return fmt.Errorf("signature verfiy failed")
	}
	return nil
}

func (m *RRNodeInfo) String() string {
	if m == nil {
		return "RRNodeInfo<nil>"
	}
	indentLevel := common.IndentLevel(0)
	indent := (indentLevel + 1).IndentString()
	return fmt.Sprintf("RRNodeInfo{"+
		"\n%sEra: %s"+
		"\n%sRoot: %x"+
		"\n%sMaxDeposit: %s"+
		"\n%sConsDepSum: %s"+
		"\n%sDelegatedSum: %s"+
		"\n%sDataDepSum: %s"+
		"\n%sInfo: %s"+
		"\n%sCurrentChanging: %s"+
		"\n}",
		indent, &(m.Era),
		indent, m.Root[:],
		indent, math.BigForPrint(m.MaxDeposit),
		indent, math.BigForPrint(m.ConsDepSum),
		indent, math.BigForPrint(m.DelegatedSum),
		indent, math.BigForPrint(m.DataDepSum),
		indent, m.Info.InfoString(indentLevel+1),
		indent, m.Changing.InfoString(indentLevel+1),
	)
}

type RpcCommProof struct {
	ChainID common.ChainID
	// epoch where committee used
	Epoch common.EpochNum
	// block height where committee pronounced, ({Height}.EpochNum()+1)=={Epoch}
	Height common.Height
	// block hash of height
	HashOfHeader []byte
	// committee node id list of {Epoch}
	Committee *models.Committee
	// signature list of block
	Pass models.PubAndSigs
	// proof from header.ElectedNextRoot to hash of header
	HeaderProof trie.ProofChain
	// last height where committee of (Epoch-1) pronounced. ({LastHeight}.EpochNum()+2)=={Epoch}
	LastHeight common.Height
	// proof from last block hash to current block hash
	LastProof trie.ProofChain
}

func (p *RpcCommProof) String() string {
	if p == nil {
		return "CommProof<nil>"
	}
	return fmt.Sprintf("CommProof{ChainID:%d Epoch:%d Height:%d HoB:%x %s PaSs:%d "+
		"HeaderProof:%d LastHeight:%s LastProof:%d}", p.ChainID, p.Epoch, p.Height,
		common.ForPrint(p.HashOfHeader, 0, -1), p.Committee, len(p.Pass), len(p.HeaderProof),
		&(p.LastHeight), len(p.LastProof))
}

func (p *RpcCommProof) InfoString(level common.IndentLevel) string {
	if p == nil {
		return "CommProof<nil>"
	}
	commStr := ""
	commBytes, err := rtl.Marshal(p.Committee)
	if err != nil {
		commStr = err.Error()
	} else {
		commStr = fmt.Sprintf("0x%x", commBytes)
	}
	base := level.IndentString()
	nextLevel := level + 1
	return fmt.Sprintf("CommProof{"+
		"\n%s\tChainID: %d"+
		"\n%s\tEpoch: %d"+
		"\n%s\tHeight: %d"+
		"\n%s\tHashOfHeader: %x"+
		"\n%s\tCommittee: %s"+
		"\n%s\tCommitteeBytes: %s"+
		"\n%s\tPass: %s"+
		"\n%s\tHeaderProof: %s"+
		"\n%s\tLastHeight: %d"+
		"\n%s\tLastProof: %s"+
		"\n%s}",
		base, p.ChainID,
		base, p.Epoch,
		base, p.Height,
		base, common.ForPrint(p.HashOfHeader, 0, -1),
		base, p.Committee.InfoString(nextLevel),
		base, commStr,
		base, p.Pass.InfoString(nextLevel),
		base, p.HeaderProof.InfoString(nextLevel),
		base, p.LastHeight,
		base, p.LastProof.InfoString(nextLevel),
		base)
}

func (p *RpcCommProof) Validate() error {
	if p == nil {
		return common.ErrNil
	}
	if p.Epoch != p.Height.EpochNum()+1 {
		return fmt.Errorf("mismatch Epoch:%d Height:%d", p.Epoch, p.Height)
	}
	// validate header proof
	if err := p.VerifyHeader(nil); err != nil {
		return fmt.Errorf("validate HeaderProof failed: %v", err)
	}
	// validate pass
	sigs := make(map[string]struct{})
	for _, pas := range p.Pass {
		if pas == nil {
			// return errors.New("nil PaS found")
			continue
		}
		if !cipher.RealCipher.Verify(pas.PublicKey, p.HashOfHeader, pas.Signature) {
			return fmt.Errorf("invalid PaS found: %s", pas)
		}
		if _, exist := sigs[string(pas.PublicKey)]; exist {
			return fmt.Errorf("duplicated PaS found: %s", pas)
		}
	}
	// check whether LastHeight matchs LastProof
	if p.LastHeight.IsNil() {
		// fixme: compatible with old data, see CommitteeIndex
		// if p.Epoch != 1 {
		// 	return fmt.Errorf("mismatch LastHeight:%s Epoch:%d Height:%s", &(p.LastHeight), p.Epoch, &(p.Height))
		// }
		if len(p.LastProof) > 0 {
			return fmt.Errorf("mismatch LastHeight:%s len(LastProof):%d", &(p.LastHeight), len(p.LastProof))
		}
	} else {
		if p.Epoch != p.LastHeight.EpochNum()+2 {
			return fmt.Errorf("mismatch LastHeight:%d Epoch:%d", p.LastHeight, p.Epoch)
		}
		// the last 1 for proof(HistoryRoot->HashOfHeader), others for HistoryProof(lastHash->HistoryRoot)
		if len(p.LastProof) <= 1 {
			return fmt.Errorf("more proof needed LastHeight:%d len(LastProof):%d", p.LastHeight, len(p.LastProof))
		}
		historyProof := p.LastProof[:len(p.LastProof)-1]
		key := historyProof.BigKey().Uint64()
		if key != uint64(p.LastHeight) {
			return fmt.Errorf("LastHeight:%d not match with historyProof key:%d", p.LastHeight, key)
		}
	}
	return nil
}

func (p *RpcCommProof) VerifyHeader(curComm *models.Committee) error {
	if p == nil {
		return common.ErrNil
	}
	hashOfComm := p.Committee.Hash()
	proofed, err := p.HeaderProof.Proof(hashOfComm)
	if err != nil {
		return err
	}
	if !bytes.Equal(p.HashOfHeader, proofed) {
		return fmt.Errorf("result of HeaderProof is %x but hash of header is %x",
			common.ForPrint(proofed), common.ForPrint(p.HashOfHeader))
	}
	if curComm != nil {
		if err := p.Pass.VerifyByComm(curComm, p.HashOfHeader); err != nil {
			return err
		}
	}
	return nil
}

func (p *RpcCommProof) VerifyLast(lastHeight common.Height, lastHash common.Hash) error {
	if p == nil {
		return common.ErrNil
	}
	if lastHeight != p.LastHeight {
		return fmt.Errorf("lastHeight:%d not match with LastHeight:%d", lastHeight, p.LastHeight)
	}
	if len(p.LastProof) == 0 {
		return errors.New("no last information found")
	}
	root, err := p.LastProof.Proof(lastHash)
	if err != nil {
		return fmt.Errorf("proof failed: %v", err)
	}
	if !bytes.Equal(root, p.HashOfHeader) {
		return fmt.Errorf("history proof failed, root:%x but hob:%x", common.ForPrint(root),
			common.ForPrint(p.HashOfHeader))
	}
	return nil
}

func (p *BlockWithAuditings) Build(block *models.BlockEMessage, auditings models.AuditorPass) *BlockWithAuditings {
	if p == nil {
		p = new(BlockWithAuditings)
	} else {
		p.Clear()
	}
	if block != nil {
		p.BlockHeader = block.BlockHeader
		p.BlockBody = block.BlockBody
		p.BlockPass = block.BlockPass
	}
	p.Auditings = auditings
	return p
}

func (p *BlockWithAuditings) Clear() {
	p.BlockHeader = nil
	p.BlockBody = nil
	p.BlockPass = nil
	p.Auditings = nil
}

func (p *BlockWithAuditings) InfoString(level common.IndentLevel) string {
	if p == nil {
		return "Block<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("Block{"+
		"\n\t%sHeader: %s"+
		"\n\t%sBody: %s"+
		"\n\t%sPass: %s"+
		"\n\t%sAuditings: %s"+
		"\n%s}",
		base, p.BlockHeader.InfoString(next),
		base, p.BlockBody.InfoString(next),
		base, p.BlockPass.InfoString(next),
		base, p.Auditings.InfoString(next),
		base)
}

func (c *RRNodeChanging) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "NodeChanging<nil>"
	}
	base := level.IndentString()
	nextLevel := level + 1
	indent := nextLevel.IndentString()
	return fmt.Sprintf("NodeChanging{"+
		"\n%sInfo: %s"+
		"\n%sChanging: %s"+
		"\n%s}",
		indent, c.Info.InfoString(nextLevel),
		indent, c.Changing.InfoString(nextLevel),
		base)
}

func (c *RRChanges) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "RRChanges<nil>"
	}
	base := level.IndentString()
	nextLevel := level + 1
	indent := nextLevel.IndentString()
	return fmt.Sprintf("RRChanges{"+
		"\n%sEra: %s"+
		"\n%sRoot: %x"+
		"\n%sNext: %x"+
		"\n%sChanging: %x"+
		"\n%sMaxDepost: %s"+
		"\n%sConsDepSum: %s"+
		"\n%sDelegatedSum: %s"+
		"\n%sDataDepSum: %s"+
		"\n%sChanges: %s"+
		"\n%s}",
		indent, &(c.Era),
		indent, c.Root[:],
		indent, c.Next[:],
		indent, c.Changing[:],
		indent, math.BigForPrint(c.MaxDeposit),
		indent, math.BigForPrint(c.ConsDepSum),
		indent, math.BigForPrint(c.DelegatedSum),
		indent, math.BigForPrint(c.DataDepSum),
		indent, nextLevel.InfoString(c.Changes),
		base,
	)
}

func (c *Confirmeds) InfoString(level common.IndentLevel) string {
	if c == nil {
		return "Confirmeds<nil>"
	}
	base := level.IndentString()
	nextLevel := level + 1
	indent := nextLevel.IndentString()
	return fmt.Sprintf("Confirmeds{"+
		"\n%sAt: %s"+
		"\n%sRoot: %x"+
		"\n%sData: %s"+
		"\n%s}",
		indent, &(c.At),
		indent, common.ForPrint(c.Root),
		indent, nextLevel.InfoString(c.Data),
		base)
}

func (x *RpcReboot) ToMessage() (*models.RebootMainChainMessage, error) {
	if x == nil {
		return nil, common.ErrNil
	}
	msg := &models.RebootMainChainMessage{}
	msg.LastHeight = common.Height(x.LastHeight)
	if len(x.LastHash) != common.HashLength {
		return nil, errors.New("illegal lastHash")
	}
	msg.LastHash = common.BytesToHash(x.LastHash)
	if nids, err := common.ByteSlicesToNodeIDs(x.Comm); err != nil {
		return nil, err
	} else if len(nids) < consts.MinimumCommSize {
		return nil, errors.New("illegal committee size")
	} else {
		msg.Comm = new(models.Committee).SetMembers(nids)
	}
	if pass, err := models.PubAndSigs(nil).FromPubsAndSigs(x.Pubs, x.Sigs); err != nil {
		return nil, err
	} else {
		msg.PaSs = pass
	}
	return msg, nil
}

type RpcBlocks struct {
	ChainID common.ChainID
	Current common.Height
	Blocks  []*models.BlockEMessage
}

func (b *RpcBlocks) String() string {
	if b == nil {
		return "Blocks<nil>"
	}
	if len(b.Blocks) > 0 {
		return fmt.Sprintf("Blocks{ChainID:%d Height:%s Blocks:%d StartHeight:%d}", b.ChainID, &(b.Current), len(b.Blocks), b.Blocks[0].GetHeight())
	}
	return fmt.Sprintf("Blocks{ChainID:%d Height:%s Blocks:%d}", b.ChainID, &(b.Current), len(b.Blocks))
}

func (b *RpcBlocks) InfoString(level common.IndentLevel) string {
	if b == nil {
		return "Blocks<nil>"
	}
	next := level + 1
	indent := next.IndentString()
	return fmt.Sprintf("Blocks{"+
		"\n%sChainID: %d"+
		"\n%sHeight: %s"+
		"\n%sBlocks: %s"+
		"\n%s}",
		indent, b.ChainID, indent, &(b.Current),
		indent, next.InfoString(b.Blocks),
		level.IndentString())
}

func (x *RpcResponse) Success() bool {
	return x != nil && x.Code == SuccessCode
}

func (x *RpcResponseStream) Success() bool {
	return x != nil && x.Code == SuccessCode
}

type BridgeData struct {
	ReqCursor  common.Height
	RespCursor common.Height
	Reqs       []*models.BridgeReq
	Resps      []*models.BridgeResp
}

func (b *BridgeData) InfoString(level common.IndentLevel) string {
	if b == nil {
		return "BridgeData<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("BridgeData{"+
		"\n%s\tReqCursor: %s"+
		"\n%s\tRespCursor: %s"+
		"\n%s\tRequests: %s"+
		"\n%s\tResponses: %s"+
		"\n%s}",
		base, &(b.ReqCursor),
		base, &(b.RespCursor),
		base, next.InfoString(b.Reqs),
		base, next.InfoString(b.Resps),
		base)
}
