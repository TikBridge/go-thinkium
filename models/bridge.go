package models

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

var (
	TypeOfBridgeInfoPtr       = reflect.TypeOf((*BridgeInfo)(nil))
	TypeOfBridgeTargetNodePtr = reflect.TypeOf((*BridgeTargetNode)(nil))
	TypeOfBridgeReqPtr        = reflect.TypeOf((*BridgeReq)(nil))
	TypeOfBridgeRespPtr       = reflect.TypeOf((*BridgeResp)(nil))
)

type TokenType byte

const (
	// source ERC20:
	// function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
	// target ERC20:
	// function mint(address _to, uint256 _value) external;
	// function burnFrom(address _to, uint256 _value) external;
	TT_ERC20 TokenType = 0
	// source ERC721:
	// function safeTransferFrom(address _from, address _to, uint256 _tokenId, bytes calldata data) external payable;
	// target ERC721:
	// function claim(uint256 _tokenId, address _to) external;
	// function mint(address _to) external returns(uint256 _tokenId);
	// function burn(uint256 _tokenId) external;
	TT_ERC721 TokenType = 1
	// source ERC1155:
	// function safeTransferFrom(address _from, address _to, uint256 _id, uint256 _value, bytes calldata _data) external;
	// target ERC1155:
	// function mint(address _to, uint256 _id, uint256 _value, bytes calldata _data) external;
	// function burn(address _to, uint256 _id, uint256 _value) external;
	TT_ERC1155 TokenType = 2
)

func (t TokenType) IsValid() bool {
	return t == TT_ERC20 || t == TT_ERC721 || t == TT_ERC1155
}

func (t TokenType) String() string {
	switch t {
	case TT_ERC20:
		return "ERC20"
	case TT_ERC721:
		return "ERC721"
	case TT_ERC1155:
		return "ERC1155"
	default:
		return fmt.Sprintf("UNKNOWN-%d", t)
	}
}

type MappingType byte

const (
	MT_MAIN    MappingType = 0
	MT_MAPPING MappingType = 1
)

func (e MappingType) IsValid() bool {
	return e == MT_MAIN || e == MT_MAPPING
}

func (e MappingType) ToBig() *big.Int {
	return big.NewInt(int64(e))
}

func (e MappingType) String() string {
	switch e {
	case MT_MAIN:
		return "MAIN"
	case MT_MAPPING:
		return "MAP"
	default:
		return fmt.Sprintf("UNKNOWN-%x", byte(e))
	}
}

// defination of bridge stored in main chain
// 1. there are two types of contracts: main contract and mapping contract, each mapping contract
//    can only correspond to one main contract. To contract can only be a mapping contract.
// 2. for safety, it is required that all the tokens on the mapping contract are mint from the system
//    bridge, and others cannot mint, so as to ensure that the token on the account of the system
//    bridge address on the main contract and the token on the mapping contract of all modified
//    contracts can be the same. one-to-one
// 3. creating the Trie with (ToChain, ToContract) as the unique key ensures that each mapping contract
//    corresponds to only one main contract.
// 4. the transfer from the main contract to the mapping contract uses TRANSFER-MINT
// 5. the transfer from the mapping contract to the main contract uses BURN-TRANSFER
// 6. mapping contracts of the same (FromChain, FromContract) can be transferred to each other using
//    the BURN-MINT pair
// 1. 合约分为主合约和映射合约两种，每一个映射合约只能对应一个主合约。to合约只能是映射合约。
// 2. 为了安全，需要所有映射合约上的token都是由系统桥mint出来的，其他人无法mint，这样才能保
//    证主合约上系统桥地址的账户上的token与所有改合约的映射合约上的token才能一一对应
// 3. 以 (ToChain, ToContract)为唯一键创建Trie，可以保证每个映射合约只对应一个主合约。
// 4. 从主合约到映射合约的转移使用 TRANSFER-MINT
// 5. 从映射合约到主合约的转移使用 BURN-TRANSFER
// 6. 相同(FromChain, FromContract)的合约可以互相转移，使用BURN-MINT对
type BridgeInfo struct {
	MappingChain    common.ChainID
	MappingContract common.Address
	FromChain       common.ChainID
	FromContract    common.Address
	Type            TokenType
}

func (b *BridgeInfo) Clone() *BridgeInfo {
	if b == nil {
		return nil
	}
	return &BridgeInfo{
		MappingChain:    b.MappingChain,
		MappingContract: b.MappingContract,
		FromChain:       b.FromChain,
		FromContract:    b.FromContract,
		Type:            b.Type,
	}
}

func (b *BridgeInfo) Validate() error {
	if b == nil {
		return common.ErrNil
	}
	if b.FromChain.IsNil() || b.FromChain.IsMain() {
		return errors.New("invalid main contract chain")
	}
	if b.MappingChain.IsNil() || b.MappingChain.IsMain() {
		return errors.New("invalid mapping contract chain")
	}
	if b.FromChain == b.MappingChain && b.FromContract == b.MappingContract {
		return errors.New("cannot mapping contract itself")
	}
	if !b.Type.IsValid() {
		return errors.New("invalid token type")
	}
	return nil
}

func (*BridgeInfo) BridgeInfoKey(chainId common.ChainID, contract common.Address) []byte {
	bs := make([]byte, 4+20)
	binary.BigEndian.PutUint32(bs, uint32(chainId))
	copy(bs[4:], contract[:])
	return bs
}

// unique by (FromChain,FromContract,ToChain,ToContract)
func (b *BridgeInfo) Key() []byte {
	return b.BridgeInfoKey(b.MappingChain, b.MappingContract)
}

func (b *BridgeInfo) Match(o *BridgeInfo) bool {
	if b == o {
		return true
	}
	if b == nil || o == nil {
		return false
	}
	return b.FromChain == o.FromChain && b.FromContract == o.FromContract &&
		b.MappingChain == o.MappingChain && o.MappingContract == o.MappingContract &&
		b.Type == o.Type
}

func (b *BridgeInfo) SameMain(o *BridgeInfo) bool {
	if b == o {
		return true
	}
	if b == nil || o == nil {
		return false
	}
	return b.FromChain == o.FromChain && b.FromContract == o.FromContract
}

func (b *BridgeInfo) IsMapping(chain common.ChainID, contract common.Address) bool {
	return b.MappingChain == chain && b.MappingContract == contract
}

func (b *BridgeInfo) IsMainContract(chain common.ChainID, contract common.Address) bool {
	return b.FromChain == chain && b.FromContract == contract
}

func (b *BridgeInfo) ErcType(chain common.ChainID, contract common.Address) (typ MappingType, exist bool) {
	if b.FromChain == chain && b.FromContract == contract {
		return MT_MAIN, true
	} else if b.MappingChain == chain && b.MappingContract == contract {
		return MT_MAPPING, true
	} else {
		return 0xff, false
	}
}

// DONOT change because used in system bridge contract returned error
func (b *BridgeInfo) String() string {
	if b == nil {
		return "BRG<nil>"
	}
	return fmt.Sprintf("BRG{Mapping:(%d, %x) From:(%d, %x) Type:%s}",
		b.MappingChain, b.MappingContract[:], b.FromChain, b.FromContract[:], b.Type)
}

type BridgeInfos []*BridgeInfo

func (s BridgeInfos) String() string {
	if s == nil {
		return "BridgeInfos<nil>"
	}
	if len(s) == 0 {
		return "BridgeInfos[]"
	}
	if len(s) > 50 {
		return fmt.Sprintf("BridgeInfos(%d)%s...", len(s), []*BridgeInfo(s[:50]))
	} else {
		return fmt.Sprintf("BridgeInfos(%d)%s", len(s), []*BridgeInfo(s))
	}
}

type BridgeInfoTrie trie.RevertableTrie

func (t *BridgeInfoTrie) GetInfo(chainid common.ChainID, contract common.Address) *BridgeInfo {
	key := (*BridgeInfo)(nil).BridgeInfoKey(chainid, contract)
	v, ok := (*trie.RevertableTrie)(t).Get(key)
	if ok && v != nil {
		info := v.(*BridgeInfo)
		return info
	}
	return nil
}

// B(mappingChain, mappingContract) must be a mapping contract,
// A(fromChain, fromContract) could be the main contract of B, or the other mapping contract of
// the same main contract of B.
func (t *BridgeInfoTrie) Validate(fromChain common.ChainID, fromContract common.Address,
	mappingChain common.ChainID, mappingContract common.Address, tType TokenType) (fromType MappingType, err error) {
	toInfo := t.GetInfo(mappingChain, mappingContract)
	if toInfo == nil {
		return MT_MAIN, errors.New("no bridge info found for mapping contract")
	}
	if toInfo.Type != tType {
		return MT_MAIN, errors.New("to token type not match")
	}
	if toInfo.FromChain == fromChain && toInfo.FromContract == fromContract {
		return MT_MAIN, nil
	}

	fromInfo := t.GetInfo(fromChain, fromContract)
	if fromInfo == nil {
		return MT_MAIN, errors.New("no bridge info found for fromContract")
	}
	if fromInfo.Type != tType {
		return MT_MAIN, errors.New("from token type not match")
	}
	if fromInfo.SameMain(toInfo) {
		return MT_MAPPING, nil
	} else {
		return MT_MAIN, errors.New("no relationship with each other")
	}
}

func (t *BridgeInfoTrie) RangeAll(callback func(info *BridgeInfo) bool) {
	it := (*trie.RevertableTrie)(t).ValueIterator()
	for it.Next() {
		_, v := it.Current()
		info := v.(*BridgeInfo)
		if info != nil {
			if !callback(info) {
				break
			}
		}
	}
}

func (t *BridgeInfoTrie) ToInfos() ([]*BridgeInfo, error) {
	var ret []*BridgeInfo
	t.RangeAll(func(info *BridgeInfo) bool {
		ret = append(ret, info)
		return true
	})
	return ret, nil
}

type BridgePeerSession struct {
	Node  *BridgeTargetNode
	Reqs  []*BridgeReq
	Resps []*BridgeResp
}

func (s *BridgePeerSession) String() string {
	if s == nil {
		return "Peer<nil>"
	}
	return fmt.Sprintf("Peer{%s Len(Reqs):%d Len(Resps):%d}", s.Node, len(s.Reqs), len(s.Resps))
}

func (s *BridgePeerSession) InfoString(level common.IndentLevel) string {
	if s == nil {
		return "Peer<nil>"
	}
	base := level.IndentString()
	next := level + 1
	return fmt.Sprintf("Peer{"+
		"\n%s\tNode: %s"+
		"\n%s\tReqs: %s"+
		"\n%s\tResps: %s"+
		"\n%s}",
		base, s.Node,
		base, next.InfoString(s.Reqs),
		base, next.InfoString(s.Resps),
		base)
}

type BridgePeerSessions []*BridgePeerSession

func (s BridgePeerSessions) String() string {
	if s == nil {
		return "BridgePeers<nil>"
	}
	if len(s) == 0 {
		return "BridgePeers[]"
	}
	if len(s) > 50 {
		return fmt.Sprintf("BridgePeers(%d)%s...", len(s), []*BridgePeerSession(s[:50]))
	} else {
		return fmt.Sprintf("BridgePeers(%d)%s", len(s), []*BridgePeerSession(s))
	}
}

type BridgeReqStatus uint8

const (
	BReqNotRespond BridgeReqStatus = 0
	BReqSuccess    BridgeReqStatus = 1
	BReqFailed     BridgeReqStatus = 2
)

func (s BridgeReqStatus) IsValid() bool {
	return s == BReqNotRespond || s == BReqSuccess || s == BReqFailed
}

func (s BridgeReqStatus) IsSuccess() bool {
	return s == BReqSuccess
}

func (s BridgeReqStatus) IsFailed() bool {
	return s == BReqFailed
}

func (s BridgeReqStatus) String() string {
	switch s {
	case BReqNotRespond:
		return "NotRespond"
	case BReqSuccess:
		return "Succeed"
	case BReqFailed:
		return "Failed"
	default:
		return fmt.Sprintf("UNKNOWN-%X", uint8(s))
	}
}

// bridge mint or burn request, generated and stored in from-chain, processed in target-chain
// key: Height(8)+ToAccount(20)+Nonce(8), ordered with height and unique by account+nonce
type BridgeReq struct {
	FromChain          common.ChainID  //
	FromContract       common.Address  // mapping contract if BURNING, main contract if TRANSFERING
	Height             common.Height   // the height of the block in which the requested transaction packed
	ToChain            common.ChainID  // bridge target chain
	ToContract         common.Address  // bridge target contract, get from BridgeInfo in main chain
	ToAccount          common.Address  // request user
	Nonce              uint64          // nonce of transaction generate this request
	Value              *big.Int        // value of erc20, amount of 721/1155
	TokenID            *big.Int        // not nil if Type is 721 or 1155
	Data               []byte          // used for mint1155
	TokenType          TokenType       // token type
	FromContractType   MappingType     // used to determine which method should be called when generating a withdraw transaction
	TargetContractType MappingType     // used to determine which method should be called when generating a proccess transaction, regardless of whether the BridgeInfo in the main chain has changed
	Status             BridgeReqStatus // 0: not responded, 1: process successful, 2: process failed
}

func (r *BridgeReq) Clone() *BridgeReq {
	if r == nil {
		return nil
	}
	return &BridgeReq{
		FromChain:          r.FromChain,
		FromContract:       r.FromContract,
		Height:             r.Height,
		ToChain:            r.ToChain,
		ToContract:         r.ToContract,
		ToAccount:          r.ToAccount,
		Nonce:              r.Nonce,
		Value:              math.CopyBigInt(r.Value),
		TokenID:            math.CopyBigInt(r.TokenID),
		Data:               common.CopyBytes(r.Data),
		TokenType:          r.TokenType,
		FromContractType:   r.FromContractType,
		TargetContractType: r.TargetContractType,
		Status:             r.Status,
	}
}

func (r *BridgeReq) Equal(o *BridgeReq) bool {
	if r == o {
		return true
	}
	if r == nil || o == nil {
		return false
	}
	return r.FromChain == o.FromChain && r.FromContract == o.FromContract && r.Height == o.Height &&
		r.ToChain == o.ToChain && r.ToContract == o.ToContract && r.ToAccount == o.ToAccount &&
		r.Nonce == o.Nonce && math.CompareBigInt(r.Value, o.Value) == 0 &&
		math.CompareBigInt(r.TokenID, o.TokenID) == 0 && bytes.Equal(r.Data, o.Data) &&
		r.TokenType == o.TokenType && r.FromContractType == o.FromContractType &&
		r.TargetContractType == o.TargetContractType && r.Status == o.Status
}

func (r *BridgeReq) Validate() error {
	if r == nil {
		return common.ErrNil
	}
	if !r.Status.IsValid() {
		return errors.New("invalid status")
	}
	if !r.FromContractType.IsValid() {
		return errors.New("invalid source contract mapping type")
	}
	if !r.TargetContractType.IsValid() {
		return errors.New("invalid target contract mapping type")
	}
	switch r.TokenType {
	case TT_ERC20:
		if r.Value == nil || r.Value.Sign() <= 0 {
			return errors.New("invalid value")
		}
		if r.TokenID != nil {
			return errors.New("no token id needed")
		}
		if len(r.Data) > 0 {
			return errors.New("no call data needed")
		}
	case TT_ERC721:
		if r.Value != nil {
			return errors.New("value not needed")
		}
		if r.TokenID == nil || r.TokenID.Sign() < 0 {
			return errors.New("invalid token id")
		}
	case TT_ERC1155:
		if r.Value == nil || r.Value.Sign() <= 0 {
			return errors.New("invalid value")
		}
		if r.TokenID == nil || r.TokenID.Sign() < 0 {
			return errors.New("invalid token id")
		}
	default:
		return errors.New("unknown token type")
	}
	return nil
}

func (r *BridgeReq) Succeeded() bool {
	if r == nil || !r.Status.IsSuccess() {
		return false
	}
	return true
}

func (r *BridgeReq) Failed() bool {
	if r == nil || !r.Status.IsFailed() {
		return false
	}
	return true
}

func (r *BridgeReq) ToProcessingTx(nonce uint64) (*Transaction, error) {
	if r == nil {
		return nil, nil
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	tx := &Transaction{
		ChainID:  r.ToChain,
		From:     AddressOfSysBridge.Copy(),
		To:       AddressOfSysBridge.Copy(),
		Nonce:    nonce,
		UseLocal: false,
		Val:      big.NewInt(0),
		Input:    nil,
		Extra:    nil,
		Version:  TxVersion,
	}
	reqInfo, err := new(BridgeReqInfo).FromReq(r)
	if err != nil {
		return nil, err
	}
	var input []byte
	switch r.TokenType {
	case TT_ERC20:
		input, err = BridgeAbi.Pack(BridgeProcessReq20, reqInfo, r.ToContract, r.ToAccount, r.Value)
	case TT_ERC721:
		input, err = BridgeAbi.Pack(BridgeProcessReq721, reqInfo, r.ToContract, r.ToAccount, r.TokenID,
			EmptyBytesIfNil(r.Data))
	case TT_ERC1155:
		input, err = BridgeAbi.Pack(BridgeProcessReq1155, reqInfo, r.ToContract, r.ToAccount, r.TokenID,
			r.Value, EmptyBytesIfNil(r.Data))
	}
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	tx.Input = input
	extra := &BridgeExtra{Type: BridgeExtraReqType}
	extraBytes, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("extra marshal failed: %v", err)
	}
	if err := tx.SetTkmExtra(extraBytes); err != nil {
		return nil, fmt.Errorf("set tkm extra failed: %v", err)
	}
	return tx, nil
}

func (r *BridgeReq) ToFailedTx(nonce uint64) (*Transaction, error) {
	if r == nil {
		return nil, nil
	}
	tx := &Transaction{
		ChainID:  r.ToChain,
		From:     AddressOfSysBridge.Copy(),
		To:       AddressOfSysBridge.Copy(),
		Nonce:    nonce,
		UseLocal: false,
		Val:      big.NewInt(0),
		Input:    nil,
		Extra:    nil,
		Version:  TxVersion,
	}
	reqInfo, err := new(BridgeReqInfo).FromReq(r)
	if err != nil {
		return nil, err
	}
	input, err := BridgeAbi.Pack(BridgeProcessFailed, reqInfo)
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	tx.Input = input
	extra := &BridgeExtra{Type: BridgeExtraReqFailedType}
	extraBytes, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("extra marshal failed: %v", err)
	}
	if err := tx.SetTkmExtra(extraBytes); err != nil {
		return nil, fmt.Errorf("set tkm extra failed: %v", err)
	}
	return tx, nil
}

func (r *BridgeReq) MakeWithdrawingInput() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	switch r.TokenType {
	case TT_ERC20:
		if r.FromContractType == MT_MAIN {
			return BridgeErc20Abi.Pack(TBE20Transfer, r.ToAccount, r.Value)
		} else {
			return BridgeErc20Abi.Pack(TBE20Mint, r.ToAccount, r.Value)
		}
	case TT_ERC721:
		if r.FromContractType == MT_MAIN {
			return BridgeErc721Abi.Pack(TBE721TransFrom, AddressOfSysBridge, r.ToAccount, r.TokenID, EmptyBytesIfNil(r.Data))
		} else {
			return BridgeErc721Abi.Pack(TBE721Claim, r.TokenID, r.ToAccount)
		}
	case TT_ERC1155:
		if r.FromContractType == MT_MAIN {
			return BridgeErc1155Abi.Pack(TBE1155TransFrom, AddressOfSysBridge,
				r.ToAccount, r.TokenID, r.Value, EmptyBytesIfNil(r.Data))
		} else {
			return BridgeErc1155Abi.Pack(TBE1155Mint, r.ToAccount, r.TokenID, r.Value, EmptyBytesIfNil(r.Data))
		}
	default:
		return nil, errors.New("invalid token type")
	}
}

func BridgeReqRespKey(height common.Height, addr common.Address, nonce uint64) []byte {
	key := make([]byte, 8+20+8)
	binary.BigEndian.PutUint64(key, uint64(height))
	copy(key[8:], addr[:])
	binary.BigEndian.PutUint64(key[28:], nonce)
	return key
}

func (r *BridgeReq) Key() []byte {
	if r == nil {
		return nil
	}
	return BridgeReqRespKey(r.Height, r.ToAccount, r.Nonce)
}

// DONOT change because this method is used in system bridge contract returned error value
func (r *BridgeReq) String() string {
	if r == nil {
		return "BridgeReq<nil>"
	}
	buf := new(bytes.Buffer)
	if r.TokenID != nil {
		buf.WriteString(fmt.Sprintf(" TokenID:%s", r.TokenID))
	}
	if len(r.Data) > 0 {
		buf.WriteString(fmt.Sprintf(" Len(Data):%d", len(r.Data)))
	}
	return fmt.Sprintf("BridgeReq{From:(%d, %x, %s) Height:%d To:(%d, %x, %s) Acc:%x Nonce:%d "+
		"Value:%s%s ERC:%s Status:%s}", r.FromChain, r.FromContract[:], r.FromContractType, r.Height,
		r.ToChain, r.ToContract[:], r.TargetContractType, r.ToAccount[:], r.Nonce, r.Value, buf.String(),
		r.TokenType, r.Status)
}

// the response of the request send from SourceChain to TargetChain
// a response should be send from TargetChain to SourceChain to update the status of the request
// SourceChain is the key in the upper level of the trie which is not included in the struct
type BridgeResp struct {
	SourceChain common.ChainID // where the request generated
	ReqHeight   common.Height  // the height of from chain block where the request generated
	TargetChain common.ChainID // where the request processed and also where the response generated
	BlockHeight common.Height  // the height of block where the request processed
	Account     common.Address // request.ToAccount
	Nonce       uint64         // request.Nonce
	Status      uint8          // 0: failed, 1: succeed
}

func (p *BridgeResp) Clone() *BridgeResp {
	if p == nil {
		return nil
	}
	r := *p
	return &r
}

func (p *BridgeResp) Equal(o *BridgeResp) bool {
	if p == o {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	return *p == *o
	// return p.SourceChain == o.SourceChain && p.ReqHeight == o.ReqHeight && p.TargetChain == o.TargetChain &&
	// 	p.BlockHeight == o.BlockHeight && p.Account == o.Account && p.Nonce == o.Nonce && p.Status == o.Status
}

func (p *BridgeResp) ToUpdateTx(nonce uint64) (*Transaction, error) {
	if p == nil {
		return nil, nil
	}
	tx := &Transaction{
		ChainID:  p.SourceChain,
		From:     AddressOfSysBridge.Copy(),
		To:       AddressOfSysBridge.Copy(),
		Nonce:    nonce,
		UseLocal: false,
		Val:      big.NewInt(0),
		Input:    nil,
		Extra:    nil,
		Version:  TxVersion,
	}
	input, err := BridgeAbi.Pack(BridgeUpdateReq, p.ReqHeight, p.TargetChain, p.BlockHeight, p.Account, p.Nonce, p.Status == 1)
	if err != nil {
		return nil, fmt.Errorf("pack input failed: %v", err)
	}
	tx.Input = input
	extra := &BridgeExtra{Type: BridgeExtraStatusType}
	extraBytes, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("extra marshal failed: %v", err)
	}
	if err := tx.SetTkmExtra(extraBytes); err != nil {
		return nil, fmt.Errorf("set tkm extra failed: %v", err)
	}
	return tx, nil
}

func (p *BridgeResp) Succeeded() bool {
	if p == nil || p.Status == 0 {
		return false
	}
	return true
}

func (p *BridgeResp) StatusString() string {
	if p.Succeeded() {
		return "Succeed"
	} else {
		return "Failed"
	}
}

// same with the key of BridgeReq: BlockHeight + Account + Nonce,
// FromChain is the key in upper level
func (p *BridgeResp) Key() []byte {
	if p == nil {
		return nil
	}
	return BridgeReqRespKey(p.BlockHeight, p.Account, p.Nonce)
}

func (p *BridgeResp) String() string {
	if p == nil {
		return "BridgeResp<nil>"
	}
	return fmt.Sprintf("BridgeResp{SourceChain:%d ReqHeight:%s TargetChain:%d BlockHeight:%s Acc:%x Nonce:%d Status:%s}",
		p.SourceChain, &(p.ReqHeight), p.TargetChain, &(p.BlockHeight), p.Account[:], p.Nonce, p.StatusString())
}

// Bridge request trie node, generate trie root for block header
// TargetChainID -> (Height, Account, Nonce) -> Requests
type BridgeTargetNode struct {
	ToChainID  common.ChainID // the target chain of generated bridge requests, and the from chain of all processed requests
	ReqCursor  common.Height  // the last height of processed requests from ToChainID
	ReqRoot    []byte         // trie root of requests to ToChainID
	RespCursor common.Height  // the last height of processed responses from ToChainID
	RespRoot   []byte         // trie root of responses to ToChainID
}

type BridgeTargetNodeProofIndex int

const (
	BridgeTargetNodeToChain    BridgeTargetNodeProofIndex = 0
	BridgeTargetNodeReqCursor  BridgeTargetNodeProofIndex = 1
	BridgeTargetNodeReqRoot    BridgeTargetNodeProofIndex = 2
	BridgeTargetNodeRespCursor BridgeTargetNodeProofIndex = 3
	BridgeTargetNodeRespRoot   BridgeTargetNodeProofIndex = 4
)

func (i BridgeTargetNodeProofIndex) IsValid() bool {
	if i >= BridgeTargetNodeToChain && i <= BridgeTargetNodeRespRoot {
		return true
	}
	return false
}

func (n *BridgeTargetNode) Clone() *BridgeTargetNode {
	if n == nil {
		return nil
	}
	return &BridgeTargetNode{
		ToChainID:  n.ToChainID,
		ReqCursor:  n.ReqCursor,
		ReqRoot:    common.CopyBytes(n.RespRoot),
		RespCursor: n.RespCursor,
		RespRoot:   common.CopyBytes(n.RespRoot),
	}
}

func (n *BridgeTargetNode) Key() []byte {
	if n == nil {
		return nil
	}
	return n.ToChainID.Bytes()
}

func (n *BridgeTargetNode) updateReqRoot(root []byte) bool {
	if len(root) > 0 && !bytes.Equal(root, n.ReqRoot) {
		n.ReqRoot = common.CopyBytes(root)
		return true
	}
	return false
}

func (n *BridgeTargetNode) updateRespRoot(root []byte) bool {
	if len(root) > 0 && !bytes.Equal(root, n.RespRoot) {
		n.RespRoot = common.CopyBytes(root)
		return true
	}
	return false
}

func (n *BridgeTargetNode) _proof(toBeProof int, proofs *common.MerkleProofs) ([]byte, error) {
	var toChainHash, reqCursorHash, reqRootHash, respCursorHash, respRootHash []byte
	var err error
	if toChainHash, err = n.ToChainID.HashValue(); err != nil {
		return nil, err
	}
	if reqCursorHash, err = n.ReqCursor.HashValue(); err != nil {
		return nil, err
	}
	if n.ReqRoot == nil {
		reqRootHash = common.CopyBytes(common.EmptyNodeHashSlice)
	} else {
		reqRootHash = common.CopyBytes(n.ReqRoot)
	}
	if respCursorHash, err = n.RespCursor.HashValue(); err != nil {
		return nil, err
	}
	if n.RespRoot == nil {
		respRootHash = common.CopyBytes(common.EmptyNodeHashSlice)
	} else {
		respRootHash = common.CopyBytes(n.RespRoot)
	}
	hashList := [][]byte{toChainHash, reqCursorHash, reqRootHash, respCursorHash, respRootHash}
	return common.MerkleHash(hashList, toBeProof, proofs)
}

func (n *BridgeTargetNode) MakeProof(index BridgeTargetNodeProofIndex, proofs *common.MerkleProofs) ([]byte, *common.MerkleProofs, error) {
	if !index.IsValid() {
		return nil, nil, errors.New("illegal index")
	}
	if proofs == nil {
		proofs = common.NewMerkleProofs()
	}
	root, err := n._proof(int(index), proofs)
	if err != nil {
		return nil, nil, err
	}
	return root, proofs, nil
}

func (n *BridgeTargetNode) HashValue() ([]byte, error) {
	return n._proof(-1, nil)
}

func (n *BridgeTargetNode) String() string {
	if n == nil {
		return "Node<nil>"
	}
	return fmt.Sprintf("Node{ToChain:%d Req(Cursor:%s Root:%x) Resp(Cursor:%s Root:%x)}",
		n.ToChainID, &(n.ReqCursor), common.ForPrint(n.ReqRoot), &(n.RespCursor), common.ForPrint(n.RespRoot))
}

type BridgeSessionTrie struct {
	chains    *trie.RevertableTrie
	requests  map[common.ChainID]*trie.RevertableTrie
	responses map[common.ChainID]*trie.RevertableTrie
	lock      sync.Mutex

	dbase db.Database
}

func (t *BridgeSessionTrie) String() string {
	if t == nil {
		return "BridgeSessionTrie<nil>"
	}
	return "BridgeSessionTrie{}"
}

func NewBridgeSessionTrie(dbase db.Database, root []byte) *BridgeSessionTrie {
	na := db.NewKeyPrefixedDataAdapter(dbase, KPBridgeReqTrieNode)
	va := db.NewKeyPrefixedDataAdapter(dbase, KPBridgeReqTrieValue)
	chains := trie.NewTrieWithValueType(root, na, va, TypeOfBridgeTargetNodePtr)
	return &BridgeSessionTrie{
		chains:   &trie.RevertableTrie{Origin: chains},
		requests: nil,
		dbase:    dbase,
	}
}

// get BridgeTrieNode from chains trie, create one if there's no node yet if createIfNil is true
func (t *BridgeSessionTrie) _targetNode(cid common.ChainID, createIfNil bool) (node *BridgeTargetNode) {
	defer func() {
		if createIfNil && node == nil {
			node = &BridgeTargetNode{
				ToChainID:  cid,
				ReqCursor:  common.NilHeight,
				ReqRoot:    nil,
				RespCursor: common.NilHeight,
				RespRoot:   nil,
			}
		}
	}()
	key := cid.Bytes()
	v, ok := t.chains.GetLive(key)
	if !ok || v == nil {
		return nil
	}
	one, ok := v.(*BridgeTargetNode)
	if !ok || one == nil {
		return nil
	}
	return one
}

func (t *BridgeSessionTrie) _reqTrie(cid common.ChainID, createIfEmpty bool) (tr *trie.RevertableTrie) {
	if t.requests != nil {
		tr, _ = t.requests[cid]
		if tr != nil {
			return tr
		}
	}
	var root []byte
	node := t._targetNode(cid, false)
	if node != nil {
		root = common.CopyBytes(node.ReqRoot)
	}
	if len(root) == 0 && !createIfEmpty {
		return nil
	}
	if t.requests == nil {
		t.requests = make(map[common.ChainID]*trie.RevertableTrie)
	}
	tr = t._createRequestTrie(root)
	t.requests[cid] = tr
	return tr
}

func (t *BridgeSessionTrie) _respTrie(cid common.ChainID, createIfEmpty bool) (tr *trie.RevertableTrie) {
	if t.responses != nil {
		tr, _ = t.responses[cid]
		if tr != nil {
			return tr
		}
	}
	var root []byte
	node := t._targetNode(cid, false)
	if node != nil {
		root = common.CopyBytes(node.RespRoot)
	}
	if len(root) == 0 && !createIfEmpty {
		return nil
	}
	if t.responses == nil {
		t.responses = make(map[common.ChainID]*trie.RevertableTrie)
	}
	tr = t._createResponseTrie(root)
	t.responses[cid] = tr
	return tr
}

func _rangeReqs(reqTrie *trie.RevertableTrie, callback func(req *BridgeReq) bool) {
	it := reqTrie.LiveValueIterator()
	for it.Next() {
		_, v := it.Current()
		one, ok := v.(*BridgeReq)
		if !ok || one == nil {
			continue
		}
		if !callback(one) {
			break
		}
	}
}

func _rangeResps(respTrie *trie.RevertableTrie, callback func(resp *BridgeResp) bool) {
	it := respTrie.LiveValueIterator()
	for it.Next() {
		_, v := it.Current()
		one, ok := v.(*BridgeResp)
		if !ok || one == nil {
			continue
		}
		if !callback(one) {
			break
		}
	}
}

func (t *BridgeSessionTrie) _updateChainReqsRoot(cid common.ChainID, root []byte) bool {
	one := t._targetNode(cid, true)
	if one.updateReqRoot(root) {
		t.chains.PutValue(one)
		return true
	}
	return false
}

func (t *BridgeSessionTrie) _updateChainRespsRoot(cid common.ChainID, root []byte) bool {
	one := t._targetNode(cid, true)
	if one.updateRespRoot(root) {
		t.chains.PutValue(one)
		return true
	}
	return false
}

func (t *BridgeSessionTrie) _createRequestTrie(root []byte) *trie.RevertableTrie {
	na := db.NewKeyPrefixedDataAdapter(t.dbase, KPBridgeReqNode)
	va := db.NewKeyPrefixedDataAdapter(t.dbase, KPBridgeReqValue)
	tr := trie.NewTrieWithValueType(root, na, va, TypeOfBridgeReqPtr)
	return &trie.RevertableTrie{Origin: tr}
}

func (t *BridgeSessionTrie) _createResponseTrie(root []byte) *trie.RevertableTrie {
	na := db.NewKeyPrefixedDataAdapter(t.dbase, KPBridgeRespNode)
	va := db.NewKeyPrefixedDataAdapter(t.dbase, KPBridgeRespValue)
	tr := trie.NewTrieWithValueType(root, na, va, TypeOfBridgeRespPtr)
	return &trie.RevertableTrie{Origin: tr}
}

func (t *BridgeSessionTrie) GetLastReqCursor(fromChain common.ChainID) common.Height {
	t.lock.Lock()
	defer t.lock.Unlock()
	one := t._targetNode(fromChain, false)
	if one == nil {
		return common.NilHeight
	}
	return one.ReqCursor
}

func (t *BridgeSessionTrie) GetLastRespCursor(fromChain common.ChainID) common.Height {
	t.lock.Lock()
	defer t.lock.Unlock()
	one := t._targetNode(fromChain, false)
	if one == nil {
		return common.NilHeight
	}
	return one.RespCursor
}

func (t *BridgeSessionTrie) _preCommit() ([]byte, error) {
	for cid, reqs := range t.requests {
		if reqs == nil {
			continue
		}
		reqsRoot, err := reqs.PreCommit()
		if err != nil {
			return nil, fmt.Errorf("preCommit request trie at ChainID:%d failed: %v", cid, err)
		}
		t._updateChainReqsRoot(cid, reqsRoot)
	}
	for cid, resps := range t.responses {
		if resps == nil {
			continue
		}
		respsRoot, err := resps.PreCommit()
		if err != nil {
			return nil, fmt.Errorf("preCommit response trie at ChainID:%d failed: %v", cid, err)
		}
		t._updateChainRespsRoot(cid, respsRoot)
	}
	root, err := t.chains.PreCommit()
	if err != nil {
		return nil, fmt.Errorf("preCommit at chains failed: %v", err)
	}
	return root, nil
}

func (t *BridgeSessionTrie) PreCommit() ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t._preCommit()
}

func (t *BridgeSessionTrie) Rollback() {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.requests = nil
	t.responses = nil
	t.chains.Rollback()
}

func (t *BridgeSessionTrie) HashValue() ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.chains.HashValue()
}

func (t *BridgeSessionTrie) _commit() ([]byte, error) {
	for cid, reqs := range t.requests {
		if reqs == nil {
			continue
		}
		reqsRoot, err := reqs.CommitAndHash()
		if err != nil {
			return nil, fmt.Errorf("commitAndHash request trie at ChainID:%d failed: %v", cid, err)
		}
		t._updateChainReqsRoot(cid, reqsRoot)
	}
	for cid, resps := range t.responses {
		if resps == nil {
			continue
		}
		respsRoot, err := resps.CommitAndHash()
		if err != nil {
			return nil, fmt.Errorf("commitAndHash responses trie at ChainID:%d failed: %v", cid, err)
		}
		t._updateChainRespsRoot(cid, respsRoot)
	}
	root, err := t.chains.CommitAndHash()
	if err != nil {
		return nil, fmt.Errorf("commitAndHash at chains failed: %v", err)
	}
	t.requests = nil
	t.responses = nil
	return root, nil
}

func (t *BridgeSessionTrie) Commit() ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t._commit()
}

func (t *BridgeSessionTrie) CompareAndUpdateReqCursor(sourceChain common.ChainID, cursor common.Height) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	if cursor.IsNil() {
		return false
	}
	node := t._targetNode(sourceChain, true)
	if node.ReqCursor.Compare(cursor) < 0 {
		node.ReqCursor = cursor
		t.chains.PutValue(node)
		return true
	}
	return false
}

func (t *BridgeSessionTrie) CompareAndUpdateRespCursor(targetChain common.ChainID, cursor common.Height) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	if cursor.IsNil() {
		return false
	}
	node := t._targetNode(targetChain, true)
	if node.RespCursor.Compare(cursor) < 0 {
		node.RespCursor = cursor
		t.chains.PutValue(node)
		return true
	}
	return false
}

func (t *BridgeSessionTrie) UpdateReqStatus(toChain common.ChainID, reqHeight common.Height,
	account common.Address, nonce uint64, status BridgeReqStatus) error {
	if !status.IsValid() {
		return errors.New("invalid status")
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	reqTrie := t._reqTrie(toChain, false)
	if reqTrie == nil {
		return errors.New("request trie is empty")
	}
	key := BridgeReqRespKey(reqHeight, account, nonce)
	v, ok := reqTrie.GetLive(key)
	if !ok || v == nil {
		return errors.New("no request found")
	}
	req := v.(*BridgeReq)
	if req == nil {
		return errors.New("invalid request")
	}
	req.Status = status
	if !reqTrie.Put(key, req) {
		return errors.New("new request put failed")
	}
	return nil
}

func (t *BridgeSessionTrie) FindFailedRequest(targetChain common.ChainID, account common.Address, nonce uint64) *BridgeReq {
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._reqTrie(targetChain, false)
	if tr == nil {
		return nil
	}
	var ret *BridgeReq
	_rangeReqs(tr, func(req *BridgeReq) bool {
		if req.Status == BReqNotRespond {
			return false
		}
		if req.ToAccount == account && req.Nonce == nonce {
			if req.Status == BReqFailed {
				ret = req.Clone()
			}
			return false
		}
		return true
	})
	return ret
}

func (t *BridgeSessionTrie) PutRequest(req *BridgeReq) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._reqTrie(req.ToChain, true)
	if !tr.PutValue(req) {
		return errors.New("no request put")
	}
	return nil
}

func (t *BridgeSessionTrie) PutResponse(resp *BridgeResp) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._respTrie(resp.SourceChain, true)
	if !tr.PutValue(resp) {
		return errors.New("no response put")
	}
	return nil
}

func (t *BridgeSessionTrie) _proofTarget(toChain common.ChainID, index BridgeTargetNodeProofIndex, proofs *trie.ProofChain) error {
	// target node proof
	targetNode := t._targetNode(toChain, false)
	if targetNode == nil {
		return errors.New("SHOULD NOT BE HERE!!! target node not found, but request found")
	}
	_, targetProof, err := targetNode.MakeProof(index, nil)
	if err != nil || targetProof == nil {
		return fmt.Errorf("target proof failed: %v", err)
	}
	*proofs = append(*proofs, trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, targetProof))

	// chains trie proof
	_, chainsProof, ok := t.chains.GetProof(targetNode.Key())
	if !ok || len(chainsProof) == 0 {
		return fmt.Errorf("SHOULD NOT BE HERE!! target node %s proof failed", targetNode)
	}
	*proofs = append(*proofs, chainsProof...)

	return nil
}

func (t *BridgeSessionTrie) GetReqProof(req *BridgeReq) (trie.ProofChain, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	// reqeust trie proof
	tr := t._reqTrie(req.ToChain, false)
	if tr == nil {
		return nil, common.ErrNotFound
	}
	key := req.Key()
	v, proofs, ok := tr.GetProof(key)
	if !ok || v == nil || len(proofs) == 0 {
		return nil, common.ErrNotFound
	}
	reqInTrie := v.(*BridgeReq)
	if !reqInTrie.Equal(req) {
		return nil, common.ErrNotFound
	}

	if err := t._proofTarget(req.ToChain, BridgeTargetNodeReqRoot, &proofs); err != nil {
		return nil, err
	}
	return proofs, nil
}

func (t *BridgeSessionTrie) GetRespProof(resp *BridgeResp) (trie.ProofChain, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	// response trie proof
	tr := t._respTrie(resp.SourceChain, false)
	if tr == nil {
		return nil, common.ErrNotFound
	}
	key := resp.Key()
	v, proofs, ok := tr.GetProof(key)
	if !ok || v == nil || len(proofs) == 0 {
		return nil, common.ErrNotFound
	}
	respInTrie := v.(*BridgeResp)
	if !respInTrie.Equal(resp) {
		return nil, common.ErrNotFound
	}

	if err := t._proofTarget(resp.SourceChain, BridgeTargetNodeRespRoot, &proofs); err != nil {
		return nil, err
	}
	return proofs, nil
}

// list all request which height>lastHeight && height<=notAfter
func (t *BridgeSessionTrie) ListRequestsTo(cid common.ChainID, lastHeight, notAfter common.Height) []*BridgeReq {
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._reqTrie(cid, false)
	if tr == nil {
		return nil
	}
	var ret []*BridgeReq
	_rangeReqs(tr, func(req *BridgeReq) bool {
		if req.Height.Compare(lastHeight) <= 0 {
			return true
		}
		if req.Height.Compare(notAfter) <= 0 {
			ret = append(ret, req)
			return true
		}
		return false
	})
	return ret
}

func (t *BridgeSessionTrie) ListResponsesTo(cid common.ChainID, lastHeight, notAfter common.Height) []*BridgeResp {
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._respTrie(cid, false)
	if tr == nil {
		return nil
	}
	var ret []*BridgeResp
	_rangeResps(tr, func(resp *BridgeResp) bool {
		if resp.BlockHeight.Compare(lastHeight) <= 0 {
			return true
		}
		if resp.BlockHeight.Compare(notAfter) <= 0 {
			ret = append(ret, resp)
			return true
		}
		return false
	})
	return ret
}

func (t *BridgeSessionTrie) ListSessionsAt(cid common.ChainID, at common.Height) (reqs []*BridgeReq, resps []*BridgeResp) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if tr := t._reqTrie(cid, false); tr != nil {
		_rangeReqs(tr, func(req *BridgeReq) bool {
			if cmp := req.Height.Compare(at); cmp < 0 {
				return true
			} else if cmp > 0 {
				return false
			} else {
				reqs = append(reqs, req)
				return true
			}
		})
	}

	if tr := t._respTrie(cid, false); tr != nil {
		_rangeResps(tr, func(resp *BridgeResp) bool {
			if cmp := resp.BlockHeight.Compare(at); cmp < 0 {
				return true
			} else if cmp > 0 {
				return false
			} else {
				resps = append(resps, resp)
				return true
			}
		})
	}

	return
}

func (t *BridgeSessionTrie) AllSessionsTo(targetChain common.ChainID) (reqs []*BridgeReq, resps []*BridgeResp) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if tr := t._reqTrie(targetChain, false); tr != nil {
		_rangeReqs(tr, func(req *BridgeReq) bool {
			reqs = append(reqs, req)
			return true
		})
	}
	if tr := t._respTrie(targetChain, false); tr != nil {
		_rangeResps(tr, func(resp *BridgeResp) bool {
			resps = append(resps, resp)
			return true
		})
	}
	return
}

func (t *BridgeSessionTrie) MinimumHeightOfReqs(cid common.ChainID) (min common.Height, hasData bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if tr := t._reqTrie(cid, false); tr != nil {
		var first *BridgeReq
		_rangeReqs(tr, func(req *BridgeReq) bool {
			if req.Status.IsFailed() {
				return true
			}
			first = req
			return false
		})
		if first == nil {
			return common.NilHeight, false
		} else {
			return first.Height, true
		}
	}
	return common.NilHeight, false
}

func (t *BridgeSessionTrie) MinimumHeightOfResps(cid common.ChainID) (min common.Height, hasData bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if tr := t._respTrie(cid, false); tr != nil {
		var first *BridgeResp
		_rangeResps(tr, func(resp *BridgeResp) bool {
			first = resp
			return false
		})
		if first == nil {
			return common.NilHeight, false
		} else {
			return first.BlockHeight, true
		}
	}
	return common.NilHeight, false
}

func (t *BridgeSessionTrie) ChainIDs() []common.ChainID {
	t.lock.Lock()
	defer t.lock.Unlock()
	var cids []common.ChainID
	it := t.chains.ValueIterator()
	for it.Next() {
		_, v := it.Current()
		if v != nil {
			one := v.(*BridgeTargetNode)
			if one != nil {
				cids = append(cids, one.ToChainID)
			}
		}
	}
	return cids
}

func (t *BridgeSessionTrie) DeleteRequest(toChain common.ChainID, reqHeight common.Height, account common.Address, nonce uint64) *BridgeReq {
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._reqTrie(toChain, false)
	if tr == nil {
		return nil
	}
	changed, oldvalue := tr.Delete(BridgeReqRespKey(reqHeight, account, nonce))
	if !changed || oldvalue == nil {
		return nil
	}
	return oldvalue.(*BridgeReq)
}

func (t *BridgeSessionTrie) RemoveRequests(cid common.ChainID, notAfter common.Height) []*BridgeReq {
	if notAfter.IsNil() {
		return nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._reqTrie(cid, false)
	if tr == nil {
		return nil
	}
	var reqs []*BridgeReq
	it := tr.LiveValueIterator()
	for it.Next() {
		k, v := it.Current()
		if v == nil {
			tr.Delete(k)
			continue
		}
		req := v.(*BridgeReq)
		if req == nil {
			tr.Delete(k)
			continue
		}
		if req.Height.Compare(notAfter) <= 0 {
			if req.Status == BReqSuccess {
				if changed, _ := tr.Delete(k); changed {
					reqs = append(reqs, req)
				}
			} else {
				if req.Status == BReqNotRespond {
					req.Status = BReqFailed
					tr.Put(k, req)
					if config.IsLogOn(config.DataDebugLog) {
						log.Debugf("[BRIDGE] update %s status from %s to %s while remove reqs not after %s at ChainID:%d",
							req, BReqNotRespond, BReqFailed, &notAfter, cid)
					}
				}
			}
		} else {
			break
		}
	}
	return reqs
}

func (t *BridgeSessionTrie) RemoveResponses(cid common.ChainID, notAfter common.Height) []*BridgeResp {
	if notAfter.IsNil() {
		return nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	tr := t._respTrie(cid, false)
	if tr == nil {
		return nil
	}
	var resps []*BridgeResp
	it := tr.LiveValueIterator()
	for it.Next() {
		k, v := it.Current()
		if v == nil {
			tr.Delete(k)
			continue
		}
		resp := v.(*BridgeResp)
		if resp == nil {
			tr.Delete(k)
			continue
		}
		if resp.BlockHeight.Compare(notAfter) <= 0 {
			if changed, _ := tr.Delete(k); changed {
				resps = append(resps, resp)
			}
		} else {
			break
		}
	}
	return resps
}

func (t *BridgeSessionTrie) rangeAll(
	nodeCallback func(node *BridgeTargetNode) error,
	reqCallback func(req *BridgeReq) error,
	respCallback func(resp *BridgeResp) error) error {
	t.lock.Lock()
	nodeIt := t.chains.ValueIterator()
	t.lock.Unlock()
	for nodeIt.Next() {
		_, v := nodeIt.Current()
		node := v.(*BridgeTargetNode)
		if node == nil {
			continue
		}
		if err := nodeCallback(node); err != nil {
			return err
		}
		if len(node.ReqRoot) > 0 {
			reqs := t._createRequestTrie(node.ReqRoot)
			var errr error
			_rangeReqs(reqs, func(req *BridgeReq) bool {
				if err := reqCallback(req); err != nil {
					errr = err
					return false
				}
				return true
			})
			if errr != nil {
				return errr
			}
		}
		if len(node.RespRoot) > 0 {
			resps := t._createResponseTrie(node.RespRoot)
			var errr error
			_rangeResps(resps, func(resp *BridgeResp) bool {
				if err := respCallback(resp); err != nil {
					errr = err
					return false
				}
				return true
			})
			if errr != nil {
				return errr
			}
		}
	}
	return nil
}

type copier struct {
	t          *BridgeSessionTrie
	peerId     common.ChainID
	reqTrie    *trie.RevertableTrie
	reqPutter  *trie.BatchPutter
	respTrie   *trie.RevertableTrie
	respPutter *trie.BatchPutter
}

func (p *copier) reset(cid common.ChainID) error {
	if p.reqTrie != nil {
		if err := p.reqTrie.Commit(); err != nil {
			return fmt.Errorf("commit request trie of PeerChain:%s failed: %v", p.peerId, err)
		}
	}
	p.reqTrie = nil
	p.reqPutter = nil
	if p.respTrie != nil {
		if err := p.respTrie.Commit(); err != nil {
			return fmt.Errorf("commit response trie of PeerChain:%s failed: %v", p.peerId, err)
		}
	}
	p.respTrie = nil
	p.respPutter = nil
	p.peerId = cid
	return nil
}

func (p *copier) putReq(req *BridgeReq) error {
	if req.ToChain != p.peerId {
		return fmt.Errorf("PeerChain:%s not match with %s", p.peerId, req)
	}
	if p.reqTrie == nil {
		p.reqTrie = p.t._reqTrie(req.ToChain, true)
		if liveTrie, err := p.reqTrie.LiveTrie(); err != nil {
			return fmt.Errorf("live trie of requests failed: %v", err)
		} else {
			p.reqPutter = trie.NewBatchPutter(liveTrie, 500)
		}
	}
	if _, err := p.reqPutter.Put(req.Key(), req); err != nil {
		return fmt.Errorf("put %s failed: %v", req, err)
	}
	return nil
}

func (p *copier) putResp(resp *BridgeResp) error {
	if resp.SourceChain != p.peerId {
		return fmt.Errorf("PeerChain:%s not match with %s", p.peerId, resp)
	}
	if p.respTrie == nil {
		p.respTrie = p.t._respTrie(resp.SourceChain, true)
		if liveTrie, err := p.respTrie.LiveTrie(); err != nil {
			return fmt.Errorf("live trie of responses failed: %v", err)
		} else {
			p.respPutter = trie.NewBatchPutter(liveTrie, 500)
		}
	}
	if _, err := p.respPutter.Put(resp.Key(), resp); err != nil {
		return fmt.Errorf("put %s failed: %v", resp, err)
	}
	return nil
}

func (t *BridgeSessionTrie) CopyFrom(from *BridgeSessionTrie) ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	current := &copier{t: t, peerId: common.NilChainID}
	noder := func(node *BridgeTargetNode) error {
		n := node.Clone()
		n.ReqRoot = nil
		n.RespRoot = nil
		t.chains.Put(node.Key(), n)
		return current.reset(n.ToChainID)
	}
	if err := from.rangeAll(noder, current.putReq, current.putResp); err != nil {
		return nil, err
	}
	return t._commit()
}

func (t *BridgeSessionTrie) ToPeerSessions() (peers []*BridgePeerSession, err error) {
	var current *BridgePeerSession
	if err = t.rangeAll(func(node *BridgeTargetNode) error {
		if current != nil {
			peers = append(peers, current)
			current = nil
		}
		current = new(BridgePeerSession)
		current.Node = node
		return nil
	}, func(req *BridgeReq) error {
		if current == nil {
			return errors.New("missing target node while put request")
		}
		current.Reqs = append(current.Reqs, req)
		return nil
	}, func(resp *BridgeResp) error {
		if current == nil {
			return errors.New("missing target node while put response")
		}
		current.Resps = append(current.Resps, resp)
		return nil
	}); err != nil {
		return nil, err
	}
	if current != nil {
		peers = append(peers, current)
	}
	return
}

func (t *BridgeSessionTrie) BuildPeer(peerSession *BridgePeerSession) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if peerSession == nil || peerSession.Node == nil {
		return errors.New("invalid peer session")
	}
	current := &copier{t: t, peerId: common.NilChainID}
	node := peerSession.Node.Clone()
	node.ReqRoot = nil
	node.RespRoot = nil
	t.chains.Put(peerSession.Node.Key(), node)
	if err := current.reset(peerSession.Node.ToChainID); err != nil {
		return err
	}
	for _, req := range peerSession.Reqs {
		if err := current.putReq(req); err != nil {
			return err
		}
	}
	for _, resp := range peerSession.Resps {
		if err := current.putResp(resp); err != nil {
			return err
		}
	}
	_, err := t._preCommit()
	return err
}

func CopyBridgeSessions(fromdb db.Database, root []byte, todb db.Database) (*BridgeSessionTrie, []byte, error) {
	from := NewBridgeSessionTrie(fromdb, root)
	to := NewBridgeSessionTrie(todb, nil)
	if newRoot, err := to.CopyFrom(from); err != nil {
		return nil, nil, err
	} else {
		if !TrieRootEqual(root, newRoot) {
			return nil, nil, fmt.Errorf("source root:%x not match with copyed root:%x",
				common.ForPrint(root), common.ForPrint(newRoot))
		}
		return to, newRoot, nil
	}
}
