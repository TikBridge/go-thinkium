package models

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

var (
	ErrDuplicatedDeltaFrom = errors.New("duplicated deltas")
)

func init() {
	common.RegisterSystemContract(false,
		AddressOfRequiredReserve,
		AddressOfWriteCashCheck,
		AddressOfCurrencyExchanger,
		AddressOfLocalCurrencyMinter,
		AddressOfSysBridge,
		AddressOfForwarder,
	)

	common.RegisterSystemContract(true,
		AddressOfCashCashCheck,
		AddressOfCancelCashCheck,
		AddressOfChainInfoManage,
		AddressOfManageChains,
		AddressOfChainSettings,
		AddressOfNewChainSettings,
		AddressOfManageCommittee,
		AddressOfBlackHole,
		AddressOfShareReward,
		AddressOfUpdateVersion,
		AddressOfBridgeInfo,
	)

	common.RegisterNoCheckAddress(
		AddressOfRewardFrom,
		AddressOfTryPocFrom,
		AddressOfPenalty,
		AddressOfRequiredReserve, // allow IsSystemContract() but NoCheck() address as transaction sender (AddressOfRequiredReserve)
		AddressOfSysBridge,
		// AddressOfGasReward,
		// AddressOfRewardForGenesis,
	)
}

// Global chain currency query
type GlobalCurrencier interface {
	// Query the chain currency by chain ID, and return (local currency ID, local currency name),
	// when the local currency ID==0, it is the basic currency, when there is no local currency,
	// CoinID returns 0
	GetChainLocalCurrencyInfo(chainID common.ChainID) (common.CoinID, string)
	// Get the list of administrator public keys of the specific chain. If there is a valid value,
	// the second return value will return true, otherwise it will return false
	GetChainAdmins(chainID common.ChainID) ([][]byte, bool)
	// Whether the specific chain is a PoC (Proof of Capacity) chain
	IsPocChain(chainID common.ChainID) bool
}

type GlobalCurrencierAdapter struct {
	dmanager DataManager
}

func NewGlobalCurrencierAdapter(dmanager DataManager) GlobalCurrencier {
	adapter := &GlobalCurrencierAdapter{dmanager: dmanager}
	return adapter
}

func (g *GlobalCurrencierAdapter) GetChainLocalCurrencyInfo(chainID common.ChainID) (coinId common.CoinID, coinName string) {
	info, ok := g.dmanager.GetChainInfos(chainID)
	if ok && !info.SecondCoinId.IsSovereign() {
		return info.SecondCoinId, info.SecondCoinName
	}
	return 0, "TKM"
}

func (g *GlobalCurrencierAdapter) GetChainAdmins(chainID common.ChainID) ([][]byte, bool) {
	var admins [][]byte
	info, ok := g.dmanager.GetChainInfos(chainID)
	if ok {
		admins = info.AdminPubs
		if len(admins) > 0 {
			return admins, true
		}
	}
	if chainID != common.MainChainID {
		return g.GetChainAdmins(common.MainChainID)
	}
	return nil, false
}

func (g *GlobalCurrencierAdapter) IsPocChain(chainID common.ChainID) bool {
	info, ok := g.dmanager.GetChainInfos(chainID)
	if !ok {
		return false
	}
	return info.IsPocChain()
}

// Used to determine whether there is a local currency in the current chain, and if so, what
// is the type of the local currency
type ChainCurrencier interface {
	GlobalCurrencier
	// Whether there is a local currency, if so, the last one method will return the local currency
	// information. Otherwise, the latter one method return basic currency information
	HasLocalCurrency() bool
	// Return (local currency ID, local currency name), when the local currency ID==0, it is the
	// basic currency
	GetLocalCurrency() (common.CoinID, string)
	// Get the list of administrator public keys of the current chain. If there is a valid value,
	// the second return value will return true, otherwise it will return false
	GetAdmins() ([][]byte, bool)
	// Whether the current chain is a PoC (Proof of Capacity) chain
	IsPoc() bool
}

type ChainCurrencierAdapter struct {
	GlobalCurrencier
	CID common.ChainID
}

func NewChainCurrencier(global GlobalCurrencier, chainid common.ChainID) ChainCurrencierAdapter {
	return ChainCurrencierAdapter{
		GlobalCurrencier: global,
		CID:              chainid,
	}
}

func (a ChainCurrencierAdapter) HasLocalCurrency() bool {
	id, _ := a.GetLocalCurrency()
	return id > 0
}

func (a ChainCurrencierAdapter) GetLocalCurrency() (common.CoinID, string) {
	return a.GlobalCurrencier.GetChainLocalCurrencyInfo(a.CID)
}

func (a ChainCurrencierAdapter) GetAdmins() ([][]byte, bool) {
	return a.GlobalCurrencier.GetChainAdmins(a.CID)
}

func (a ChainCurrencierAdapter) IsPoc() bool {
	return a.GlobalCurrencier.IsPocChain(a.CID)
}

type LongValue struct {
	KeyHash common.Hash // long storage key
	Value   []byte      // long value，could be any type of data serialization, resolved by the upper business layer
}

var TypeOfLongStoragePtr = reflect.TypeOf((*LongValue)(nil))

func (v *LongValue) Key() []byte {
	return v.KeyHash[:]
}

func (v *LongValue) HashValue() ([]byte, error) {
	// In this way, the longvalue under the same key will be covered to save space
	return v.KeyHash[:], nil
}

func (v *LongValue) String() string {
	if v == nil {
		return "<nil>"
	}
	if len(v.Value) > 32 {
		return fmt.Sprintf("Long{KeyHash:%x Len(Value):%d}", v.KeyHash[:], len(v.Value))
	} else {
		return fmt.Sprintf("Long{KeyHash:%x Value:%x}", v.KeyHash[:], v.Value)
	}
}

// The Key in LongStorage is composed of account address and additional value (generally attribute
// name), used for system contracts usually
func SCLongStorageKey(addr common.Address, name []byte) common.Hash {
	if len(name) == 0 {
		return common.Hash256(addr[:])
	}
	var source []byte
	source = append(source, addr[:]...)
	source = append(source, name...)
	return common.Hash256(source)
}

func SCLongStorageKey2(addr common.Address, name string) common.Hash {
	return SCLongStorageKey(addr, []byte(name))
}

func ReadLongStorage(statedb StateDB, addr common.Address, name string, decoder func(bs []byte) error) error {
	bs := statedb.GetLong(addr, SCLongStorageKey(addr, []byte(name)))
	return decoder(bs)
}

func SaveLongStorage(statedb StateDB, addr common.Address, name string, bs []byte) {
	if bs == nil {
		statedb.SetLong(addr, SCLongStorageKey(addr, []byte(name)), []byte{})
	} else {
		statedb.SetLong(addr, SCLongStorageKey(addr, []byte(name)), bs)
	}
}

func ReadBigIntLong(statedb StateDB, addr common.Address, name string, defaultValue *big.Int) *big.Int {
	var ret *big.Int
	_ = ReadLongStorage(statedb, addr, name, func(bs []byte) error {
		if len(bs) > 0 {
			r, ok := new(big.Int).SetString(string(bs), 10)
			if !ok {
				log.Warnf("parse *big.Int from %x(%s) failed: [%s]", addr, name, string(bs))
			} else {
				ret = r
			}
		}
		return nil
	})
	if ret == nil && defaultValue != nil {
		ret = new(big.Int).Set(defaultValue)
	}
	return ret
}

func SaveBigIntLong(statedb StateDB, addr common.Address, name string, value *big.Int) {
	if value == nil {
		// clear
		statedb.SetLong(addr, SCLongStorageKey(addr, []byte(name)), []byte{})
	} else {
		v := value.String()
		statedb.SetLong(addr, SCLongStorageKey(addr, []byte(name)), []byte(v))
	}
}

func ReadBigRatLong(statedb StateDB, addr common.Address, name string, defaultValue *big.Rat) *big.Rat {
	var ret *big.Rat
	_ = ReadLongStorage(statedb, addr, name, func(bs []byte) error {
		if len(bs) > 0 {
			r, ok := new(big.Rat).SetString(string(bs))
			if !ok {
				log.Warnf("parse *big.Int from %x(%s) failed: [%s]", addr, name, string(bs))
			} else {
				ret = r
			}
		}
		return nil
	})
	if ret == nil && defaultValue != nil {
		ret = new(big.Rat).Set(defaultValue)
	}
	return ret
}

func SaveBigRatLong(statedb StateDB, addr common.Address, name string, value *big.Rat) {
	if value == nil {
		statedb.SetLong(addr, SCLongStorageKey(addr, []byte(name)), []byte{})
	} else {
		v := value.String()
		statedb.SetLong(addr, SCLongStorageKey(addr, []byte(name)), []byte(v))
	}
}

func ReadRatioLong(statedb StateDB, addr common.Address, name string, defaultValue *big.Rat) *big.Rat {
	r := ReadBigRatLong(statedb, addr, name, defaultValue)
	if r.Sign() <= 0 || r.Cmp(math.Rat1) > 0 {
		return math.CopyBigRat(defaultValue)
	}
	return r
}

// read *big.Int from ChainSetting which serialized as a string
func ReadBigIntChainSetting(statedb StateDB, name string, defaultValue *big.Int) *big.Int {
	return ReadBigIntLong(statedb, AddressOfChainSettings, name, defaultValue)
}

func SaveBigIntChainSetting(statedb StateDB, name string, value *big.Int) {
	SaveBigIntLong(statedb, AddressOfChainSettings, name, value)
}

func ReadBigRatChainSetting(statedb StateDB, name string, defaultValue *big.Rat) *big.Rat {
	return ReadBigRatLong(statedb, AddressOfChainSettings, name, defaultValue)
}

func ReadRatioChainSetting(statedb StateDB, name string, defaultValue *big.Rat) *big.Rat {
	return ReadRatioLong(statedb, AddressOfChainSettings, name, defaultValue)
}

func SaveBigRatChainSetting(statedb StateDB, name string, value *big.Rat) {
	SaveBigRatLong(statedb, AddressOfChainSettings, name, value)
}

func ReadUint64ChainSetting(statedb StateDB, name string, defaultValue uint64) uint64 {
	bs := statedb.GetLong(AddressOfChainSettings, SCLongStorageKey2(AddressOfChainSettings, name))
	if len(bs) != 8 {
		return defaultValue
	}
	return binary.BigEndian.Uint64(bs)
}

func SaveUint64ChainSetting(statedb StateDB, name string, value *uint64) {
	if value == nil {
		statedb.SetLong(AddressOfChainSettings, SCLongStorageKey2(AddressOfChainSettings, name), []byte{})
	} else {
		bs := make([]byte, 8)
		binary.BigEndian.PutUint64(bs, *value)
		statedb.SetLong(AddressOfChainSettings, SCLongStorageKey2(AddressOfChainSettings, name), bs)
	}
}

func ReadAddressChainSetting(statedb StateDB, name string) (common.Address, bool) {
	bs := statedb.GetLong(AddressOfChainSettings, SCLongStorageKey2(AddressOfChainSettings, name))
	if len(bs) != common.AddressLength {
		return common.Address{}, false
	}
	return common.BytesToAddress(bs), true
}

func SaveAddressChainSettings(statedb StateDB, name string, addr common.Address) {
	statedb.SetLong(AddressOfChainSettings, SCLongStorageKey2(AddressOfChainSettings, name), addr[:])
}

func DeleteAddressChainSettings(statedb StateDB, name string) {
	statedb.SetLong(AddressOfChainSettings, SCLongStorageKey2(AddressOfChainSettings, name), []byte{})
}

type (
	GasStackRecord struct {
		Addr    common.Address // the address of the called contract
		In      uint64         // gas left in evm when pushed to stack
		TopUsed uint64         // gas used by contracts in the stack on top of the current record
	}

	GasStack struct {
		initialGas uint64                    // initial gas of the tx
		stack      []*GasStackRecord         // contracts called stack
		used       map[common.Address]uint64 // record Contract.Address->SumGasUsed
		lock       sync.Mutex
	}
)

func (r *GasStackRecord) String() string {
	if r == nil {
		return "GasRec<nil>"
	}
	return fmt.Sprintf("GasRec{Addr:%x In:%d TopUsed:%d}", r.Addr[:], r.In, r.TopUsed)
}

func (r *GasStackRecord) Used(leftover uint64) (oneLayerUsed, allLayerUsed uint64, err error) {
	if x, overflow := math.SafeAdd(leftover, r.TopUsed); overflow {
		return 0, 0, fmt.Errorf("record.TopUsed(%d) + Leftover(%d) overflowed", r.TopUsed, leftover)
	} else {
		if x > r.In {
			return 0, 0, fmt.Errorf("record.TopUsed(%d) + Leftover(%d) is bigger than record.In(%d)",
				r.TopUsed, leftover, r.In)
		}
		return r.In - x, r.In - leftover, nil
	}
}

func (r *GasStackRecord) AddTopUsed(used uint64) error {
	u, overflow := math.SafeAdd(r.TopUsed, used)
	if overflow {
		return fmt.Errorf("%s.AddTopUsed(%d) overflowed", r, used)
	}
	r.TopUsed = u
	return nil
}

func (s *GasStack) SetInitialGas(gas uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.initialGas = gas
}

func (s *GasStack) Push(addr common.Address, gas uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(s.stack) == 0 {
		if s.initialGas == 0 {
			return
		}
		// tx call entry
		gas = s.initialGas
	}
	record := &GasStackRecord{
		Addr:    addr,
		In:      gas,
		TopUsed: 0,
	}
	s.stack = append(s.stack, record)
}

func (s *GasStack) Pop(addr common.Address, leftover uint64, iscreatings ...bool) (rec *GasStackRecord, used uint64, err error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	iscreating := false
	if len(iscreatings) > 0 {
		iscreating = iscreatings[0]
	}
	defer func() {
		if config.IsLogOn(config.VmDebugLog) {
			if err != nil {
				log.Errorf("[GASSTACK] pop(leftover:%d iscreating:%t) failed: %v", leftover, iscreating, err)
			} else {
				log.Debugf("[GASSTACK] pop(leftover:%d iscreating:%t) %s, gas used:%d", leftover, iscreating, rec, used)
			}
		}
	}()
	if len(s.stack) == 0 {
		return nil, 0, errors.New("empty gas stack")
	}
	record := s.stack[len(s.stack)-1]
	if record.Addr != addr {
		return nil, 0, errors.New("address not match")
	}

	// calculate the gas used by addr in this call
	var aboveused uint64
	used, aboveused, err = record.Used(leftover)
	if err != nil {
		return nil, 0, err
	}

	// pre-calculate the aggregation of used gas in the addr
	allused := used
	if s.used != nil {
		old, exist := s.used[addr]
		if exist {
			var overflow bool
			allused, overflow = math.SafeAdd(old, used)
			if overflow {
				return nil, 0, fmt.Errorf("aggregation of gas used in %x overflowed by (%d + %d)",
					addr[:], old, used)
			}
		}
	}

	// update TopUsed under the poping record
	if len(s.stack) > 1 {
		if err := s.stack[len(s.stack)-2].AddTopUsed(aboveused); err != nil {
			return nil, 0, err
		}
	}
	// update aggregation of used gas
	if s.used == nil {
		s.used = make(map[common.Address]uint64)
	}
	s.used[addr] = allused
	// pop
	s.stack = s.stack[:len(s.stack)-1]

	return record, used, nil
}

func (s *GasStack) Finished() bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.stack) == 0 && len(s.used) > 0
}

func (s *GasStack) _usedRatio() (ratios map[common.Address]*big.Rat, max common.Address) {
	if len(s.used) == 0 {
		return nil, common.Address{}
	}
	type temp struct {
		addr common.Address
		used *big.Int
	}
	sum := math.NewBigInt(nil)
	var sorter []temp
	for addr, used := range s.used {
		u := new(big.Int).SetUint64(used)
		sum = sum.AddInt(u)
		sorter = append(sorter, temp{
			addr: addr,
			used: u,
		})
	}
	if !sum.Positive() || len(sorter) == 0 {
		return nil, common.Address{}
	}
	sort.Slice(sorter, func(i, j int) bool {
		cmp := math.CompareBigInt(sorter[i].used, sorter[j].used)
		if cmp == 0 {
			return bytes.Compare(sorter[i].addr[:], sorter[j].addr[:]) < 0
		}
		return cmp < 0
	})
	max = sorter[len(sorter)-1].addr

	ret := make(map[common.Address]*big.Rat)
	for _, t := range sorter {
		a := t.used
		b := sum.Clone().Int()
		r := new(big.Rat).SetFrac(a, b)
		ret[t.addr] = r
	}
	return ret, max
}

//
// func (s *GasStack) UsedRatio() map[common.Address]*big.Rat {
// 	s.lock.Lock()
// 	defer s.lock.Unlock()
// 	return s._usedRatio()
// }

func (s *GasStack) _info() string {
	return fmt.Sprintf("GasStack{InitialGas:%d %s, %v}", s.initialGas, s.stack, s.used)
}

func (s *GasStack) Info() string {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s._info()
}

func (s *GasStack) Bonus(bonus *big.Int) (map[common.Address]*big.Int, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if bonus == nil {
		return nil, nil
	}
	left := math.NewBigInt(bonus)
	b := math.NewBigInt(bonus)
	if !b.Positive() {
		return nil, errors.New("no positive bonus")
	}
	ratios, maxaddr := s._usedRatio()
	if len(ratios) == 0 {
		return nil, errors.New("no used ratios")
	}
	ret := make(map[common.Address]*big.Int)
	for addr, ratio := range ratios {
		if addr == maxaddr {
			continue
		}
		val := b.Clone().MulRat(ratio)
		if val.Positive() {
			left = left.Sub(val)
			if left.Negative() {
				return nil, errors.New("negative bonus left")
			}
			ret[addr] = val.MustInt()
		}
	}
	ret[maxaddr] = left.MustInt()
	if config.IsLogOn(config.VmDebugLog) {
		log.Debugf("[GASSTACK] Bonus(%s), Ratios(%s), %s, %s", math.BigForPrint(bonus), ratios, s._info(), ret)
	}
	return ret, nil
}

// Message EVM message
type Message struct {
	to         *common.Address
	from       common.Address
	nonce      uint64
	useLocal   bool
	amount     *big.Int
	gasLimit   uint64
	gasPrice   *big.Int
	gasFeeCap  *big.Int
	gasTipCap  *big.Int
	data       []byte
	checkNonce bool
	bodyhash   common.Hash
	txhash     common.Hash
	senderSig  *PubAndSig
	multiSigs  PubAndSigs
	version    uint16
}

func NewMessage(bodyhash common.Hash, txhash common.Hash, from common.Address, to *common.Address, nonce uint64, useLocal bool,
	amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, checkNonce bool, senderSig *PubAndSig,
	multiSigs PubAndSigs, version uint16) Message {
	return Message{
		from:       from,
		to:         to,
		nonce:      nonce,
		useLocal:   useLocal,
		amount:     math.MustBigInt(math.CopyBigInt(amount)),
		gasLimit:   gasLimit,
		gasPrice:   gasPrice,
		gasFeeCap:  big.NewInt(0),
		gasTipCap:  big.NewInt(0),
		data:       data,
		checkNonce: checkNonce,
		bodyhash:   bodyhash,
		txhash:     txhash,
		senderSig:  senderSig,
		multiSigs:  multiSigs,
		version:    version,
	}
}

func (m Message) From() common.Address   { return m.from }
func (m Message) To() *common.Address    { return m.to }
func (m Message) GasPrice() *big.Int     { return m.gasPrice }
func (m Message) GasFeeCap() *big.Int    { return m.gasFeeCap }
func (m Message) GasTipCap() *big.Int    { return m.gasTipCap }
func (m Message) UseLocal() bool         { return m.useLocal }
func (m Message) Value() *big.Int        { return m.amount }
func (m Message) Gas() uint64            { return m.gasLimit }
func (m Message) Nonce() uint64          { return m.nonce }
func (m Message) IsFake() bool           { return false }
func (m Message) Data() []byte           { return m.data }
func (m Message) AccessList() AccessList { return nil }
func (m Message) CheckNonce() bool       { return m.checkNonce }
func (m Message) TxHash() common.Hash    { return m.txhash }
func (m Message) Sig() *PubAndSig        { return m.senderSig }
func (m Message) MultiSigs() PubAndSigs  { return m.multiSigs }
func (m Message) Version() uint16        { return m.version }

func (m Message) String() string {
	return fmt.Sprintf("Msg{From:%s To:%s Nonce:%d Input:%d Hash:%x}",
		m.from, m.to.ToString(), m.nonce, len(m.data), m.txhash[:])
}

func (m Message) VerifyNonce(statedb StateDB) error {
	if m.checkNonce {
		nonce := statedb.GetNonce(m.from)
		if nonce < m.nonce {
			if config.IsLogOn(config.VmDebugLog) {
				log.Errorf("[VM] preCheck state nonce %d and msg nonce %d", nonce, m.nonce)
			}
			return ErrNonceTooHighForVersion0
		} else if nonce > m.nonce {
			if config.IsLogOn(config.VmDebugLog) {
				log.Errorf("[VM] preCheck state nonce %d and msg nonce %d", nonce, m.nonce)
			}
			return ErrNonceTooLowForVersion0
		}
	}
	return nil
}

// AllValidSigns Traverse all the valid signatures without repetition, call the callback method, and return
// the map with the key as the public key of the valid signature
func (m Message) AllValidSigns(callback func(pas *PubAndSig)) map[string]struct{} {
	r := make(map[string]struct{}, len(m.multiSigs)+1)
	{
		ok, pubkey := VerifyHashWithPub(m.bodyhash[:], m.senderSig.PublicKey, m.senderSig.Signature)
		if ok {
			r[string(pubkey)] = struct{}{}
			if callback != nil {
				callback(&PubAndSig{PublicKey: pubkey, Signature: m.senderSig.Signature})
			}
		}
	}
	if len(m.multiSigs) == 0 {
		return r
	}
	for _, sig := range m.multiSigs {
		if sig == nil {
			continue
		}
		ok, pubkey := VerifyHashWithPub(m.bodyhash[:], sig.PublicKey, sig.Signature)
		if !ok {
			continue
		}
		_, exist := r[string(pubkey)]
		if exist {
			continue
		}
		r[string(pubkey)] = struct{}{}
		if callback != nil {
			callback(&PubAndSig{PublicKey: pubkey, Signature: sig.Signature})
		}
	}
	return r
}

// SignedPubs Returns an unordered list of all correctly signed public keys
func (m Message) SignedPubs() map[string]struct{} {
	return m.AllValidSigns(nil)
}

// SignedAddresses Returns the unordered list of addresses corresponding to all correctly signed public keys
func (m Message) SignedAddresses() map[common.Address]struct{} {
	r := make(map[common.Address]struct{}, len(m.multiSigs)+1)
	m.AllValidSigns(func(pas *PubAndSig) {
		addr, err := common.AddressFromPubSlice(pas.PublicKey)
		if err != nil {
			return
		}
		r[addr] = struct{}{}
	})
	return r
}

var (
	ErrNonceTooHighForVersion0 = NewVersionError(TxVersion0, errors.New("nonce too high"))
	ErrNonceTooLowForVersion0  = NewVersionError(TxVersion0, errors.New("nonce too low"))
)

type versionError struct {
	version uint16
	err     error
}

func NewVersionError(version uint16, err error) error {
	return &versionError{version, err}
}

func (ve *versionError) Version() uint16 {
	return ve.version
}

func (ve *versionError) Error() string {
	return ve.err.Error()
}

func (ve *versionError) Unwrap() error {
	return ve.err
}

func AppendRevertMsg(err error, ret []byte) error {
	if err.Error() != ErrExecutionReverted.Error() {
		return err
	}
	return NewRevertError(ret)
}

func NewRevertError(revertMsg []byte) error {
	reason, errUnpack := abi.UnpackRevert(revertMsg)
	err := errors.New("execution reverted")
	if errUnpack == nil {
		err = fmt.Errorf("execution reverted: %v", reason)
	}
	return &revertError{
		error:  err,
		reason: hexutil.Encode(revertMsg),
	}
}

// revertError is an API error that encompassas an EVM revertal with JSON error
// code and a binary data blob.
type revertError struct {
	error
	reason string // revert reason hex encoded
}

// ErrorCode returns the JSON error code for a revertal.
// See: https://github.com/ethereum/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
func (e *revertError) ErrorCode() int {
	return 3
}

// ErrorData returns the hex encoded revert reason.
func (e *revertError) ErrorData() interface{} {
	return e.reason
}
