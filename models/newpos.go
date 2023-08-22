package models

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/sirupsen/logrus"
)

type (
	ProcessContext struct {
		RRState *RRStateDB
		DBase   db.Database
		RRTrie  trie.ITrie
	}

	RRActProcessor interface {
		// check legality of parameters, called by addChangingLocked
		CheckParams(ctx *ProcessContext, info *RRInfo, isGen bool, typ common.NodeType, nodeIdHash common.Hash,
			addr common.Address, amount *big.Int, chargeRatio *big.Rat, withNodeSig bool, changing *RRC) (err error)

		// create RRAct by parameters, called by addChangingLocked
		// There will be a check later in RRC.AddAct, so this method does not need to check
		// compatibility with the RRAct queue in RRC
		CreateAct(ctx *ProcessContext, info *RRInfo, isGen bool, changing *RRC,
			fromChain common.ChainID, fromTxHash common.Hash, height common.Height, typ common.NodeType,
			nodeIdHash common.Hash, addr common.Address, amount *big.Int, chargeRatio *big.Rat,
			currentEra common.EraNum) (*RRAct, error)

		// called by applyChanges
		Apply(ctx *ProcessContext, info *RRInfo, isGen bool, changing *RRC,
			act *RRAct, effectEra common.EraNum, logger logrus.FieldLogger) (changed bool, created bool,
			shouldRemove bool, newinfo *RRInfo, receipt ActResult, fatal error)
	}
)

var (
	actProcessors = make(map[RRAType]RRActProcessor)
)

func RegisterActProcessor(actType RRAType, processor RRActProcessor) {
	if !actType.Valid() || processor == nil {
		panic(fmt.Errorf("invalid acttype:%s or processor==nil:%t", actType, processor == nil))
	}
	actProcessors[actType] = processor
	log.Infof("ActType:%s Processor registerred", actType)
}

func ActProccessor(actType RRAType) RRActProcessor {
	p, _ := actProcessors[actType]
	return p
}

type accState struct {
	nonce   uint64
	balance *big.Int
}

type RRStateDB struct {
	statedb StateDB
	lock    sync.Mutex

	// cache
	maxDepositSum     *big.Int
	baseDepositSum    *big.Int
	depositFactor     *big.Int
	attenuationFactor int64 // floor((MaxDepositSum-BaseDepositSum)/DepositFactor)

	baseCoefficient       *big.Rat
	coefficientFactor     *big.Rat
	coefficientLowerLimit *big.Rat
	coefficient           *big.Rat // max( (baseCoefficient - attenuationFactor * coefficientFactor), coefficientLowerLimit )

	erasPerYear common.EraNum

	consensusDepSum *big.Int
	delegatedSum    *big.Int
	dataDepSum      *big.Int

	minDepositEras common.EraNum

	consensusRewardFactor *big.Rat
	delegatedRewardFactor *big.Rat
	dataRewardFactor      *big.Rat
	auditorRewardFactor   *big.Rat

	minConsensus, maxConsensus *big.Int
	minData, maxData           *big.Int

	delegateLimit *big.Int

	rrWhiteAddr *common.Address

	rewardAccState  *accState
	depositAccState *accState
	penaltyAccState *accState
}

func NewRRStateDB(statedb StateDB) *RRStateDB {
	return &RRStateDB{
		statedb:           statedb,
		attenuationFactor: -1,
		erasPerYear:       common.NilEra,
		minDepositEras:    common.NilEra,
	}
}

func (a *RRStateDB) _getAndLoadBigInt(bigint **big.Int, name string, defaultInt *big.Int, canBeZero bool) *big.Int {
	if defaultInt == nil {
		panic(fmt.Errorf("name:%s with nil default value", name))
	}
	if *bigint == nil {
		val := ReadBigIntChainSetting(a.statedb, name, defaultInt)
		if canBeZero {
			if val.Sign() < 0 {
				val = math.CopyBigInt(defaultInt)
			}
		} else {
			if val.Sign() <= 0 {
				val = math.CopyBigInt(defaultInt)
			}
		}
		*bigint = val
	}
	return math.CopyBigInt(*bigint)
}

func (a *RRStateDB) _getAndLoadBigRat(bigrat **big.Rat, name string, defaultRat *big.Rat, canBeZero bool) *big.Rat {
	if defaultRat == nil {
		panic(fmt.Errorf("name:%s with nil default value", name))
	}
	if *bigrat == nil {
		val := ReadBigRatChainSetting(a.statedb, name, defaultRat)
		if math.CompareBigRat(val, math.Rat1) > 0 {
			val = math.CopyBigRat(defaultRat)
		} else {
			if canBeZero {
				if val.Sign() < 0 {
					val = math.CopyBigRat(defaultRat)
				}
			} else {
				if val.Sign() <= 0 {
					val = math.CopyBigRat(defaultRat)
				}
			}
		}
		*bigrat = val
	}
	return math.CopyBigRat(*bigrat)
}

func (a *RRStateDB) _getAndLoadEra(era *common.EraNum, name string, defaultVal uint64, canBeZero bool) common.EraNum {
	if (*era).IsNil() {
		e := common.EraNum(ReadUint64ChainSetting(a.statedb, name, defaultVal))
		if !canBeZero && e == 0 {
			e = common.EraNum(defaultVal)
		}
		*era = e
	}
	return *era
}

func (a *RRStateDB) StateDB() StateDB {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.statedb
}

func (a *RRStateDB) _resetAttenuationFactorCache() {
	a.attenuationFactor = -1
	a.minDepositEras = common.NilEra
	a.coefficient = nil
}

func (a *RRStateDB) _maxDepositSum() *big.Int {
	if a.maxDepositSum == nil {
		a.maxDepositSum = ReadBigIntLong(a.statedb, AddressOfRequiredReserve, RRMaxDepositSumName, nil)
		if a.maxDepositSum == nil {
			a.maxDepositSum = a.statedb.GetBalance(AddressOfRequiredReserve)
		}
	}
	return math.CopyBigInt(a.maxDepositSum)
}

func (a *RRStateDB) MaxDepositSum() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._maxDepositSum()
}

func (a *RRStateDB) CASMaxDepositSum(newValue *big.Int) bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	if newValue == nil || newValue.Sign() <= 0 {
		return false
	}
	old := a._maxDepositSum()
	if newValue.Cmp(old) > 0 {
		SaveBigIntLong(a.statedb, AddressOfRequiredReserve, RRMaxDepositSumName, newValue)
		a.maxDepositSum = new(big.Int).Set(newValue)
		a._resetAttenuationFactorCache()
		return true
	}
	return false
}

func (a *RRStateDB) _attenuationFactor() int64 {
	if a.attenuationFactor < 0 {
		m := a._maxDepositSum()
		b := a._getAndLoadBigInt(&(a.baseDepositSum), RRBaseDepositSumName, DefaultBaseDepositSumBig, true)
		if m.Cmp(b) > 0 {
			d := a._getAndLoadBigInt(&(a.depositFactor), RRDepositFactorName, DefaultDepositFactorBig, false)
			mb := new(big.Int).Sub(m, b)
			mb.Div(mb, d)
			a.attenuationFactor = mb.Int64()
		} else {
			a.attenuationFactor = 0
		}
	}
	return a.attenuationFactor
}

func (a *RRStateDB) _coefficient() *big.Rat {
	if a.coefficient == nil {
		f := a._getAndLoadBigRat(&(a.coefficientFactor), RRCoefficientFactorName, DefaultCoefficientFactorBig, true)
		af := a._attenuationFactor()
		f = f.Mul(f, big.NewRat(af, 1))
		b := a._getAndLoadBigRat(&(a.baseCoefficient), RRBaseCoefficientName, DefaultBaseCoefficientBig, false)
		if b.Cmp(f) > 0 {
			b = b.Sub(b, f)
			limit := a._getAndLoadBigRat(&(a.coefficientLowerLimit), RRCoefficientLowerLimitName, DefaultCoefficientLowerLimitBig, false)
			if b.Cmp(limit) >= 0 {
				a.coefficient = b
			} else {
				a.coefficient = limit
			}
		} else {
			a.coefficient = a._getAndLoadBigRat(&(a.coefficientLowerLimit), RRCoefficientLowerLimitName, DefaultCoefficientLowerLimitBig, false)
		}
	}
	return math.CopyBigRat(a.coefficient)
}

func (a *RRStateDB) Coefficient() *big.Rat {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._coefficient()
}

func (a *RRStateDB) _erasPerYear() int64 {
	era := a._getAndLoadEra(&(a.erasPerYear), RRErasPerYearName, DefaultErasPerYear, false)
	if era > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(era)
}

func (a *RRStateDB) _rewardValue(sum *big.Int, factor *big.Rat) *big.Int {
	if !(*math.BigInt)(sum).Positive() {
		return nil
	}
	c := a._coefficient()
	f := factor.Mul(factor, c)
	// x/y = factor * coefficient
	x := f.Num()
	y := f.Denom()

	x = x.Mul(x, sum)
	result := x.Div(x, y) // result = sum * x / y = sum * factor * coefficient
	result = result.Div(result, big.NewInt(a._erasPerYear()))
	return result
}

func (a *RRStateDB) SaveConsensusDepSum(newValue *big.Int) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if !(*math.BigInt)(newValue).Positive() {
		newValue = big.NewInt(0)
	}
	SaveBigIntLong(a.statedb, AddressOfRequiredReserve, RRConsensusDepSumName, newValue)
	a.consensusDepSum = math.CopyBigInt(newValue)
}

func (a *RRStateDB) ConsensusDepSum() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.consensusDepSum == nil {
		a.consensusDepSum = ReadBigIntLong(a.statedb, AddressOfRequiredReserve, RRConsensusDepSumName, nil)
	}
	return math.CopyBigInt(a.consensusDepSum)
}

func (a *RRStateDB) _consensusRewardFactor() *big.Rat {
	return a._getAndLoadBigRat(&(a.consensusRewardFactor), RRConsensusRewardFactorName, DefaultConsensusRewardFactorBig, true)
}

func (a *RRStateDB) ConsensusRewardFactor() *big.Rat {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._consensusRewardFactor()
}

func (a *RRStateDB) ConsensusRewardValue(sum *big.Int) *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	f := a._consensusRewardFactor()
	return a._rewardValue(sum, f)
}

func (a *RRStateDB) SaveDelegatedSum(newValue *big.Int) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if !(*math.BigInt)(newValue).Positive() {
		newValue = big.NewInt(0)
	}
	SaveBigIntLong(a.statedb, AddressOfRequiredReserve, RRDelegatedSumName, newValue)
	a.delegatedSum = math.CopyBigInt(newValue)
}

func (a *RRStateDB) DelegatedSum() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.delegatedSum == nil {
		a.delegatedSum = ReadBigIntLong(a.statedb, AddressOfRequiredReserve, RRDelegatedSumName, nil)
	}
	return math.CopyBigInt(a.delegatedSum)
}

func (a *RRStateDB) _delegatedRewardFactor() *big.Rat {
	return a._getAndLoadBigRat(&(a.delegatedRewardFactor), RRDelegatedRewardFactorName, DefaultDelegatedRewardFactorBig, true)
}

func (a *RRStateDB) DelegatedRewardFactor() *big.Rat {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._delegatedRewardFactor()
}

func (a *RRStateDB) DelegatedRewardValue(sum *big.Int) *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	f := a._delegatedRewardFactor()
	return a._rewardValue(sum, f)
}

func (a *RRStateDB) SaveDataDepSum(newValue *big.Int) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if !(*math.BigInt)(newValue).Positive() {
		newValue = big.NewInt(0)
	}
	SaveBigIntLong(a.statedb, AddressOfRequiredReserve, RRDataDepSumName, newValue)
	a.dataDepSum = math.CopyBigInt(newValue)
}

func (a *RRStateDB) DataDepSum() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.dataDepSum == nil {
		a.dataDepSum = ReadBigIntLong(a.statedb, AddressOfRequiredReserve, RRDataDepSumName, nil)
	}
	return math.CopyBigInt(a.dataDepSum)
}

func (a *RRStateDB) _dataRewardFactor() *big.Rat {
	return a._getAndLoadBigRat(&(a.dataRewardFactor), RRDataRewardFactorName, DefaultDataRewardFactorBig, true)
}

func (a *RRStateDB) DataRewardFactor() *big.Rat {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._dataRewardFactor()
}

func (a *RRStateDB) DataRewardValue(sum *big.Int) *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	f := a._dataRewardFactor()
	return a._rewardValue(sum, f)
}

func (a *RRStateDB) _auditorRewardFactor() *big.Rat {
	return a._getAndLoadBigRat(&(a.auditorRewardFactor), RRAuditorRewardFactorName, DefaultAuditorRewardFactorBig, true)
}

func (a *RRStateDB) AuditorRewardFactor() *big.Rat {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._auditorRewardFactor()
}

func (a *RRStateDB) AuditorRewardValue(sum *big.Int) *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	f := a._auditorRewardFactor()
	return a._rewardValue(sum, f)
}

func (a *RRStateDB) MinConsensusRR() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._getAndLoadBigInt(&(a.minConsensus), RRConsensusMinName, DefaultMinConsensusRRBig, true)
}

func (a *RRStateDB) AvailableAmount(nodeType common.NodeType, amount *big.Int) *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	if amount == nil || amount.Sign() <= 0 {
		return nil
	}
	switch nodeType {
	case common.Consensus:
		min := a._getAndLoadBigInt(&(a.minConsensus), RRConsensusMinName, DefaultMinConsensusRRBig, true)
		max := a._getAndLoadBigInt(&(a.maxConsensus), RRConsensusMaxName, DefaultMaxConsensusRRBig, false)
		if amount.Cmp(min) < 0 {
			return nil
		}
		if amount.Cmp(max) > 0 {
			return max
		}
		return math.CopyBigInt(amount)
	case common.Data:
		min := a._getAndLoadBigInt(&(a.minData), RRDataMinName, DefaultMinDataRRBig, true)
		max := a._getAndLoadBigInt(&(a.maxData), RRDataMaxName, DefaultMaxDataRRBig, false)
		if amount.Cmp(min) < 0 {
			return nil
		}
		if amount.Cmp(max) > 0 {
			return max
		}
		return math.CopyBigInt(amount)
	default:
		return nil
	}
}

func (a *RRStateDB) DelegateLimit() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.delegateLimit == nil {
		a.delegateLimit = ReadBigIntChainSetting(a.statedb, RRDelegateLimitName, DefaultDelegateLimitBig)
	}
	return math.CopyBigInt(a.delegateLimit)
}

func (a *RRStateDB) _whiteListAddress() *common.Address {
	if a.rrWhiteAddr == nil {
		one, ok := ReadAddressChainSetting(a.statedb, RRWhiteListAddrName)
		if !ok {
			addr := common.EmptyAddress
			a.rrWhiteAddr = &addr
			// } else {
			// 	acc := a.statedb.Account(one)
			// 	if acc == nil || acc.IsUserContract() == false {
			// 		log.Errorf("[REWARD] WhiteList address is not exist nor user contract")
			// 		one = common.EmptyAddress
			// 	}
			// 	a.rrWhiteAddr = &one
		}
		a.rrWhiteAddr = &one
	}
	if *a.rrWhiteAddr == common.EmptyAddress {
		return nil
	} else {
		return a.rrWhiteAddr
	}
}

func (a *RRStateDB) WhiteListAddress() *common.Address {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a._whiteListAddress()
}

func (a *RRStateDB) IsWhiteListAddress(addr common.Address) bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	whiteAddr := a._whiteListAddress()
	if whiteAddr != nil && *whiteAddr == addr {
		return true
	}
	return false
}

func (a *RRStateDB) _accState(addr common.Address, state **accState) *accState {
	if *state == nil {
		nonce := a.statedb.GetNonce(addr)
		balance := a.statedb.GetBalance(addr)
		*state = &accState{
			nonce:   nonce,
			balance: balance,
		}
	}
	return *state
}

func (a *RRStateDB) RewardAccNextNonce() uint64 {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRewardFrom, &(a.rewardAccState))
	nonce := state.nonce
	state.nonce++
	return nonce
}

func (a *RRStateDB) RewardAccNonce() uint64 {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRewardFrom, &(a.rewardAccState))
	return state.nonce
}

func (a *RRStateDB) RewardAccSetNonce(nonce uint64) {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRewardFrom, &(a.rewardAccState))
	state.nonce = nonce
}

func (a *RRStateDB) RewardAccSubBalance(amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("illegal amount")
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRewardFrom, &(a.rewardAccState))
	if math.CompareBigInt(state.balance, amount) >= 0 {
		state.balance.Sub(state.balance, amount)
		return nil
	}
	return common.ErrInsufficientBalance
}

func (a *RRStateDB) RewardAccBalance() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRewardFrom, &(a.rewardAccState))
	return math.CopyBigInt(state.balance)
}

func (a *RRStateDB) DepositAccNextNonce() uint64 {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRequiredReserve, &(a.depositAccState))
	nonce := state.nonce
	state.nonce++
	return nonce
}

func (a *RRStateDB) DepositAccSubBalance(amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("illegal amount")
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRequiredReserve, &(a.depositAccState))
	if math.CompareBigInt(state.balance, amount) >= 0 {
		state.balance.Sub(state.balance, amount)
		return nil
	}
	return common.ErrInsufficientBalance
}

func (a *RRStateDB) DepositAccBalance() *big.Int {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfRequiredReserve, &(a.depositAccState))
	return math.CopyBigInt(state.balance)
}

func (a *RRStateDB) PenaltyAccNextNonce() uint64 {
	a.lock.Lock()
	defer a.lock.Unlock()
	state := a._accState(AddressOfPenalty, &(a.penaltyAccState))
	nonce := state.nonce
	state.nonce++
	return nonce
}
