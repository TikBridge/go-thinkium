package models

import (
	"math/big"

	"github.com/ThinkiumGroup/go-common"
)

const (
	LegacyTxType = iota
	AccessListTxType
	DynamicFeeTxType
)

// 为了使ETHSigner无状态，Signer中的chainId被取消。因此，当VRS信息不全时，会导致LegacyTx的chainID()和Hash()方法的错误
// Hash()方法返回错误的signature hash值，会影响签名等一系列问题。
// 所以，在GTKM中，LegacyTx只能存储有签名的完全信息。这一点，由所有创建ETHTransaction的地方确保。
// 需要签名时，可以使用Transaction对象
// LegacyTx is the transaction data of regular Ethereum transactions.
type LegacyTx struct {
	Nonce    uint64          // nonce of sender account
	GasPrice *big.Int        // wei per gas
	Gas      uint64          // gas limit
	To       *common.Address `rlp:"nil"` // nil means contract creation
	Value    *big.Int        // wei amount
	Data     []byte          // contract invocation input data
	V, R, S  *big.Int        // signature values
}

//
// // NewTransaction creates an unsigned legacy transaction.
// // Deprecated: use NewEthTx instead.
// func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *ETHTransaction {
// 	return NewEthTx(&LegacyTx{
// 		Nonce:    nonce,
// 		To:       &to,
// 		Value:    amount,
// 		Gas:      gasLimit,
// 		GasPrice: gasPrice,
// 		Data:     data,
// 	})
// }
//
// // NewContractCreation creates an unsigned legacy transaction.
// // Deprecated: use NewEthTx instead.
// func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *ETHTransaction {
// 	return NewEthTx(&LegacyTx{
// 		Nonce:    nonce,
// 		Value:    amount,
// 		Gas:      gasLimit,
// 		GasPrice: gasPrice,
// 		Data:     data,
// 	})
// }

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *LegacyTx) copy() TxData {
	cpy := &LegacyTx{
		Nonce: tx.Nonce,
		To:    tx.To.Clone(), // TODO: copy pointed-to address
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are initialized below.
		Value:    new(big.Int),
		GasPrice: new(big.Int),
		V:        new(big.Int),
		R:        new(big.Int),
		S:        new(big.Int),
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice.Set(tx.GasPrice)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// accessors for innerTx.
func (tx *LegacyTx) TxType() byte           { return LegacyTxType }
func (tx *LegacyTx) chainID() *big.Int      { return deriveChainId(tx.V) }
func (tx *LegacyTx) accessList() AccessList { return nil }
func (tx *LegacyTx) data() []byte           { return tx.Data }
func (tx *LegacyTx) gas() uint64            { return tx.Gas }
func (tx *LegacyTx) gasPrice() *big.Int     { return tx.GasPrice }
func (tx *LegacyTx) gasTipCap() *big.Int    { return tx.GasPrice }
func (tx *LegacyTx) gasFeeCap() *big.Int    { return tx.GasPrice }
func (tx *LegacyTx) value() *big.Int        { return tx.Value }
func (tx *LegacyTx) nonce() uint64          { return tx.Nonce }
func (tx *LegacyTx) to() *common.Address    { return tx.To }

func (tx *LegacyTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *LegacyTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}
