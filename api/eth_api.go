package api

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/dao"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/ThinkiumGroup/go-thinkium/tkmrpc"
)

// PublicBlockChainAPI provides an API to access the Ethereum blockchain.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicBlockChainAPI struct {
	chainID  common.ChainID
	nmanager models.NetworkManager
	dmanager models.DataManager
	engine   models.Engine
	eventer  models.Eventer
}

func NewPublicBlockChainAPI(nmanager models.NetworkManager, dmanager models.DataManager,
	engine models.Engine, eventer models.Eventer) *PublicBlockChainAPI {
	return &PublicBlockChainAPI{
		nmanager: nmanager,
		dmanager: dmanager,
		engine:   engine,
		eventer:  eventer,
	}
}

func (api *PublicBlockChainAPI) SetChainID(chainID common.ChainID) {
	api.chainID = chainID
}

func (api *PublicBlockChainAPI) Accounts() []common.Address {
	var addrs []common.Address
	return addrs
}

func (api *PublicBlockChainAPI) BlockNumber(context.Context) hexutil.Uint64 {
	stats, err := api.dmanager.GetChainStats(api.chainID)
	if err != nil {
		return hexutil.Uint64(0)
	}
	return hexutil.Uint64(stats.CurrentHeight)
}

func (api *PublicBlockChainAPI) ChainLatestComm(ctx context.Context) (map[string]interface{}, error) {
	if api.dmanager.IsDataNode() || api.dmanager.IsMemoNode() {
		chainId := api.dmanager.DataOrMemoOf()
		stats, err := api.dmanager.GetChainStats(chainId)
		mp := make(map[string]interface{}, 3)
		if err != nil {
			return nil, err
		}
		mp["height"] = stats.CurrentHeight

		nextEpochHeight := (stats.CurrentHeight/common.BlocksInEpoch + 1) * common.BlocksInEpoch

		holder, err := api.dmanager.GetChainData(chainId)
		if err != nil {
			return mp, err
		}
		currentComm, err := holder.GetCommittee(chainId, common.Height(stats.CurrentHeight))
		if err == nil && currentComm != nil {
			mp["currentComm"] = currentComm.Members
		} else {
			mp["currentComm"] = []common.NodeID{}
		}
		nextComm, err := holder.GetCommittee(chainId, common.Height(nextEpochHeight))
		if err == nil && nextComm != nil {
			mp["nextComm"] = nextComm.Members
		} else {
			mp["nextComm"] = []common.NodeID{}
		}
		return mp, err
	}
	return nil, nil
}

func (api *PublicBlockChainAPI) Call(ctx context.Context, args TransactionArgs, blockNrOrHash BlockNumberOrHash, overrides *StateOverride) (hexutil.Bytes, error) {
	chainData, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	if args.To == nil {
		return nil, errors.New("illegal to address")
	}
	from := args.From
	if from == nil {
		defaultAddr := common.HexToAddress("0000000000000000000000000000000000000000")
		from = &defaultAddr
	}
	if args.Data == nil {
		return nil, errors.New("no input found")
	}
	acc, _ := chainData.GetAccount(from)
	if acc == nil {
		acc = models.NewAccount(*from, nil)
	}
	tx := models.NewTx(api.chainID, from, args.To, acc.Nonce, false, big.NewInt(0), *args.Data)
	extrakeys := &models.Extra{
		Type:     models.LegacyTxType,
		Gas:      0,
		GasPrice: big.NewInt(0),
	}
	if args.Gas != nil {
		extrakeys.Gas = uint64(*args.Gas)
	}
	if args.GasPrice != nil {
		extrakeys.GasPrice = args.GasPrice.ToInt()
	}
	_ = tx.SetExtraKeys(extrakeys)
	if err := tx.IsLegalIncomingTx(api.chainID); err != nil {
		return nil, err
	}
	// extra, _ := json.Marshal(extrakeys)
	// tx.Extra = extra
	curBlock := chainData.CurrentBlock()
	// bc := chainData.GetBlockChain()
	// if bc == nil {
	// 	return nil, errors.New(tkmrpc.ErrInvalidBlockChain)
	// }
	// if bc.CurrentBlock() == nil {
	// 	return nil, errors.New(tkmrpc.ErrNilBlock)
	// }
	if curBlock == nil {
		return nil, errors.New("current block nil")
	}
	rec, err := chainData.CallProcessTx(tx, nil, curBlock.BlockHeader)
	if err != nil {
		return nil, err
	}
	receipt := rec.(*models.Receipt)
	if receipt == nil {
		return nil, nil
	}
	return receipt.Out, nil
}

func (api *PublicBlockChainAPI) Coinbase() string {
	return ""
}

func (api *PublicBlockChainAPI) ChainId() (*hexutil.Big, error) {
	return (*hexutil.Big)(new(big.Int).SetUint64(models.ETHChainID(api.chainID, models.TxVersion))), nil

}

func (api *PublicBlockChainAPI) GasPrice() (*hexutil.Big, error) {
	// gasprice, _ := new(big.Int).SetString(models.GasPrice, 10)
	gasprice := new(big.Int).Set(models.DefaultGasPriceBig)
	return (*hexutil.Big)(gasprice), nil
}

func (api *PublicBlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash BlockNumberOrHash) (*hexutil.Big, error) {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	var acc *models.Account
	height := blockNrOrHash.GetRealHeight(cdata)
	if height != 0 && height != common.NilHeight {
		acc, err = cdata.GetAccountAtHeight(height, &address)
		if err != nil {
			return nil, fmt.Errorf("get account failed: %v", err)
		}
	} else {
		acc, _ = cdata.GetAccount(&address)
	}

	if acc == nil {
		acc = models.NewAccount(address, nil)
	}
	return (*hexutil.Big)(acc.Balance), nil

}

func (api *PublicBlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash BlockNumberOrHash) (*AccountResult, error) {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	}
	res := &AccountResult{
		Address:      address,
		AccountProof: nil,
		Balance:      (*hexutil.Big)(acc.Balance),
		CodeHash:     common.BytesToHash(acc.CodeHash),
		Nonce:        hexutil.Uint64(acc.Nonce),
		StorageHash:  common.BytesToHash(acc.StorageRoot),
		StorageProof: nil,
	}
	return res, nil

}

func (api *PublicBlockChainAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	block, err := cdata.GetBlockByHash(hash.Slice())
	if err != nil {
		return nil, err
	}
	return api.rpcMarshalBlock(ctx, block, true, fullTx)

}

func (api *PublicBlockChainAPI) GetBlockByNumber(ctx context.Context, number BlockNumber, fulltx bool) (map[string]interface{}, error) {
	var err error
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if number == LatestBlockNumber {
		block, err = cdata.GetBlock(cdata.GetCurrentHeight())
	} else {
		block, err = cdata.GetBlock(common.Height(number))
	}
	if err != nil || block == nil {
		return nil, err
	}
	return api.rpcMarshalBlock(ctx, block, true, fulltx)
}

func (api *PublicBlockChainAPI) rpcMarshalBlock(ctx context.Context, block *models.BlockEMessage, incLTx, fullTx bool) (map[string]interface{}, error) {
	fields := RPCMarshalHeader(block.BlockHeader)
	if incLTx {
		formatTx := func(tx *models.Transaction) (interface{}, error) {
			return tx.Hash(), nil
		}
		if fullTx {
			formatTx = func(tx *models.Transaction) (interface{}, error) {
				return newRPCTransactionFromBlockHash(block, tx.Hash()), nil
			}
		}
		txs := block.BlockBody.Txs
		transactions := make([]interface{}, len(txs))
		var err error
		for i, tx := range txs {
			if transactions[i], err = formatTx(tx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}

	fields["uncles"] = make([]common.Hash, 0)
	return fields, nil
}

func RPCMarshalHeader(head *models.BlockHeader) map[string]interface{} {
	// ethereum EmptyRootHash
	emptyRootHash := common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	// ethereum EmptyUncleHash
	emptyUncleHash := common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")

	txroot := emptyRootHash
	var receiptroot common.Hash
	if head.TransactionRoot != nil {
		txroot = *head.TransactionRoot
	}
	if head.ReceiptRoot != nil {
		receiptroot = *head.ReceiptRoot
	}
	blocknonce := make([]byte, 8)

	result := map[string]interface{}{
		"number":           (*hexutil.Big)(big.NewInt(int64(head.GetHeight()))),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            hexutil.Bytes(blocknonce),
		"mixHash":          common.Hash{},
		"sha3Uncles":       emptyUncleHash,
		"logsBloom":        new(Bloom),
		"stateRoot":        head.StateRoot,
		"miner":            common.Address{},
		"difficulty":       (*hexutil.Big)(big.NewInt(0)),
		"extraData":        hexutil.Bytes([]byte{}),
		"size":             hexutil.Uint64(0),
		"gasLimit":         hexutil.Uint64(models.MaxGasLimit),
		"gasUsed":          (*hexutil.Big)(big.NewInt(0)),
		"timestamp":        hexutil.Uint64(head.TimeStamp),
		"transactionsRoot": txroot,
		"receiptsRoot":     receiptroot,
	}
	return result
}

func (api *PublicBlockChainAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil
	}
	block, err := cdata.GetBlockByHash(blockHash.Slice())
	if err != nil || block == nil || block.BlockHeader == nil || block.BlockBody == nil {
		return nil
	}
	rpctx, err := api.genRpcTxFromBlock(cdata, block, index)
	if err != nil {
		return nil
	}
	return rpctx
}

func (api *PublicBlockChainAPI) genRpcTxFromBlock(cdata models.DataHolder, block *models.BlockEMessage, index hexutil.Uint) (rpctx *RPCTransaction, err error) {
	if int(index) < 0 || int(index) >= len(block.BlockBody.Txs) {
		return
	}
	transaction := block.BlockBody.Txs[index]
	var receipt *models.Receipt
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := dao.ReadReceipts(cdata.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(index))
		if err != nil {
			log.Error("[ETHRPC] GetTransactionByHash ReadReceipt error:", err.Error())
			return
		}
	}
	if receipt == nil {
		return
	}
	txi := &models.TXIndex{
		BlockHeight: uint64(block.GetHeight()),
		BlockHash:   block.Hash(),
		Index:       uint32(index),
	}
	rpctx, err = GenRpcTxRes(transaction, txi, receipt)
	return
}

func (api *PublicBlockChainAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr BlockNumber, index hexutil.Uint) *RPCTransaction {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil
	}
	block := new(models.BlockEMessage)
	if blockNr == LatestBlockNumber {
		block, err = cdata.GetBlock(cdata.GetCurrentHeight())
	} else {
		block, err = cdata.GetBlock(common.Height(blockNr))
	}
	if err != nil || block == nil || block.BlockHeader == nil || block.BlockBody == nil {
		return nil
	}
	rpctx, err := api.genRpcTxFromBlock(cdata, block, index)
	if err != nil {
		return nil
	}
	return rpctx
}

func (api *PublicBlockChainAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil
	}
	b, err := cdata.GetBlockByHash(blockHash.Slice())
	if err != nil {
		return nil
	}
	txcount := uint(len(b.BlockBody.Txs))
	return (*hexutil.Uint)(&txcount)
}

func (api *PublicBlockChainAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr BlockNumber) *hexutil.Uint {
	var err error
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil
	}
	block := new(models.BlockEMessage)
	if blockNr == LatestBlockNumber {
		block, err = cdata.GetBlock(cdata.GetCurrentHeight())
	} else {
		block, err = cdata.GetBlock(common.Height(blockNr))
	}
	if err != nil {
		return nil
	}
	txcount := uint(len(block.BlockBody.Txs))
	return (*hexutil.Uint)(&txcount)
}

func (api *PublicBlockChainAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	chainData, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	// bc := chainData.GetBlockChain()
	// if bc == nil {
	// 	return nil, errors.New("Invalid blockchain")
	// }
	txI, err := chainData.GetBlockTxIndexs(hash[:])
	if err != nil {
		// No error is returned here so that the front-end application does not make an error,
		// and the front-end application will terminate the polling when it receives err.
		return nil, nil
	}
	block, err := chainData.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, errors.New(tkmrpc.ErrNilBlock)
	}
	if block.BlockHeader == nil || block.BlockBody == nil {
		return nil, errors.New(tkmrpc.ErrNilBlock)
	}
	if int(txI.Index) < 0 || int(txI.Index) >= len(block.BlockBody.Txs) {
		return nil, errors.New(tkmrpc.ErrNilTransaction)
	}
	transaction := block.BlockBody.Txs[txI.Index]
	var receipt *models.Receipt
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := dao.ReadReceipts(chainData.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(txI.Index))
		if err != nil {
			log.Error("[ETHRPC] GetTransactionByHash ReadReceipt error:", err.Error())
			return nil, err
		}
	}
	if receipt == nil {
		return nil, errors.New(tkmrpc.ErrReadReceipt)
	}
	return GenRpcTxRes(transaction, txI, receipt)
}

func (api *PublicBlockChainAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash BlockNumberOrHash) (*hexutil.Uint64, error) {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	}
	return (*hexutil.Uint64)(&acc.Nonce), nil
}

func (api *PublicBlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash BlockNumberOrHash) (hexutil.Bytes, error) {
	cdata, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	var code []byte
	acc, _ := cdata.GetAccount(&address)
	if acc == nil {
		acc = models.NewAccount(address, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}
	return code, nil
}

func (api *PublicBlockChainAPI) GetLogs(ctx context.Context, query FilterQuery) ([]*models.Log, error) {
	begin, end := common.NilHeight, common.NilHeight
	if query.FromBlock != nil {
		begin = common.Height(query.FromBlock.Int64())
	}
	if query.ToBlock != nil {
		end = common.Height(query.ToBlock.Int64())
	}
	filter := &models.RpcFilter{
		BlockHash: query.BlockHash,
		Addrs:     query.Addresses,
		Begin:     begin,
		End:       end,
		Topics:    query.Topics,
	}
	logs, err := api.dmanager.GetLogs(api.chainID, filter)
	if err != nil {
		return nil, err
	}
	return returnLogs(logs), nil
}

// returnLogs is a helper that will return an empty log array in case the given logs array is nil,
// otherwise the given logs array is returned.
func returnLogs(logs []*models.Log) []*models.Log {
	if logs == nil {
		return []*models.Log{}
	}
	return logs
}

func (api *PublicBlockChainAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	chainData, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	// bc := chainData.GetBlockChain()
	// if bc == nil {
	// 	return nil, errors.New("Invalid blockchain")
	// }
	txI, err := chainData.GetBlockTxIndexs(hash[:])
	if err != nil {
		return nil, nil
	}
	block, err := chainData.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, errors.New(tkmrpc.ErrNilBlock)
	}
	if block.BlockHeader == nil || block.BlockBody == nil {
		return nil, errors.New(tkmrpc.ErrNilBlock)
	}
	if int(txI.Index) < 0 || int(txI.Index) >= len(block.BlockBody.Txs) {
		return nil, errors.New(tkmrpc.ErrNilTransaction)
	}
	var receipt *models.Receipt
	tx := block.BlockBody.Txs[txI.Index]
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := dao.ReadReceipts(chainData.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(txI.Index))
		if err != nil {
			log.Error("[ETHRPC] GetTransactionByHash ReadReceipt error:", err.Error())
			return nil, err
		}
	}
	if receipt == nil {
		return nil, errors.New(tkmrpc.ErrReadReceipt)
	}
	bh := block.Hash()
	for index := range receipt.Logs {
		receipt.Logs[index].BlockHash = &bh
	}
	gasprice, _ := chainData.GetGasSettings()
	bloom := make([]byte, 256)
	fields := map[string]interface{}{
		"blockHash":         bh,
		"blockNumber":       hexutil.Uint64(block.GetHeight()),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(txI.Index),
		"from":              tx.From,
		"to":                tx.To,
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"type":              hexutil.Uint(tx.ETHTxType()),
		"logsBloom":         hexutil.Bytes(bloom),
		"effectiveGasPrice": hexutil.Uint64(gasprice.Uint64()),
		"root":              nil,
		"status":            hexutil.Uint(receipt.Status),
	}
	if receipt.Logs == nil {
		fields["logs"] = [][]*models.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != nil && *receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields, nil
}

func checkTx(tx *models.Transaction, verifySig bool, sig, pub []byte) error {
	if tx.From != nil && tx.From.IsReserved() {
		return errors.New("reserved address")
	}
	if err := tx.IsLegalIncomingTx(tx.ChainID); err != nil {
		return err
	}
	if verifySig {
		txhash := models.ETHSigner.HashGtkm(tx)
		if v := models.VerifyHash(txhash.Slice(), pub, sig); !v {
			return models.ErrInvalidSig
		}
	}
	return nil
}

func (api *PublicBlockChainAPI) SendRawTransaction(ctx context.Context, input hexutil.Bytes) (common.Hash, error) {
	// to ethtransaction type
	tx := new(models.ETHTransaction)
	if err := tx.UnmarshalBinary(input); err != nil {
		return common.Hash{}, err
	}
	// verify chain id
	switch tx.Type() {
	case models.LegacyTxType, models.AccessListTxType, models.DynamicFeeTxType:
		should := new(big.Int).SetUint64(models.ETHChainID(api.chainID, models.TxVersion))
		inChainid := tx.ChainId()
		if should.Cmp(inChainid) != 0 {
			return common.Hash{}, fmt.Errorf("chain id not match, have:%s want:%s", inChainid, should)
		}
	default:
		return common.Hash{}, models.ErrTxTypeNotSupported
	}
	sig, pub, err := models.ETHSigner.RecoverSigAndPub(tx)
	if err != nil {
		return common.Hash{}, err
	}
	gtkmtx, err := tx.ToTransaction()
	if err != nil {
		return common.Hash{}, err
	}
	if err := checkTx(gtkmtx, true, sig, pub); err != nil {
		return common.Hash{}, err
	}
	if err := api.eventer.PostEvent(gtkmtx, pub, sig); err != nil {
		return common.Hash{}, err
	}
	return gtkmtx.Hash(), nil
}

func (api *PublicBlockChainAPI) EstimateGas(ctx context.Context, args TransactionArgs, blockNrOrHash *BlockNumberOrHash) (hexutil.Uint64, error) {
	dmanager, err := api.dmanager.Simulate()
	if err != nil {
		return 0, err
	}

	isNoGasChain, _ := dmanager.IsNoGasChain(api.chainID)
	if isNoGasChain || (args.To != nil && args.To.IsNoGas()) {
		return 0, nil
	}
	if args.From == nil {
		return 0, errors.New("insufficient balance to pay for gas")
	}

	extrakeys := new(models.Extra)

	cdata, err := dmanager.GetChainData(api.chainID)
	if err != nil {
		return 0, err
	}

	acc, _ := cdata.GetAccount(args.From)
	if acc == nil {
		acc = models.NewAccount(*args.From, nil)
	}
	val := new(big.Int)
	if args.Value != nil {
		val.Set(args.Value.ToInt())
	}
	if val.Cmp(acc.Balance) >= 0 {
		return 0, errors.New("insufficient funds for transfer")
	}
	// extrakeys.Gas = models.GasLimit
	// if args.Gas != nil && uint64(*args.Gas) > models.GasLimit {
	// 	extrakeys.Gas = uint64(*args.Gas)
	// }

	tx := models.Transaction{
		ChainID:  api.chainID,
		From:     args.From,
		To:       args.To,
		Nonce:    acc.Nonce,
		UseLocal: false,
		Val:      val,
		Input:    args.data(),
		Version:  models.TxVersion,
	}
	tx.SetExtraKeys(extrakeys)
	if err := checkTx(&tx, false, nil, nil); err != nil {
		return 0, err
	}
	currentBlock := cdata.CurrentBlock()
	if currentBlock == nil {
		return 0, errors.New("block not found")
	}

	used, err := cdata.Estimate(&tx, currentBlock.BlockHeader)
	return hexutil.Uint64(used), err
	// if err != nil {
	// 	return 0, err
	// }
	// if receipt.Error != "" {
	// 	if !strings.Contains(receipt.Error, "out of gas") {
	// 		if len(receipt.Out) > 0 {
	// 			err := models.NewRevertError(receipt.Revert())
	// 			return 0, err
	// 		}
	// 	}
	// 	return 0, errors.New("gas required exceeds allowance")
	// }
	// return hexutil.Uint64(receipt.GasUsed), nil
	//
}

func (api *PublicBlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, key string, blockNrOrHash BlockNumberOrHash) (hexutil.Bytes, error) {
	chainData, err := api.dmanager.GetChainData(api.chainID)
	if err != nil {
		return nil, err
	}
	statdb := chainData.GetStateDB()
	res := statdb.GetState(address, common.HexToHash(key))
	return res[:], nil
}
