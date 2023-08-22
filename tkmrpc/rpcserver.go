package tkmrpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/dao"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
	"github.com/stephenfire/go-rtl"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	ErrNilRequest = errors.New("nil request")
)

type RPCServer struct {
	common.AbstractService

	local    common.Endpoint
	listener net.Listener
	nmanager models.NetworkManager
	dmanager models.DataManager
	engine   models.Engine
	eventer  models.Eventer
	logger   logrus.FieldLogger

	UnimplementedNodeServer
}

func NewRPCServer(local common.Endpoint, nmanager models.NetworkManager, dmanager models.DataManager, engine models.Engine,
	eventer models.Eventer) (*RPCServer, error) {
	server := &RPCServer{
		local:    local,
		nmanager: nmanager,
		dmanager: dmanager,
		engine:   engine,
		eventer:  eventer,
		logger:   log.WithField("L", "RPCServer"),
	}
	server.SetChanger(server)

	return server, nil
}

func (s *RPCServer) String() string {
	return "RPC@" + s.local.String()
}

func (s *RPCServer) Initializer() error {
	if s.local.IsNil() {
		return errors.New("empty server endpoint setting for RPC Server")
	}
	s.logger.Debug("[RPCServer] initialized")
	return nil
}

func (s *RPCServer) Starter() error {
	l, err := net.Listen(s.local.NetType, s.local.Address)
	if err != nil {
		return err
	}
	s.listener = l
	srv := grpc.NewServer()
	RegisterNodeServer(srv, s)
	reflection.Register(srv)
	go func() {
		if err := srv.Serve(s.listener); err != nil {
			s.logger.Errorf("[RPCServer] failed to serve: %v", err)
		}
		s.logger.Debug("[RPCServer] serve stoped")
	}()

	s.logger.Debugf("[RPCServer] started @ %s", s.local)
	return nil
}

func (s *RPCServer) Closer() error {
	if err := s.listener.Close(); err != nil {
		s.logger.Errorf("[RPCServer] closing rpc server listener error: %v", err)
	}
	s.logger.Debug("[RPCServer] closed")
	return nil
}

type RpcError interface {
	ToRpcResponse() *RpcResponse
	ToRpcResponseStream() *RpcResponseStream
}

type rpcError struct {
	code int32
	msgs []string
}

func newRpcError(code int32, msg ...string) *rpcError {
	return &rpcError{
		code: code,
		msgs: msg,
	}
}

func (e *rpcError) Error() string {
	if len(e.msgs) == 0 || len(e.msgs[0]) == 0 {
		return RpcErrMsgMap[e.code]
	}
	var data, detail string
	if len(e.msgs) > 0 {
		data = e.msgs[0]
	}
	if len(e.msgs) > 1 {
		detail = e.msgs[1]
	}
	return fmt.Sprintf("response error %d, data: %s, detail: %s", e.code, data, detail)
}

func (e *rpcError) Msg() string {
	if len(e.msgs) == 0 {
		return ""
	}
	return e.msgs[0]
}

func (e *rpcError) ToRpcResponse() *RpcResponse {
	return newResponse(e.code, e.msgs...)
}

func (e *rpcError) ToRpcResponseStream() *RpcResponseStream {
	return &RpcResponseStream{Code: e.code, Msg: e.Msg()}
}

func newResponse(code int32, msg ...string) (resp *RpcResponse) {
	resp = new(RpcResponse)
	resp.Code = code
	if len(msg) == 0 || len(msg[0]) == 0 {
		resp.Data = RpcErrMsgMap[code]
	} else {
		for index, m := range msg {
			if index == 0 {
				resp.Data = m
			}
			if index == 1 {
				resp.Detail = m
			}
		}
	}
	return
}

func (s *RPCServer) Ping(_ context.Context, req *RpcRequest) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	ni := NodeInfo{
		NodeId:        common.SystemNodeID,
		Version:       fmt.Sprintf("%s - %s", consts.Version, config.VersionInfo.Versions[0]),
		IsDataNode:    s.dmanager.IsDataNode(),
		DataNodeOf:    s.dmanager.DataNodeOf(),
		LastMsgTime:   common.LastMsgTime,
		LastEventTime: common.LastEventTime,
		LastBlockTime: common.LastBlockTime,
		LastBlocks:    common.LastBlocks.CopyMap(),
		Overflow:      common.Overflow,
		OpTypes:       s.eventer.GetNodeOpTypes(),
	}
	if jsons, err := json.Marshal(ni); err != nil {
		s.logger.Error("[RPCServer] Marshal NodeInfo error,", err.Error())
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetAccount return resp.data as models.Account in JSON format
func (s *RPCServer) GetAccount(_ context.Context, addr *RpcAddress) (*RpcResponse, error) {
	if addr == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	if len(addr.Address) != common.AddressLength {
		return newResponse(InvalidParamsCode, "invalid address"), nil
	}
	chainId := common.ChainID(addr.Chainid)
	comaddr := common.BytesToAddress(addr.Address)

	cdata, err := s.dmanager.GetChainData(chainId)
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}

	var code []byte
	acc, _ := cdata.GetAccount(&comaddr)
	if acc == nil {
		acc = models.NewAccount(comaddr, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}

	ach := &AccountWithCode{
		Addr:            acc.Addr,
		Creator:         acc.Creator.Clone(),
		Nonce:           acc.Nonce,
		Balance:         acc.Balance,
		LocalCurrency:   acc.LocalCurrency,
		StorageRoot:     acc.StorageRoot,
		CodeHash:        acc.CodeHash,
		LongStorageRoot: acc.LongStorageRoot,
		Code:            code,
	}
	if jsons, err := json.Marshal(ach); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func (s *RPCServer) GetAccountAtHeight(_ context.Context, req *RpcAccountAt) (*RpcResponse, error) {
	if req == nil {
		return nil, common.ErrNil
	}
	if len(req.Address) != common.AddressLength {
		return nil, errors.New("invalid address")
	}
	chainid := common.ChainID(req.Chainid)
	addr := common.BytesToAddress(req.Address)
	if chainid.IsNil() {
		return nil, errors.New("invalid chainid")
	}
	height := common.Height(req.Height)
	if height.IsNil() {
		return nil, errors.New("invalid height")
	}
	cdata, err := s.dmanager.GetChainData(chainid)
	if err != nil {
		return nil, fmt.Errorf("get chain data failed: %v", err)
	}
	acc, err := cdata.GetAccountAtHeight(height, &addr)
	if err != nil {
		return nil, fmt.Errorf("get account failed: %v", err)
	}
	var code []byte
	if acc == nil {
		acc = models.NewAccount(addr, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}
	ach := &AccountWithCode{
		Addr:            acc.Addr,
		Creator:         acc.Creator.Clone(),
		Nonce:           acc.Nonce,
		Balance:         acc.Balance,
		LocalCurrency:   acc.LocalCurrency,
		StorageRoot:     acc.StorageRoot,
		CodeHash:        acc.CodeHash,
		LongStorageRoot: acc.LongStorageRoot,
		Code:            code,
	}
	if jsons, err := json.Marshal(ach); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetAccountWithChainHeight Get account information and current chain height
func (s *RPCServer) GetAccountWithChainHeight(_ context.Context, addr *RpcAddress) (*RpcResponse, error) {
	if addr == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	if len(addr.Address) != common.AddressLength {
		return newResponse(InvalidParamsCode, "invalid address"), nil
	}
	chainId := common.ChainID(addr.Chainid)
	comaddr := common.BytesToAddress(addr.Address)

	cdata, err := s.dmanager.GetChainData(chainId)
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}

	var code []byte
	acc, _ := cdata.GetAccount(&comaddr)
	if acc == nil {
		acc = models.NewAccount(comaddr, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}

	ach := &AccountHeight{
		Height:          cdata.GetCurrentHeight(),
		Addr:            acc.Addr,
		Nonce:           acc.Nonce,
		Balance:         acc.Balance,
		LocalCurrency:   acc.LocalCurrency,
		StorageRoot:     acc.StorageRoot,
		CodeHash:        acc.CodeHash,
		LongStorageRoot: acc.LongStorageRoot,
		Code:            code,
	}
	if jsons, err := json.Marshal(ach); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func deltaFromToAccountChange(header *models.BlockHeader, key models.DeltaFromKey, delta *models.AccountDelta) *AccountChange {
	if delta == nil {
		return nil
	}
	return &AccountChange{
		ChainID:   key.ShardID,
		Height:    key.Height,
		From:      nil,
		To:        &delta.Addr,
		Nonce:     0,
		Val:       delta.Delta,
		TimeStamp: header.TimeStamp,
	}
}

func txToAccountChange(header *models.BlockHeader, height common.Height, tx *models.Transaction, pas *models.PubAndSig) *AccountChange {
	if tx == nil {
		return nil
	}
	txhash := tx.Hash()
	return &AccountChange{
		TxHash:    &txhash,
		ChainID:   tx.ChainID,
		Height:    height,
		From:      tx.From,
		To:        tx.To,
		Nonce:     tx.Nonce,
		Val:       tx.Val,
		Input:     tx.Input,
		UseLocal:  tx.UseLocal,
		Extra:     tx.Extra,
		TimeStamp: header.TimeStamp,
		Hash:      tx.Hash().Bytes(),
		Version:   tx.Version,
		MultiSigs: tx.MultiSigs,
		Sig:       pas,
	}
}

func checkRpcTx(tx *RpcTx, verifySig bool) (txmsg *models.Transaction, txHash []byte, resp *RpcResponse) {

	var err error
	txmsg, err = tx.ToTx()
	if err != nil {
		return nil, nil, newResponse(InvalidParamsCode, err.Error())
	}
	// if txmsg.ChainID.IsMain() {
	// 	// Only system contracts can be called on the main chain
	// 	if txmsg.To == nil || !txmsg.To.IsSystemContract() {
	// 		return nil, newResponse(InvalidBCCode)
	// 	}
	// }
	// if txmsg.From != nil && txmsg.From.IsReserved() {
	// 	return nil, newResponse(ReservedFromAddrErrCode)
	// }
	// if len(txmsg.Input) == 0 && (txmsg.Val == nil || txmsg.Val.Sign() == 0) {
	// 	return nil, newResponse(InvalidParamsCode, "invalid transfer value")
	// }
	if err = txmsg.IsLegalIncomingTx(txmsg.ChainID); err != nil {
		return nil, nil, newResponse(InvalidParamsCode, err.Error())
	}
	hoe, err := common.HashObject(txmsg)
	if err != nil {
		return nil, nil, newResponse(HashObjectErrCode, err.Error())
	}
	if verifySig {
		if txmsg.From == nil {
			return nil, nil, newResponse(InvalidParamsCode, "no from address")
		}
		v, pubkey := models.VerifyHashWithPub(hoe, tx.Pub, tx.Sig)
		if !v {
			log.Warnf("[RPC] tx: %s, txhash: %x, pub: %x, sig: %x verify failed", txmsg, hoe, tx.Pub, tx.Sig)
			return nil, nil, newResponse(InvalidSignatureCode)
		}
		address, err := common.AddressFromPubSlice(pubkey)
		if err != nil {
			return nil, nil, newResponse(InvalidPublicKey, err.Error())
		}
		if !bytes.Equal(txmsg.From.Slice(), address[:]) {
			return nil, nil, newResponse(InvalidPublicKey, "signature not match with from address")
		}
		// verify multi signaturesa
		if len(txmsg.MultiSigs) > 0 {
			for i, pas := range txmsg.MultiSigs {
				if pas == nil {
					return nil, nil, newResponse(InvalidMultiSigsCode, fmt.Sprintf("nil pas found at index %d", i))
				}
				if !models.VerifyHash(hoe, pas.PublicKey, pas.Signature) {
					return nil, nil, newResponse(InvalidMultiSigsCode, fmt.Sprintf("signature verify failed at index %d", i))
				}
			}
		}
	}
	return txmsg, hoe, nil
}

// CallTransaction return resp.data as TransactionReceipt in JSON format
func (s *RPCServer) CallTransaction(_ context.Context, tx *RpcTx) (*RpcResponse, error) {
	chainData, err := s.dmanager.GetChainData(common.ChainID(tx.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	txmsg, _, resp := checkRpcTx(tx, false)
	if resp != nil {
		return resp, nil
	}
	if txmsg.To == nil {
		return newResponse(InvalidParamsCode, "illegal to address"), nil
	}
	if len(txmsg.Input) == 0 {
		return newResponse(InvalidParamsCode, "no input found"), nil
	}
	currentBlock := chainData.CurrentBlock()
	if currentBlock == nil {
		return newResponse(NilBlockCode), nil
	}
	rec, err := chainData.CallProcessTx(txmsg, &models.PubAndSig{PublicKey: tx.Pub, Signature: tx.Sig}, currentBlock.BlockHeader)
	if err != nil {
		return newResponse(CallProcessTxErrCode, err.Error()), nil
	}
	receipt := rec.(*models.Receipt)

	result := new(TransactionReceipt).PartReceipt(txmsg, tx.GetSignature(), receipt)
	if jsons, err := json.Marshal(result); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func (s *RPCServer) _txInfosByValue(chainid common.ChainID, txHash common.Hash) (txIndex int,
	block *models.BlockEMessage, receipts models.Receipts, param []byte, rpcerr error) {
	chainData, err := s.dmanager.GetChainData(common.ChainID(chainid))
	if err != nil {
		return 0, nil, nil, nil, newRpcError(GetChainDataErrCode, err.Error())
	}
	txI, err := chainData.GetBlockTxIndexs(txHash[:])

	if err != nil || txI == nil {
		return 0, nil, nil, nil, newRpcError(NilTransactionCode, "", fmt.Sprintf("transaction not found or failed: %v", err))
	}
	block, err = chainData.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return 0, nil, nil, nil, newRpcError(NilBlockCode, err.Error())
	}
	if block == nil {
		return 0, nil, nil, nil, newRpcError(NilBlockCode)
	}

	if block.BlockHeader == nil || block.BlockBody == nil {
		return 0, nil, nil, nil, newRpcError(NilBlockCode, "", "nil header or body")
	}
	txIndex = int(txI.Index)
	if txIndex < 0 || txIndex >= len(block.BlockBody.Txs) {
		return 0, nil, nil, nil, newRpcError(NilTransactionCode, "", fmt.Sprintf("invalid tx index: %d in %d txs",
			txIndex, len(block.BlockBody.Txs)))
	}
	if len(block.BlockBody.Txs) != len(block.BlockBody.TxsPas) {
		return 0, nil, nil, nil, fmt.Errorf("invalid length of txs pass(%d), length of txs(%d)",
			len(block.BlockBody.TxsPas), len(block.BlockBody.Txs))
	}
	if block.BlockBody.Txs[txIndex] == nil {
		return 0, nil, nil, nil, fmt.Errorf("invalid tx at index:%d", txIndex)
	}

	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)
		receipts = dao.ReadReceipts(chainData.GetDb(), receiptHash)
	}
	if len(block.BlockBody.Txs) != len(receipts) {
		return 0, nil, nil, nil, fmt.Errorf("invalid receipts length:%d, length of txs:%d",
			len(receipts), len(block.BlockBody.Txs))
	}
	if receipts[txIndex] == nil {
		return 0, nil, nil, nil, fmt.Errorf("invalid receipt at index:%d", txIndex)
	}
	if len(block.BlockBody.TxParams) > txIndex {
		param = common.CopyBytes(block.BlockBody.TxParams[txIndex])
	}
	return txIndex, block, receipts, param, nil
}

func (s *RPCServer) _txInfosByReq(req *RpcTXHash) (txIndex int, block *models.BlockEMessage,
	receipts models.Receipts, param []byte, rpcerr error) {
	if req == nil {
		return 0, nil, nil, nil, newRpcError(InvalidParamsCode, "nil request")
	}
	txHash := common.Hash{}
	txHash.SetBytes(req.Hash)
	return s._txInfosByValue(common.ChainID(req.Chainid), txHash)
}

func (s *RPCServer) _txByHash(req *RpcTXHash, found func(txIndex int, block *models.BlockEMessage,
	receipts models.Receipts, param []byte) (*RpcResponse, error)) (*RpcResponse, error) {
	txIndex, block, receipts, txparam, err := s._txInfosByReq(req)
	if err != nil {
		rpcerr, ok := err.(RpcError)
		if ok && rpcerr != nil {
			return rpcerr.ToRpcResponse(), nil
		}
		return nil, err
	}
	return found(txIndex, block, receipts, txparam)
}

// GetTransactionByHash return resp.data as TransactionReceipt in JSON format
func (s *RPCServer) GetTransactionByHash(_ context.Context, txs *RpcTXHash) (*RpcResponse, error) {
	return s._txByHash(txs, func(txIndex int, block *models.BlockEMessage, receipts models.Receipts, param []byte) (*RpcResponse, error) {
		result := new(TransactionReceipt).FullReceipt(
			block.BlockBody.Txs[txIndex],
			block.BlockBody.TxsPas[txIndex],
			block.GetHeight(),
			receipts[txIndex])
		result.Param = param
		if jsons, err := json.Marshal(result); err != nil {
			return newResponse(MarshalErrCode, err.Error()), nil
		} else {
			return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
		}
	})
}

func (s *RPCServer) GetTxProof(_ context.Context, req *RpcTXHash) (*RpcResponse, error) {
	return s._txByHash(req, func(txIndex int, block *models.BlockEMessage, receipts models.Receipts, param []byte) (*RpcResponse, error) {
		result := new(TxProof)
		result.FullReceipt(block.BlockBody.Txs[txIndex],
			block.BlockBody.TxsPas[txIndex],
			block.GetHeight(),
			receipts[txIndex])
		result.Param = param

		proofToTxRoot := common.NewMerkleProofs()
		_, err := block.BlockBody.TxProofHash(block.BlockHeader.Version, int(txIndex), -1, proofToTxRoot)
		if err != nil {
			return newResponse(TxProofErrCode, fmt.Sprintf("proof to tx root failed: %v", err)), nil
		}

		proofToHeader := make(trie.ProofChain, 0)
		_, err = block.BlockHeader.MakeProof(trie.ProofHeaderBase+models.BHTransactionRoot, &proofToHeader)
		if err != nil {
			return newResponse(TxProofErrCode, fmt.Sprintf("proof to header failed: %v", err)), nil
		}

		var proof []MerkleItem
		convert := func(val []byte, order bool) error {
			dir := uint8(0)
			if !order {
				dir = 1
			}
			proof = append(proof, MerkleItem{
				HashVal:   val,
				Direction: dir,
			})
			return nil
		}
		err = proofToTxRoot.Iterate(convert)
		if err != nil {
			return newResponse(TxProofErrCode, fmt.Sprintf("iterate proof to tx root failed: %v", err)), nil
		}
		err = proofToHeader.Iterate(convert)
		if err != nil {
			return newResponse(TxProofErrCode, fmt.Sprintf("iterate proof to header failed: %v", err)), nil
		}
		result.Proof = proof
		if jsons, err := json.Marshal(result); err != nil {
			return newResponse(MarshalErrCode, err.Error()), nil
		} else {
			return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
		}
	})
}

func (s *RPCServer) _txStreamByHash(chainid common.ChainID, txhash common.Hash, found func(txIndex int,
	block *models.BlockEMessage, receipts models.Receipts, param []byte) (*RpcResponseStream, error)) (*RpcResponseStream, error) {
	txIndex, block, receipts, txparam, err := s._txInfosByValue(chainid, txhash)
	if err != nil {
		rpcerr, ok := err.(RpcError)
		if ok && rpcerr != nil {
			return rpcerr.ToRpcResponseStream(), nil
		}
		return nil, err
	}
	return found(txIndex, block, receipts, txparam)
}

func (s *RPCServer) GetTxLocalProof(_ context.Context, req *RpcTXHash) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return s._txStreamByHash(common.ChainID(req.Chainid), common.BytesToHash(req.Hash),
		func(txIndex int, block *models.BlockEMessage, receipts models.Receipts, param []byte) (*RpcResponseStream, error) {
			tx := block.BlockBody.Txs[txIndex]
			receipt := receipts[txIndex]
			if tx.Hash() != receipt.TxHash {
				return nil, errors.New("tx not match with receipt")
			}
			receiptProof := make(trie.ProofChain, 0)
			if receiptRoot, err := receipts.Proof(txIndex, &receiptProof); err != nil {
				return nil, fmt.Errorf("proof receipt@%d/%d failed: %v", txIndex, len(receipts), err)
			} else {
				if !block.BlockHeader.ReceiptRoot.SliceEqual(receiptRoot) {
					return nil, fmt.Errorf("failed in generating proof of receipts root: want: %x, get: %x",
						common.ForPrint(block.BlockHeader.ReceiptRoot), common.ForPrint(receiptRoot))
				}
			}
			if _, err := block.BlockHeader.MakeProof(trie.ProofHeaderBase+models.BHReceiptRoot, &receiptProof); err != nil {
				return nil, fmt.Errorf("failed in generating receipt root header proof: %w", err)
			}
			localProof := &models.TxFinalProof{
				Header:       block.BlockHeader.Clone(),
				Sigs:         block.BlockPass.Clone(),
				Tx:           tx.Clone(),
				Receipt:      receipt.Clone(),
				ReceiptProof: receiptProof,
			}
			if bs, err := rtl.Marshal(localProof); err != nil {
				return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("local proof marshal failed: %v", err)}, nil
			} else {
				return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
			}
		})
}

func (s *RPCServer) GetTxFinalProof(_ context.Context, req *RpcTxProofReq) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return s._txStreamByHash(common.ChainID(req.Chainid), common.BytesToHash(req.Hash),
		func(txIndex int, blockOfA *models.BlockEMessage, receipts models.Receipts, _ []byte) (*RpcResponseStream, error) {
			tx := blockOfA.BlockBody.Txs[txIndex]
			receipt := receipts[txIndex]
			if tx.Hash() != receipt.TxHash {
				return nil, errors.New("tx not match with receipt")
			}

			aHeader := blockOfA.BlockHeader
			aCid := aHeader.ChainID
			aHeight := aHeader.Height
			holder, err := s.dmanager.GetChainData(blockOfA.GetChainID())
			if err != nil || holder == nil {
				return nil, fmt.Errorf("get chain holder of ChainID:%d failed: %v", aCid, err)
			}
			proofedMainHeight := common.Height(req.ProofedMainHeight)
			if proofedMainHeight == 0 {
				proofedMainHeight = common.NilHeight
			}
			hashOfA, blockOfB, proofs, err := holder.ProofFinalBlock(aHeight, proofedMainHeight)
			if err != nil {
				return nil, fmt.Errorf("proof final block of ChainID:%d Height:%s failed: %v", aCid, &aHeight, err)
			}
			if !bytes.Equal(aHeader.Hash().Bytes(), hashOfA) {
				return nil, errors.New("block hash A not match")
			}
			receiptProof := make(trie.ProofChain, 0)
			if receiptRoot, err := receipts.Proof(txIndex, &receiptProof); err != nil {
				return nil, fmt.Errorf("proof receipt@%d/%d failed: %v", txIndex, len(receipts), err)
			} else {
				if !blockOfA.BlockHeader.ReceiptRoot.SliceEqual(receiptRoot) {
					return nil, fmt.Errorf("failed in generating proof of receipts root: want: %x, get: %x",
						common.ForPrint(blockOfA.BlockHeader.ReceiptRoot), common.ForPrint(receiptRoot))
				}
			}
			if _, err = aHeader.MakeProof(trie.ProofHeaderBase+models.BHReceiptRoot, &receiptProof); err != nil {
				return nil, fmt.Errorf("failed in generating receipt root header proof: %v", err)
			}
			receiptProof = append(receiptProof, proofs...)
			finalProof := &models.TxFinalProof{
				Header:       blockOfB.BlockHeader.Clone(),
				Sigs:         blockOfB.BlockPass.Clone(),
				Tx:           tx.Clone(),
				Receipt:      receipt.Clone(),
				ReceiptProof: receiptProof,
			}
			if bs, err := rtl.Marshal(finalProof); err != nil {
				return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("final proof marshal failed: %v", err)}, nil
			} else {
				return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
			}
		})
}

// GetTransactions return resp.data as []models.Transaction in JSON format
func (s *RPCServer) GetTransactions(_ context.Context, txs *RpcTxList) (*RpcResponse, error) {
	if txs == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	chainData, err := s.dmanager.GetChainData(common.ChainID(txs.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	changes := make([]*AccountChange, 0)
	targetAddr := common.BytesToAddress(txs.Address.Address)
	for h := txs.StartHeight; h < txs.EndHeight; h++ {
		height := common.Height(h)
		block, err := chainData.GetBlock(common.Height(h))
		if err != nil || block == nil || block.BlockBody == nil {
			if err != nil {
				s.logger.Error("[RPCServer] get block(chainid=%d, height=%d) error: %v", txs.Chainid, h, err)
				return newResponse(NilBlockCode, err.Error()), nil
			} else {
				s.logger.Warnf("[RPCServer] get block(chainid=%d, height=%d) body nil", txs.Chainid, h)
				break
			}
		} else {
			if config.IsLogOn(config.DataDebugLog) {
				s.logger.Debugf("[RPCServer] get block (chainid=%d,height=%d) DeltaFroms(%d) txs(%d)",
					block.BlockHeader.ChainID, block.BlockHeader.Height,
					len(block.BlockBody.DeltaFroms), len(block.BlockBody.Txs))
			}
			// DeltaFroms
			for i := 0; i < len(block.BlockBody.DeltaFroms); i++ {
				for j := 0; j < len(block.BlockBody.DeltaFroms[i].Deltas); j++ {
					if block.BlockBody.DeltaFroms[i].Deltas[j] == nil {
						continue
					}
					if block.BlockBody.DeltaFroms[i].Deltas[j].Addr == targetAddr {
						change := deltaFromToAccountChange(block.BlockHeader, block.BlockBody.DeltaFroms[i].Key,
							block.BlockBody.DeltaFroms[i].Deltas[j])
						if change != nil {
							changes = append(changes, change)
						}
					}
				}
			}

			// Txs
			for i := 0; i < len(block.BlockBody.Txs); i++ {
				if block.BlockBody.Txs[i] == nil {
					continue
				}

				if *(block.BlockBody.Txs[i].From) == targetAddr ||
					(block.BlockBody.Txs[i].To != nil && *(block.BlockBody.Txs[i].To) == targetAddr) {
					change := txToAccountChange(block.BlockHeader, height, block.BlockBody.Txs[i], block.BlockBody.TxsPas[i])
					if change != nil {
						changes = append(changes, change)
					}
				}
			}
		}
	}

	if jsons, err := json.Marshal(changes); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// SendTx return resp.data as returned information
func (s *RPCServer) SendTx(_ context.Context, tx *RpcTx) (*RpcResponse, error) {

	txmsg, txHash, resp := checkRpcTx(tx, true)
	if resp != nil {
		return resp, nil
	}

	cid := txmsg.ChainID

	checkAcc := func() (*RpcResponse, error) {
		var acc *models.Account
		var exist bool
		cdata, err := s.dmanager.GetChainData(cid)
		if err == nil {
			acc, exist = cdata.GetAccount(txmsg.From)
		}
		if !exist && ((txmsg.Val != nil && txmsg.Val.Sign() > 0) || len(txmsg.Input) == 0) {
			// The from account does not exist, transfer transactions, or contract calls with amounts
			// are prohibited
			return newResponse(InvalidFromAddressCode), nil
		}
		if acc == nil {
			acc = models.NewAccount(*txmsg.From, nil)
		}
		if acc.Nonce > txmsg.Nonce {
			return newResponse(InvalidParamsCode, "invalid nonce"), nil
		}
		return nil, nil
	}

	if s.dmanager.IsDataOrMemo() {
		if s.dmanager.IsDataNodeOf(txmsg.ChainID) || (s.dmanager.IsMemoNode() && *common.ForChain == txmsg.ChainID) {
			if config.IsLogOn(config.DataDebugLog) {
				s.logger.Debugf("[RPCServer] DataOrMemo receive to queue: %s with: {Hash:%x Pub:%x Sig:%x}",
					txmsg.FullString(), txHash, tx.Pub, tx.Sig)
			}
			if resp, err := checkAcc(); resp != nil || err != nil {
				return resp, err
			}
			// If the local node is the data node of the target chain, TX will be directly put into the queue
			if err := s.eventer.PostEvent(txmsg, tx.Pub, tx.Sig); err != nil {
				return newResponse(PostEventErrCode, err.Error()), nil
			}
		} else {
			if config.IsLogOn(config.DataDebugLog) {
				s.logger.Debugf("[RPCServer] DataOrMemo got a non-local %s", txmsg.FullString())
			}
			return nil, errors.New("not a node of chain")
		}
	} else {
		if config.IsLogOn(config.DataDebugLog) {
			s.logger.Debugf("[RPCServer] receive to queue: %s with: {Hash:%x Pub:%x Sig:%x}",
				txmsg.FullString(), txHash, tx.Pub, tx.Sig)
		}
		if resp, err := checkAcc(); resp != nil || err != nil {
			return resp, err
		}
		if err := s.eventer.PostEvent(txmsg, tx.Pub, tx.Sig); err != nil {
			return newResponse(PostEventErrCode, err.Error()), nil
		}
		// // In order to prevent attacks, transaction forwarding of other chains is not supported
		// if config.IsLogOn(config.DataDebugLog) {
		// 	s.logger.Debugf("[RPCServer] not a local tx, ignored")
		// }
		// // If it is a node of other types, TX will be broadcasted to the basic network of the main chain
		// relay := &models.RelayEventMsg{
		// 	RType:     models.RelayBroadcast,
		// 	ToChainID: common.MainChainID,
		// 	ToNetType: common.BasicNet,
		// 	Msg:       reshashmsg,
		// 	Pub:       tx.Pub,
		// 	Sig:       tx.Sig,
		// }
		// if config.IsLogOn(config.DataDebugLog) {
		// 	log.Debugf("[RPCServer] receive to relay: %s, %s", reshashmsg, relay)
		// }
		// s.eventer.Post(relay)
	}
	// hs := common.BytesToHash(hashOfEvent)
	hs := txmsg.Hash()
	return &RpcResponse{Code: SuccessCode, Data: hs.Hex()}, nil
}

func (s *RPCServer) GetStats(_ context.Context, req *RpcStatsReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	reqChainID := common.ChainID(req.Chainid)
	stats, err := s.dmanager.GetChainStats(reqChainID)
	if err != nil {
		return newResponse(InvalidParamsCode, err.Error()), nil
	}
	comm, err := s.engine.ChainComm(reqChainID)
	if err == nil && comm != nil {
		stats.CurrentComm = comm.Members
	}
	if jsons, err := json.Marshal(stats); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func headerToBlockInfo(header *models.BlockHeader) *BlockInfo {
	if header == nil {
		return nil
	}
	return &BlockInfo{
		Hash:             header.Hash(),
		PreviousHash:     header.PreviousHash,
		ChainID:          header.ChainID,
		Height:           header.Height,
		Empty:            header.Empty,
		RewardAddress:    header.RewardAddress,
		MergedDeltaRoot:  header.MergedDeltaRoot,
		BalanceDeltaRoot: header.BalanceDeltaRoot,
		StateRoot:        header.StateRoot,
		RREra:            header.RREra,
		RRCurrent:        header.RRRoot,
		RRNext:           header.RRNextRoot,
		TxCount:          0,
		TimeStamp:        header.TimeStamp,
	}
}

func summaryToBlockInfo(header *models.BlockSummary) *BlockInfo {
	if header == nil {
		return nil
	}
	h := header.Hob()
	return &BlockInfo{
		Hash:    common.BytesToHash(h),
		ChainID: header.GetChainID(),
		Height:  header.GetHeight(),
	}
}

func (s *RPCServer) GetBlockHeader(_ context.Context, req *RpcBlockHeight) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock %d Error: %v", common.Height(req.Height), err.Error())
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil || block.BlockHeader == nil {
		return newResponse(NilBlockCode), nil
	}
	info := headerToBlockInfo(block.BlockHeader)
	if block.BlockBody != nil {
		info.TxCount = len(block.BlockBody.NCMsg) + len(block.BlockBody.Txs)
	}
	if jsons, err := json.Marshal(info); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// Returns the serialized bytes of block data of the specified height (not JSON)
func (s *RPCServer) GetBlock(_ context.Context, req *RpcBlockHeight) (*RpcResponseStream, error) {
	if req == nil {
		return &RpcResponseStream{Code: InvalidParamsCode, Msg: "nil request"}, nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return &RpcResponseStream{Code: GetChainDataErrCode, Msg: err.Error()}, nil
	}
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock %d Error: %v", common.Height(req.Height), err)
		return &RpcResponseStream{Code: NilBlockCode, Msg: err.Error()}, nil
	}
	if block == nil {
		return &RpcResponseStream{Code: NilBlockCode, Msg: RpcErrMsgMap[NilBlockCode]}, nil
	}
	// apass, err := cdata.GetAuditings(common.Height(req.Height), block.BlockHeader)
	// if err != nil {
	// 	return &RpcResponseStream{Code: NilBlockCode, Msg: err.Error()}, nil
	// }
	// retBlock := new(BlockWithAuditings).Build(block, apass)
	// if config.IsLogOn(config.RpcLog) {
	// 	hob := block.Hash()
	// 	s.logger.Debugf("[RPC] GetBlock(ChainID:%d Height:%d): %s Hash:%x", req.Chainid, req.Height, block, hob)
	// }

	// bs, err := rtl.Marshal(retBlock)
	bs, err := rtl.Marshal(block)
	if err != nil {
		return &RpcResponseStream{Code: MarshalErrCode, Msg: err.Error()}, nil
	}
	return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
}

// returns up to 10 blocks starting at req.Height: [req.Height, min(req.Height+9, currentHeight)]
func (s *RPCServer) GetBlocks(_ context.Context, req *RpcBlockHeight) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	chainid := common.ChainID(req.Chainid)
	height := common.Height(req.Height)
	if chainid.IsNil() || height.IsNil() {
		return nil, errors.New("invalid chainid or height")
	}
	cdata, err := s.dmanager.GetChainData(chainid)
	if err != nil || cdata == nil {
		return nil, fmt.Errorf("get chain data of ChainID:%d failed: %v", chainid, err)
	}
	current := cdata.GetCurrentHeight()
	bs := &RpcBlocks{
		ChainID: common.ChainID(req.Chainid),
		Current: current,
	}
	last := current
	if diff, cmp := last.Diff(height); cmp > 0 && diff > 9 {
		last = height + 9
	}
	if current.Compare(height) >= 0 {
		for h := height; h.Compare(last) <= 0; h++ {
			block, err := cdata.GetBlock(h)
			if err != nil || block == nil {
				return nil, fmt.Errorf("get block of ChainID:%d Height:%s failed: %v", chainid, &h, err)
			}
			bs.Blocks = append(bs.Blocks, block)
		}
	}
	retBytes, err := rtl.Marshal(bs)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %v", err)
	}
	return &RpcResponseStream{Code: SuccessCode, Stream: retBytes}, nil
}

// Returns the sub chain block header information (block hash, Chain ID, block height) contained
// in the specified block
func (s *RPCServer) GetBlockHeaders(_ context.Context, req *RpcBlockHeight) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock(ChainID:%d, Height:%d) Error: %v", req.Chainid, req.Height, err)
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil || block.BlockBody == nil {
		return newResponse(NilTransactionCode), nil
	}
	var ret []*BlockInfo
	for _, hd := range block.BlockBody.Hds {
		if !hd.IsValid() {
			continue
		}
		info := summaryToBlockInfo(hd)
		ret = append(ret, info)
	}
	if jsons, err := json.Marshal(ret); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// Returns multiple transactions in the specified location (page+size) of the specified
// block (chainid+height), and the return value is []*ElectMessage+[]*AccountChange
func (s *RPCServer) GetBlockTxs(_ context.Context, req *RpcBlockTxsReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	height := common.Height(req.Height)
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock %d Error:", common.Height(req.Height), err.Error())
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil || block.BlockBody == nil {
		return newResponse(NilBlockCode), nil
	}

	page := req.Page - 1
	if page < 0 {
		page = 0
	}
	size := req.Size
	if size < 0 {
		size = 10
	}
	start := page * size
	end := start + size

	messages := &BlockMessage{}
	if req.Chainid == uint32(common.MainChainID) {
		elections := make([]*models.ElectMessage, 0)
		elength := int32(len(block.BlockBody.NCMsg))
		if start < elength {
			for i := start; i < elength && i < end; i++ {
				if block.BlockBody.NCMsg[i] == nil {
					continue
				}
				elections = append(elections, block.BlockBody.NCMsg[i])
			}
		}
		messages.Elections = elections
	}
	changes := make([]*AccountChange, 0)
	length := int32(len(block.BlockBody.Txs))
	if start < length {
		for i := start; i < length && i < end; i++ {
			if block.BlockBody.Txs[i] == nil {
				continue
			}
			changes = append(changes, txToAccountChange(block.BlockHeader, height, block.BlockBody.Txs[i], block.BlockBody.TxsPas[i]))
		}
	}
	messages.AccountChanges = changes
	if jsons, err := json.Marshal(messages); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetChainInfo Returns the chain information of the specified chain ID, which can be multiple. Return all
// when not specified
func (s *RPCServer) GetChainInfo(_ context.Context, req *RpcChainInfoReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cids := req.Chainid
	if len(cids) == 0 {
		// When there is no input, it means to get all chain information
		cl := s.dmanager.GetChainList()
		for i := 0; i < len(cl); i++ {
			cids = append(cids, uint32(cl[i]))
		}
	}

	// De-duplication
	cidMap := make(map[uint32]struct{})
	for _, cid := range cids {
		cidMap[cid] = struct{}{}
	}
	infoMap := make(map[uint32]*ChainInfo)
	for cid := range cidMap {
		info, exist := s.dmanager.GetChainInfos(common.ChainID(cid))
		if !exist {
			continue
		}
		var datanodes []DataNodeInfo
		for _, v := range info.BootNodes {
			var datanode DataNodeInfo
			id, _ := hex.DecodeString(v.NodeIDString)
			nodeid, _ := common.ParseNodeIDBytes(id)
			datanode.DataNodeId = *nodeid
			datanode.DataNodeIp = v.IP
			datanode.DataNodePort = v.DataRpcPort
			datanodes = append(datanodes, datanode)
		}
		ci := &ChainInfo{
			ChainId:   common.ChainID(cid),
			DataNodes: datanodes,
			Mode:      info.Mode,
			ParentId:  info.ParentID,
		}
		infoMap[cid] = ci
	}

	// Return in the order of request (it may return nil if there is an illegal ID corresponding
	// to the index)
	ret := make([]*ChainInfo, len(cids))
	for i, cid := range cids {
		ci, exist := infoMap[cid]
		if exist {
			ret[i] = ci
		} else {
			ret[i] = nil
		}
	}

	if jsons, err := json.Marshal(ret); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// MakeVccProof Get the information needed for cashing the check, serialized (not JSON)
func (s *RPCServer) MakeVccProof(_ context.Context, req *RpcCashCheck) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	vcc, err := req.ToCashCheck()
	if err != nil {
		s.logger.Errorf("MakeVccProof ToCashCheck error: %v", err)
		return newResponse(ToCashCheckErrCode, err.Error()), nil
	}
	if config.IsLogOn(config.DataDebugLog) {
		s.logger.Debugf("MakeVccProof(RpcCashCheck{%s}<=>%s)", req, vcc)
	}
	cdata, err := s.dmanager.GetChainData(vcc.FromChain)
	if err != nil {
		s.logger.Errorf("MakeVccProof GetChainData error: %v", err)
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	// The current block height confirmed by the parent chain and the proof of vcc to the block hash
	_, mainHeight, proofChain, proofedHash, err := cdata.VccProof(vcc)
	if err != nil {
		s.logger.Errorf("MakeVccProof VccProof error: %v", err)
		return newResponse(VccProofErrCode, err.Error()), nil
	}
	cashRequest := &models.CashRequest{
		Check:           vcc,
		ProofedChainID:  common.MainChainID,
		ProofHeight:     mainHeight,
		ProofHeaderHash: common.BytesToHash(proofedHash),
		Proofs:          proofChain,
	}
	buf, err := rtl.Marshal(cashRequest)
	if err != nil {
		s.logger.Errorf("MakeVccProof rtl.Marshal error: %v", err)
		return newResponse(MarshalErrCode, err.Error()), nil
	}
	if response, err := hexutil.Bytes(buf).MarshalText(); err != nil {
		s.logger.Errorf("MakeVccProof MarshalText error: %v", err)
		return newResponse(MarshalTextErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(response)}, nil
	}
}

// GetCommittee Get the nodeid list of consensus committee members of the specified epoch of the specified chain
func (s *RPCServer) GetCommittee(_ context.Context, req *RpcChainEpoch) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	comm, err := cdata.GetCommittee(common.ChainID(req.Chainid), common.EpochNum(req.Epoch).FirstHeight())
	if err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("GetCommittee error: %v", err)), nil
	}
	if comm == nil {
		return newResponse(InvalidParamsCode), nil
	}
	if jsons, err := json.Marshal(comm.Members); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// MakeCCCExistenceProof Generate the proof of non-payment to be used for revoking the check
func (s *RPCServer) MakeCCCExistenceProof(_ context.Context, req *RpcCashCheck) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	ccc, err := req.ToCashCheck()
	if err != nil {
		return newResponse(ToCashCheckErrCode, err.Error()), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.To.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	height, mainHeight, existence, existProof, cashedRootProof, proofedHash, err := cdata.CCCExsitenceProof(ccc)
	if err != nil {
		return newResponse(CCCExsitenceProofErrCode, err.Error()), nil
	}
	cccr := &models.CancelCashCheckRequest{
		Check:           ccc,
		AbsenceChainID:  common.ChainID(req.To.Chainid),
		AbsenceHeight:   height,
		ProofedHash:     common.BytesToHash(proofedHash),
		CCCProofs:       existProof,
		Proofs:          cashedRootProof,
		ConfirmedHeight: mainHeight,
	}
	buf, err := rtl.Marshal(cccr)
	if err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	}
	input, err := hexutil.Bytes(buf).MarshalText()
	if err != nil {
		return newResponse(MarshalTextErrCode, err.Error()), nil
	}
	cce := CashedCheckExistence{
		Existence: existence,
		Input:     string(input),
	}
	if jsons, err := json.Marshal(cce); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetCCCRelativeTx Get the hash of the transaction of the check cashed
func (s *RPCServer) GetCCCRelativeTx(_ context.Context, req *RpcCashCheck) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	ccc, err := req.ToCashCheck()
	if err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("ToCashCheck error: %v", err)), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.To.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	hashOfCcc, err := common.HashObject(ccc)
	if err != nil {
		return newResponse(HashObjectErrCode, err.Error()), nil
	}
	hashOfTx, err := cdata.GetCCCRelativeTx(hashOfCcc)
	if err != nil {
		return newResponse(GetCCCRelativeTxErrCode, err.Error()), nil
	}
	if hashOfTx == nil {
		return newResponse(NilTransactionCode, "hashOfTx is nil"), nil
	}
	h := common.BytesToHash(hashOfTx)
	return &RpcResponse{Code: SuccessCode, Data: h.Hex()}, nil
}

// GetRRProofs Get the proof of node pledge at the specified era (a specified root of required reserver tree)
func (s *RPCServer) GetRRProofs(_ context.Context, req *RpcRRProofReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "", "nil request"), nil
	}
	if err := req.Verify(); err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("request verify failed: %v", err)), nil
	}
	holder, err := s.dmanager.GetChainData(common.ChainID(req.ChainId))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	rootHash := common.BytesToHash(req.RootHash)
	nodeHash := common.BytesToHash(req.NodeHash)
	rrp, err := holder.GetRRProof(rootHash, nodeHash)
	if err != nil {
		return newResponse(GetRRProofErrCode, err.Error()), nil
	}
	if d, err := rtl.Marshal(rrp); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: hex.EncodeToString(d)}, nil
	}
}

func (s *RPCServer) GetRRCurrent(_ context.Context, req *RpcChainRequest) (*RpcResponse, error) {
	holder, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("get holder failed: %v", err)), nil
	}
	_, rrRoot, _, _, err := holder.RRStatus()
	if err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("get current root failed: %v", err)), nil
	}
	roothex := hex.EncodeToString(rrRoot)
	return &RpcResponse{Code: SuccessCode, Data: roothex}, nil
}

func (s *RPCServer) SendBlock(_ context.Context, req *RpcMsgReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	block := new(models.BlockEMessage)
	if err := rtl.Unmarshal(req.Msg, block); err != nil {
		return newResponse(UnmarshalErrCode, err.Error()), nil
	}
	s.logger.Infof("[RPC] receive %s", block)
	s.eventer.Post(block)
	return &RpcResponse{Code: SuccessCode, Data: "Success"}, nil
}

const (
	TCGenerateKey uint32 = 0x2
	TCHash        uint32 = 0x4
	TCSign        uint32 = 0x8
	TCVerify      uint32 = 0x10
)

// TryCrypto req.Type Bitwise operation:
//
// If TCVerify exists, the input Msg must be: Signature+Hash+PublicKey, if the verification is
// successful, return success, otherwise the verification fails
//
// If TCGenerateKey exists, generate a key pair and put it in the corresponding attribute of the
// return value
//
// If TCHash exists, all (without pre-private key) or part (with pre-private key) in req.Msg are
// the data to be hashed, and put the corresponding attribute of the return value after the hash.
//
// If TCSign exists, if there is no TCGenerateKey exists, the first N bytes of req.Msg are the
// private key. If there is TCHash, then the private key is followed by the data to be hashed,
// otherwise the hash value is calculated as required. The return value is put into the corresponding
// attribute.
func (s *RPCServer) TryCrypto(_ context.Context, req *RpcMsgReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}

	type result struct {
		PrivateKey hexutil.Bytes `json:"privatekey"`
		PublicKey  hexutil.Bytes `json:"publickey"`
		Hash       hexutil.Bytes `json:"hash"`
		Signature  hexutil.Bytes `json:"signature"`
	}

	ret := new(result)

	var cc cipher.Cipher
	cc = cipher.NewCipher(cipher.SECP256K1SHA3)
	log.Infof("[TRYCRYPTO] %s created, with Req:%s", cc, req)

	if req.Type&TCVerify > 0 {
		if len(req.Msg) != (cc.LengthOfSignature() + cc.LengthOfHash() + cc.LengthOfPublicKey()) {
			log.Debugf("[TRYCRYPTO] len of message (%d) should be %d",
				len(req.Msg), cc.LengthOfSignature()+cc.LengthOfHash()+cc.LengthOfPublicKey())
			return newResponse(InvalidParamsCode), nil
		}
		sig := req.Msg[:cc.LengthOfSignature()]
		hashb := req.Msg[cc.LengthOfSignature() : cc.LengthOfSignature()+cc.LengthOfHash()]
		pub := req.Msg[cc.LengthOfSignature()+cc.LengthOfHash():]
		if cc.Verify(pub, hashb, sig) {
			log.Debugf("[TRYCRYPTO] sig:%x hashb:%x pub:%x verified", sig, hashb, pub)
			return &RpcResponse{Code: SuccessCode, Data: "{}"}, nil
		}
		log.Debugf("[TRYCRYPTO] sig:%x hashb:%x pub:%x verify failed", sig, hashb, pub)
		return newResponse(InvalidSignatureCode), nil
	}

	if req.Type&TCGenerateKey > 0 {
		pk, err := cc.GenerateKey()
		if err != nil {
			log.Debugf("[TRYCRYPTO] generate key error: %v", err)
			return newResponse(OperationFailedCode), err
		}
		ret.PrivateKey = pk.ToBytes()
		ret.PublicKey = pk.GetPublicKey().ToBytes()
		log.Debugf("[TRYCRYPTO] priv:%x pub:%x generated", ret.PrivateKey, ret.PublicKey)
	}

	if req.Type&TCSign > 0 {
		if req.Type&TCGenerateKey == 0 && len(req.Msg) < cc.LengthOfPrivateKey() {
			log.Debugf("[TRYCRYPTO] len of message (%d) should not less than %d",
				len(req.Msg), cc.LengthOfPrivateKey())
			return newResponse(InvalidParamsCode), nil
		}

		p := 0
		priv := []byte(ret.PrivateKey)
		if req.Type&TCGenerateKey == 0 {
			priv = req.Msg[:cc.LengthOfPrivateKey()]
			p = cc.LengthOfPrivateKey()
		}
		log.Debugf("[TRYCRYPTO] priv:%x", priv)

		bs := req.Msg[p:]
		if req.Type&TCHash > 0 {
			ret.Hash = common.CipherHash256(cc, bs)
			log.Debugf("[TRYCRYPTO] len(data):%d, hash:%x", len(bs), ret.Hash)
			bs = ret.Hash
		} else {
			log.Debugf("[TRYCRYPTO] hash:%x", bs)
		}

		sig, err := cc.Sign(priv, bs)
		if err != nil {
			log.Debugf("[TRYCRYPTO] sign error: %v", err)
			return newResponse(OperationFailedCode), err
		}
		ret.Signature = sig
		log.Debugf("[TRYCRYPTO] signed: %x", sig)
	} else if req.Type&TCHash > 0 {
		data := req.Msg
		ret.Hash = common.CipherHash256(cc, data)
		log.Debugf("[TRYCRYPTO] len(data):%d, hash:%x", len(data), ret.Hash)
	}

	if jsons, err := json.Marshal(ret); err != nil {
		return newResponse(MarshalErrCode), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func (s *RPCServer) GetRRInfo(_ context.Context, req *RpcGetRRInfoReq) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if !s.dmanager.IsDataNode() {
		return nil, errors.New("not a data node")
	}
	holder, err := s.dmanager.ReadOnly().GetChainData(s.dmanager.DataNodeOf())
	if err != nil {
		return nil, fmt.Errorf("get readonly data holder for ChainID:%d failed: %v", s.dmanager.DataNodeOf(), err)
	}
	if !holder.IsRewardChain() {
		return nil, fmt.Errorf("ChainID:%d is not the reward chain", s.dmanager.DataNodeOf())
	}
	nid := common.BytesToNodeID(req.NodeId)
	nidh := nid.Hash()
	dbase := holder.GetDb()
	var rrRoot *common.Hash
	era := common.NilEra
	if len(req.Root) > 0 {
		rrRoot = common.BytesToHashP(req.Root)
	} else {
		if req.Era > 0 {
			era = common.EraNum(req.Era)
		} else {
			era, _, _, _, _ = holder.RRStatus()
		}
		root, err := dao.GetRRRootIndex(dbase, era)
		if err != nil {
			return nil, fmt.Errorf("RRRoot get failed by Era:%d Req:%s: %v", era, req, err)
		}
		if root == nil {
			return nil, fmt.Errorf("RRRoot not found by Era:%d Req:%s", era, req)
		}
		rrRoot = common.BytesToHashP(root)
	}
	// log.Warnf("[RPC] GetRRInfo(%s) nid:%x rrRoot:%x era:%d", req, nid[:], rrRoot.Slice(), era)

	rrState := models.NewRRStateDB(holder.GetStateDB())
	ret := &RRNodeInfo{
		Era:          era,
		Root:         *rrRoot,
		Changing:     holder.GetCurrentRRChanging(nidh),
		MaxDeposit:   rrState.MaxDepositSum(),
		ConsDepSum:   rrState.ConsensusDepSum(),
		DelegatedSum: rrState.DelegatedSum(),
		DataDepSum:   rrState.DataDepSum(),
	}

	rrTrie := holder.CreateRRTrie(rrRoot.Slice())
	v, _ := rrTrie.Get(nidh[:])
	info, _ := v.(*models.RRInfo)
	if info != nil {
		ret.Info = info
	}

	if bs, err := rtl.Marshal(ret); err != nil {
		return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("RRNodeInfo marshal failed: %v", err)}, nil
	} else {
		return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
	}
}

func (s *RPCServer) ListRRInfos(_ context.Context, req *RpcBlockTxsReq) (*RpcResponseStream, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}

	if req.Page < 0 || req.Size <= 0 {
		return nil, errors.New("invalid page/size")
	}
	start := int(req.Page) * int(req.Size)
	end := start + int(req.Size)

	cdata, err := s.dmanager.ReadOnly().GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return nil, err
	}
	if !cdata.IsRewardChain() {
		return nil, fmt.Errorf("ChainID:%d is not the reward chain", req.Chainid)
	}
	height := common.Height(req.Height)
	if height.IsNil() {
		height = cdata.GetCurrentHeight()
	}
	header, err := cdata.GetHeader(height)
	if err != nil || header == nil {
		return nil, fmt.Errorf("get header of Height:%d failed: %v", req.Height, err)
	}
	rrTrie := cdata.CreateRRTrie(header.RRRoot.Slice())
	var ret []*models.RRInfo
	i := 0
	rrTrie.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
		if i >= end {
			return false
		}
		if i >= start {
			info, ok := value.(*models.RRInfo)
			if ok && info != nil {
				ret = append(ret, info)
			}
		}
		i++
		return true
	})

	if bs, err := rtl.Marshal(ret); err != nil {
		return nil, fmt.Errorf("marshal failed: %v", err)
	} else {
		return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
	}
}

func (s *RPCServer) GetBTransactions(_ context.Context, req *RpcTxFilter) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	chainData, err := s.dmanager.ReadOnly().GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return nil, fmt.Errorf("get chain data failed: %v", err)
	}

	targetAddr := common.BytesToAddress(req.Address.Address)

	start := req.StartHeight
	end := req.EndHeight
	maxStep := uint64(500)
	if common.Height(start).IsNil() {
		start = 0
		if end > maxStep {
			end = maxStep
		}
	} else {
		overflow := false
		if end < start {
			if end, overflow = math.SafeAdd(start, maxStep); overflow {
				end = math.MaxUint64
			}
		} else {
			if end-start > maxStep {
				end = start + maxStep
			}
		}
	}

	ret := &BTxs{}
	h := start
	ret.Start = common.Height(h)
	for ; h < end; h++ {
		block, err := chainData.GetBlock(common.Height(h))
		if err != nil || block == nil || block.BlockBody == nil {
			if err != nil {
				return nil, fmt.Errorf("get block(ChainID:%d, Height:%d) failed: %v", req.Chainid, h, err)
			} else {
				s.logger.Warnf("[RPCServer] no more blocks, get block(chainid=%d, height=%d) body nil", req.Chainid, h)
				break
			}
		} else {
			if block.BlockBody == nil || len(block.BlockBody.Txs) == 0 {
				continue
			}
			if config.IsLogOn(config.DataDebugLog) {
				s.logger.Debugf("[RPCServer] get block (chainid=%d,height=%d) DeltaFroms(%d) txs(%d)", block.BlockHeader.ChainID,
					block.BlockHeader.Height, len(block.BlockBody.DeltaFroms), len(block.BlockBody.Txs))
			}
			if len(block.BlockBody.Txs) != len(block.BlockBody.TxsPas) {
				s.logger.Errorf("[RPCServer] block{ChainID:%d Height:%d} txs length(%d) not equals to"+
					" txspas length(%d)", block.BlockHeader.ChainID, block.BlockHeader.Height, len(block.BlockBody.Txs),
					len(block.BlockBody.TxsPas))
				continue
			}

			var receipts models.Receipts
			// Txs
			for i := 0; i < len(block.BlockBody.Txs); i++ {
				if block.BlockBody.Txs[i] == nil {
					continue
				}

				if *(block.BlockBody.Txs[i].From) == targetAddr ||
					(block.BlockBody.Txs[i].To != nil && *(block.BlockBody.Txs[i].To) == targetAddr) {
					if receipts == nil {
						if block.BlockHeader != nil &&
							block.BlockHeader.ReceiptRoot != nil &&
							!block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
							receiptHash := *(block.BlockHeader.ReceiptRoot)
							receipts = dao.ReadReceipts(chainData.GetDb(), receiptHash)
							if receipts == nil {
								receipts = make(models.Receipts, 0)
							}
						} else {
							receipts = make(models.Receipts, 0)
						}
					}
					if i >= len(receipts) || receipts[i] == nil {
						s.logger.Warnf("[RPCServer] block(ChainID:%d Height:%d) index:%d len(receipts):%d or nil receipt", req.Chainid, h, i, len(receipts))
						break
					}

					receipt := new(TransactionReceipt).FullReceipt(block.BlockBody.Txs[i], block.BlockBody.TxsPas[i],
						block.GetHeight(), receipts[i])
					ret.Txs = append(ret.Txs, receipt)
				}
			}
		}
	}
	ret.End = common.Height(h)

	if bs, err := rtl.Marshal(ret); err != nil {
		return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("TransactionReceipts marshal failed: %v", err)}, nil
	} else {
		return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
	}
}

func (s *RPCServer) GetRRTxByHash(_ context.Context, req *RpcTXHash) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	holder, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return nil, fmt.Errorf("get holder of ChainID:%d failed: %v", req.Chainid, err)
	}

	txHash := common.BytesToHash(req.Hash)
	txI, err := holder.GetBlockTxIndexs(txHash[:])
	if err != nil {
		return nil, fmt.Errorf("get tx index failed: %v", err)
	}
	if txI == nil {
		return &RpcResponseStream{Code: NilTransactionCode, Msg: "transaction not found"}, nil
	}

	block, err := holder.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return nil, fmt.Errorf("get block failed: %v", err)
	}
	if block == nil {
		return &RpcResponseStream{Code: NilBlockCode, Msg: "block not found"}, nil
	}

	if block.BlockHeader == nil || block.BlockBody == nil {
		return &RpcResponseStream{Code: NilBlockCode, Msg: "block header of body nil"}, nil
	}
	if int(txI.Index) < 0 || int(txI.Index) >= len(block.BlockBody.Txs) {
		return &RpcResponseStream{Code: NilTransactionCode, Msg: fmt.Sprintf("invalid tx index %d, txsLen:%d",
			txI.Index, len(block.BlockBody.Txs))}, nil
	}
	if len(block.BlockBody.Txs) != len(block.BlockBody.TxsPas) {
		return nil, fmt.Errorf("invalid length of txs pass(%d), length of txs(%d)",
			len(block.BlockBody.TxsPas), len(block.BlockBody.Txs))
	}
	tx := block.BlockBody.Txs[txI.Index]
	pas := block.BlockBody.TxsPas[txI.Index]
	var receipt *models.Receipt
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)
		receipts := dao.ReadReceipts(holder.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(txI.Index))
		if err != nil {
			return nil, fmt.Errorf("read receipt failed: %v", err)
		}
	}
	if receipt == nil {
		return &RpcResponseStream{Code: ReadReceiptErrCode, Msg: "receipt not found"}, nil
	}
	txrpt := new(TransactionReceipt).FullReceipt(tx, pas, block.GetHeight(), receipt)

	rrrpt, err := dao.ReadRRActReceipt(holder.GetDb(), txHash[:])
	if err != nil {
		return nil, fmt.Errorf("get RRActReceipt failed: %v", err)
	}

	ret := &RRTx{
		TxReceipt: txrpt,
		RRReceipt: rrrpt,
	}
	if bs, err := rtl.Marshal(ret); err != nil {
		return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("RRTx marshal failed: %v", err)}, nil
	} else {
		return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
	}
}

// CallTransaction return resp.data as TransactionReceipt in JSON format
func (s *RPCServer) Estimate(_ context.Context, tx *RpcTx) (*RpcResponse, error) {
	dmanager, err := s.dmanager.Simulate()
	if err != nil {
		return nil, fmt.Errorf("simulating failed: %v", err)
	}
	chainData, err := dmanager.GetChainData(common.ChainID(tx.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	txmsg, _, resp := checkRpcTx(tx, false)
	if resp != nil {
		return resp, nil
	}
	if txmsg.To == nil {
		return newResponse(InvalidParamsCode, "illegal to address"), nil
	}
	currentBlock := chainData.CurrentBlock()
	if currentBlock == nil {
		return newResponse(NilBlockCode), nil
	}
	used, err := chainData.Estimate(txmsg, currentBlock.BlockHeader)
	if err != nil {
		return newResponse(CallProcessTxErrCode, err.Error()), nil
	}
	result := &TransactionReceipt{
		Transaction: txmsg,
		GasUsed:     used,
	}
	if err == nil {
		result.Status = models.ReceiptStatusSuccessful
	} else {
		result.Error = err.Error()
	}
	// result := new(TransactionReceipt).PartReceipt(txmsg, tx.GetSignature(), receipt)
	if jsons, err := json.Marshal(result); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func (s *RPCServer) GetCommWithProof(_ context.Context, req *RpcChainEpoch) (*RpcResponseStream, error) {
	if req == nil {
		return nil, common.ErrNil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return nil, fmt.Errorf("get data holder of ChainID:%d failed: %v", req.Chainid, err)
	}
	reqEpoch := common.EpochNum(req.Epoch)
	currentHeight := cdata.GetCurrentHeight()
	availEpoch := currentHeight.EpochNum()
	if reqEpoch > availEpoch {
		return nil, fmt.Errorf("current epoch is %d", availEpoch)
	}
	block, hob, comm, commProof, lastHeight, lastProof, err := cdata.GetCommitteeWithBlockProof(common.EpochNum(req.Epoch))
	if err != nil {
		return nil, err
	}
	resp := &RpcCommProof{
		ChainID:      block.BlockHeader.ChainID,
		Epoch:        block.BlockHeader.Height.EpochNum() + 1,
		Height:       block.BlockHeader.Height,
		HashOfHeader: hob,
		Committee:    comm,
		Pass:         block.BlockPass,
		HeaderProof:  commProof,
		LastHeight:   lastHeight,
		LastProof:    lastProof,
	}
	bs, err := rtl.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal comm proof failed: %v", err)
	}
	return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
}

func (s *RPCServer) ListRRChanges(_ context.Context, req *RpcRRChangesReq) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if !s.dmanager.IsDataNode() {
		return nil, errors.New("not a data node")
	}
	holder, err := s.dmanager.ReadOnly().GetChainData(s.dmanager.DataNodeOf())
	if err != nil {
		return nil, fmt.Errorf("get readonly data holder for ChainID:%d failed: %v", s.dmanager.DataNodeOf(), err)
	}
	if !holder.IsRewardChain() {
		return nil, fmt.Errorf("ChainID:%d is not the reward chain", s.dmanager.DataNodeOf())
	}

	var era common.EraNum
	var root, nextRoot, changingRoot []byte
	var ret *RRChanges
	if len(req.Root) > 0 {
		changingRoot = req.Root
		ret = &RRChanges{Changing: common.BytesToHash(req.Root)}
	} else {
		era, root, nextRoot, changingRoot, err = holder.RRStatus()
		if err != nil {
			return nil, fmt.Errorf("get rr status failed: %v", err)
		}

		rrState := models.NewRRStateDB(holder.GetStateDB())
		ret = &RRChanges{
			Era:          era,
			Root:         common.BytesToHash(root),
			Next:         common.BytesToHash(nextRoot),
			Changing:     common.BytesToHash(changingRoot),
			MaxDeposit:   rrState.MaxDepositSum(),
			ConsDepSum:   rrState.ConsensusDepSum(),
			DelegatedSum: rrState.DelegatedSum(),
			DataDepSum:   rrState.DataDepSum(),
			Changes:      nil,
		}
	}

	nextTrie := holder.CreateRRTrie(nextRoot)
	changingTrie := holder.CreateRRChangingTrie(changingRoot)

	changingTrie.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
		changing := value.(*models.RRC)
		if changing == nil {
			return true
		}
		v, _ := nextTrie.Get(key)
		info, _ := v.(*models.RRInfo)
		changingNode := &RRNodeChanging{
			Info:     info,
			Changing: changing,
		}
		ret.Changes = append(ret.Changes, changingNode)
		return true
	})

	if bs, err := rtl.Marshal(ret); err != nil {
		return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("RRChanges marshal failed: %v", err)}, nil
	} else {
		return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
	}
}

func (s *RPCServer) GetConfirmeds(_ context.Context, req *RpcBlockHeight) (*RpcResponseStream, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	at, root, confirmeds, err := s.dmanager.GetConfirmedsAt(common.ChainID(req.Chainid), common.Height(req.Height))
	if err != nil {
		return nil, err
	}
	ret := &Confirmeds{
		At:   at,
		Root: root,
		Data: confirmeds,
	}
	if bs, err := rtl.Marshal(ret); err != nil {
		return &RpcResponseStream{Code: MarshalErrCode, Msg: fmt.Sprintf("Confirmeds marshal failed: %v", err)}, nil
	} else {
		return &RpcResponseStream{Code: SuccessCode, Stream: bs}, nil
	}
}

func (s *RPCServer) RebootMainChain(_ context.Context, req *RpcReboot) (*RpcResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	msg, err := req.ToMessage()
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, errors.New("failed to create message")
	}
	mainHolder, err := s.dmanager.GetChainData(common.MainChainID)
	if err != nil || mainHolder == nil {
		return nil, fmt.Errorf("get main chain holder failed: %v", err)
	}
	rebooting, err := mainHolder.MainChainRebootable(msg)
	if err != nil {
		return nil, err
	}
	s.eventer.Post(rebooting)
	return &RpcResponse{Code: SuccessCode}, nil
}

func (s *RPCServer) ListBridgeSessionsToAt(_ context.Context, req *RpcBridgeToAt) (*RpcResponseStream, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	holder, err := s.dmanager.GetChainData(common.ChainID(req.CurrentChain))
	if err != nil || holder == nil {
		return nil, fmt.Errorf("get holder of ChainID:%d failed: %v", req.CurrentChain, err)
	}
	reqCursor, respCursor, reqs, resps, err := holder.ListBridgeSessionsToAt(common.Height(req.AtHeight),
		common.ChainID(req.ToChain), common.Height(req.ReqHeight))
	if err != nil {
		return nil, err
	}
	output := &BridgeData{
		ReqCursor:  reqCursor,
		RespCursor: respCursor,
		Reqs:       reqs,
		Resps:      resps,
	}
	outbytes, err := rtl.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("marshal output failed: %v", err)
	}
	return &RpcResponseStream{Code: SuccessCode, Stream: outbytes}, nil
}
