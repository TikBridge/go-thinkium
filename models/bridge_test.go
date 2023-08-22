package models

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
)

func _createTempSessionTrie(dbase db.Database) (*BridgeSessionTrie, error) {
	t := NewBridgeSessionTrie(dbase, nil)
	req := &BridgeReq{
		FromChain:          1,
		FromContract:       AddressOfSysBridge,
		Height:             1145,
		ToChain:            2,
		ToContract:         AddressOfBridgeInfo,
		ToAccount:          MainAccountAddr,
		Nonce:              0,
		Value:              new(big.Int).SetUint64(223300),
		TokenID:            nil,
		Data:               nil,
		TokenType:          0,
		FromContractType:   MT_MAIN,
		TargetContractType: MT_MAPPING,
		Status:             0,
	}
	if err := t.PutRequest(req); err != nil {
		return nil, err
	}

	req = req.Clone()
	req.ToAccount = AddressOfRewardFrom
	if err := t.PutRequest(req); err != nil {
		return nil, err
	}

	req = req.Clone()
	req.Height = 1155
	req.Nonce = 2
	if err := t.PutRequest(req); err != nil {
		return nil, err
	}

	req = req.Clone()
	req.ToChain = 3
	req.ToAccount = MainAccountAddr
	req.Nonce = 1
	if err := t.PutRequest(req); err != nil {
		return nil, err
	}

	req = req.Clone()
	req.Height = 1100
	req.ToAccount = AddressOfGasReward
	req.Nonce = 222
	if err := t.PutRequest(req); err != nil {
		return nil, err
	}

	resp := &BridgeResp{
		SourceChain: 2,
		ReqHeight:   555,
		TargetChain: 1,
		BlockHeight: 1000,
		Account:     AddressOfGasReward,
		Nonce:       222,
		Status:      0,
	}
	if err := t.PutResponse(resp); err != nil {
		return nil, err
	}

	resp = resp.Clone()
	resp.Account = AddressOfRewardFrom
	resp.Nonce = 2200
	resp.Status = 1
	if err := t.PutResponse(resp); err != nil {
		return nil, err
	}

	resp = resp.Clone()
	resp.SourceChain = 3
	resp.BlockHeight = 444
	if err := t.PutResponse(resp); err != nil {
		return nil, err
	}

	if _, err := t.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

func TestBridgeSessionTrie_GetReqProof(t *testing.T) {
	dbase := db.NewMemDB()
	tr, err := _createTempSessionTrie(dbase)
	if err != nil {
		t.Fatalf("create trie failed: %v", err)
	}
	srcRoot, _ := tr.HashValue()

	peers, err := tr.ToPeerSessions()
	if err != nil {
		t.Fatalf("to sessions failed: %v", err)
	}

	for _, peer := range peers {
		for _, req := range peer.Reqs {
			proofs, err := tr.GetReqProof(req)
			if err != nil {
				t.Fatalf("get proof of %s failed: %v", req, err)
			}
			hashOfObj, err := common.HashObject(req)
			if err != nil {
				t.Fatalf("hash of %s failed: %v", req, err)
			}
			proofed, err := proofs.Proof(common.BytesToHash(hashOfObj))
			if err != nil {
				t.Fatalf("proofing %s by %x failed: %v", proofs, hashOfObj, err)
			}
			if !bytes.Equal(proofed, srcRoot) {
				t.Fatalf("verify %s by %x failed: expecting:%x but:%x", proofs, hashOfObj, srcRoot, proofed)
			} else {
				t.Logf("%s proof:%s root:%x check", req, proofs, srcRoot)
			}
		}

		for _, resp := range peer.Resps {
			proofs, err := tr.GetRespProof(resp)
			if err != nil {
				t.Fatalf("get proof of %s failed: %v", resp, err)
			}
			hashOfObj, err := common.HashObject(resp)
			if err != nil {
				t.Fatalf("hash of %s failed: %v", resp, err)
			}
			proofed, err := proofs.Proof(common.BytesToHash(hashOfObj))
			if err != nil {
				t.Fatalf("proofing %s by %x failed: %v", proofs, hashOfObj, err)
			}
			if !bytes.Equal(proofed, srcRoot) {
				t.Fatalf("verify %s by %x failed: expecting:%x but:%x", proofs, hashOfObj, srcRoot, proofed)
			} else {
				t.Logf("%s proof:%s root:%x check", resp, proofs, srcRoot)
			}
		}
	}
}

func TestBridgeSessionTrie_ToPeerSessions(t *testing.T) {
	dbase := db.NewMemDB()
	tr, err := _createTempSessionTrie(dbase)
	if err != nil {
		t.Fatalf("create trie failed: %v", err)
	}
	srcRoot, _ := tr.HashValue()
	peers, err := tr.ToPeerSessions()
	if err != nil {
		t.Fatalf("to sessions failed: %v", err)
	}
	t.Logf("%s", common.IndentLevel(0).InfoString(peers))

	dbase2 := db.NewMemDB()
	dest := NewBridgeSessionTrie(dbase2, nil)
	for i, peer := range peers {
		if err := dest.BuildPeer(peer); err != nil {
			t.Fatalf("build peer index:%d Val:%s failed: %v", i, peer, err)
		}
	}
	destRoot, _ := dest.Commit()
	if !TrieRootEqual(srcRoot, destRoot) {
		t.Fatalf("rebuild by %s failed, source root:%x dest root:%x", peers, srcRoot, destRoot)
	}
}

func TestBridgeSessionTrie_CopyFrom(t *testing.T) {
	dbase := db.NewMemDB()
	tr, err := _createTempSessionTrie(dbase)
	if err != nil {
		t.Fatalf("create trie failed: %v", err)
	}
	srcRoot, _ := tr.HashValue()

	dbase2 := db.NewMemDB()
	dest := NewBridgeSessionTrie(dbase2, nil)
	if destRoot, err := dest.CopyFrom(tr); err != nil {
		t.Fatalf("copy from failed: %v", err)
	} else {
		if !TrieRootEqual(srcRoot, destRoot) {
			t.Fatalf("copyed root:%x but source root:%x", destRoot, srcRoot)
		} else {
			t.Logf("root check: %x", srcRoot)
		}
	}
}
