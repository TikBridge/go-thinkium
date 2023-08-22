package models

import (
	"bytes"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

func TestStateStreams_Hash(t *testing.T) {

	appendHashList := func(list [][]byte, streams ...[]byte) [][]byte {
		for i := 0; i < len(streams); i++ {
			if hash, err := common.HashObject(streams[i]); err == nil {
				list = append(list, hash)
			}
		}
		return list
	}
	makeHashList := func(msgbuf []byte, streams *StateStreams, hashOfBlock common.Hash) [][]byte {
		var hashList [][]byte
		hashList = appendHashList(hashList, msgbuf)
		hashList = appendHashList(hashList, streams.Storages...)
		hashList = appendHashList(hashList, streams.Codes...)
		hashList = appendHashList(hashList, streams.Longs...)
		hashList = appendHashList(hashList, streams.Accounts...)
		hashList = appendHashList(hashList, streams.Deltas...)
		hashList = appendHashList(hashList, streams.Chains)
		hashList = appendHashList(hashList, streams.Confirmeds)
		hashList = appendHashList(hashList, streams.BridgeInfos)
		hashList = appendHashList(hashList, streams.BridgePeers)
		if hashOfBlock != common.EmptyHash {
			hashList = append(hashList, hashOfBlock[:])
		}
		return hashList
	}

	randomByteSlices := func(x, y int) [][]byte {
		ret := make([][]byte, x)
		for i := 0; i < len(ret); i++ {
			ret[i] = common.RandomBytes(y)
		}
		return ret
	}
	var roots [][]byte
	var bodys [][]byte
	var proofList []*common.MerkleProofs
	makeSyncStream := func(hashList [][]byte, startNum int, streams [][]byte) int {
		for i := 0; i < len(streams); i++ {
			bodynum := startNum + i
			proofs := common.NewMerkleProofs()
			root, err := common.MerkleHashComplete(hashList, bodynum, proofs)
			if err != nil {
				log.Errorf("MerkleHashComplete %d error %v", bodynum, err)
			}
			bodys = append(bodys, streams[i])
			roots = append(roots, root)
			proofList = append(proofList, proofs)
		}
		return startNum + len(streams)
	}
	stream := &StateStreams{
		Accounts:    randomByteSlices(10, 10),
		Storages:    randomByteSlices(2, 20),
		Codes:       randomByteSlices(2, 19),
		Longs:       randomByteSlices(1, 1),
		Deltas:      randomByteSlices(1, 1),
		Chains:      nil,
		Confirmeds:  nil,
		BridgeInfos: nil,
		BridgePeers: common.RandomBytes(80),
	}
	mybuf := common.RandomBytes(100)
	hob := common.BytesToHash(common.RandomBytes(32))
	hashList := makeHashList(mybuf, stream, hob)

	i := makeSyncStream(hashList, 0, [][]byte{mybuf})
	i = makeSyncStream(hashList, i, stream.Storages)
	i = makeSyncStream(hashList, i, stream.Codes)
	i = makeSyncStream(hashList, i, stream.Longs)
	i = makeSyncStream(hashList, i, stream.Accounts)
	i = makeSyncStream(hashList, i, stream.Deltas)
	if len(stream.Chains) > 0 {
		i = makeSyncStream(hashList, i, [][]byte{stream.Chains})
	}
	if len(stream.Confirmeds) > 0 {
		i = makeSyncStream(hashList, i, [][]byte{stream.Confirmeds})
	}
	if len(stream.BridgeInfos) > 0 {
		i = makeSyncStream(hashList, i, [][]byte{stream.BridgeInfos})
	}
	if len(stream.BridgePeers) > 0 {
		i = makeSyncStream(hashList, i, [][]byte{stream.BridgePeers})
	}

	for i := 0; i < len(roots); i++ {
		h, err := common.HashObject(bodys[i])
		if err != nil {
			t.Fatal(err)
		}
		root, err := proofList[i].Proof(common.BytesToHash(h))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(root, roots[i]) {
			t.Log(i, "check")
		} else {
			t.Fatal(i, "failed")
		}
	}
}
