package models

import (
	"encoding/binary"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
)

var (
	// prefix+hash -> Account Trie Node and Value
	KPAccountNode  = []byte("aa")
	KPAccountValue = []byte("ab")
	// prefix+hash -> Code of Account
	KPCode = []byte("ac")
	// prefix+hash -> Account Storage Trie Node
	KPAccStorageNode = []byte("ad")
	// prefix+hash -> Account Long Storage Trie Node and Value (for system contract)
	KPAccLongNode  = []byte("am")
	KPAccLongValue = []byte("an")
	// shard chain
	// prefix + hash -> AccountDelta Trie Node and Value
	KPDeltaNodeNode  = []byte("ae")
	KPDeltaNodeValue = []byte("af")
	// prefix + header.BalanceDeltaRoot -> combined trie of AccountDelta Tries
	KPDeltaTrie = []byte("ag")
	// prefix + shard.ElectChainID.Formalize() + heightOfBlock.Bytes() -> hash root of Account
	KPDeltaFromTrie = []byte("ah")
	// prefix + DeltaFromKey{ShardID, Height} -> serialization of []*AccountDelta
	KPDeltaFroms          = []byte("ai")
	KPDeltaFromMaxHeight  = []byte("aj")
	KPDeltaFromWaterline  = []byte("ak")
	KPDeltaToBeSent       = []byte("ao")
	KPDFWaterlineSnapshot = []byte("ap")

	// prefix + HistoryTree.Node.Hash -> HistoryTree.Node.Children/Leafs
	KPHistoryNode = []byte("al")

	// prefix+hash -> Transaction Trie Node and Value
	KPTxNode  = []byte("tk")
	KPTxValue = []byte("tv")
	// prefix+hash -> Transaction in block  and index of the all transactions
	KPTxIndex = []byte("ti")

	// prefix + hash -> Verifiable Cash Check Trie Node and Value
	KPVccNode  = []byte("va")
	KPVccValue = []byte("vb")
	// prefix + hash -> Cashed Verifiable Cash Check Trie Node and Value
	KPCVccNode  = []byte("vc")
	KPCVccValue = []byte("vd")
	// prefix + Vcc.Hash -> cash the check Tx.Hash
	KPCVccTxIndex = []byte("ve")

	// prefix+hash(Header) -> block/Header height
	KPBlockNumByHash = []byte("bn")
	// prefix+height -> Header hash
	KPBlockHashByNum = []byte("bh")
	// prefix+hash(header) -> block encoded value
	KPBlock = []byte("bb")
	// prefix -> current Highest block height
	KPCurrentHeight = []byte("bc")
	// prefix+hash(Header) -> Receipts
	KPReceipts = []byte("br")
	// prefix+height -> received data block (not yet processed, just persisted in the database)
	KPBlockNotVerified = []byte("bv")
	// prefix+ChainID+EpochNum -> election results of the EpochNum'th committee
	// key is the elected Epoch, not the Epoch at the time of the election, starting
	// from 0. If the election result fails, continue
	KPEpochComm = []byte("bec")
	// prefix+EpochNum -> Height of the block including the election results of the committee of EpochNum
	KPEpochCommIndex = []byte("bei")

	// main chain
	// prefix + FormalizedChainID -> ChainInfos Trie Node and Value
	KPChainNode  = []byte("cn")
	KPChainValue = []byte("ci")
	// prefix + ChainId + EpochNum -> Committee
	KPChainEpochCommittee = []byte("ce")
	// // prefix + ChainId + Height -> Header
	// KPChainHeightHeader = []byte("ch")
	// // prefix + ChainId + Height -> BlockProof
	// KPChainHeightProof = []byte("cp")

	// save HDS in the parent block to current sub-chain database by the info of the parent block
	// prefix + Y.ChainID + Y.Height -> {KPConfirmedHdsByParentInfo + parent.ChainID + parent.Height}|(Y=BlockSummary, parent.Hds ⊇ X.Height)
	KPConfirmedHdsByParentCursor = []byte("ch")
	// prefix + X.ChainID + X.Height -> {block.Header, block.body.Hds}|(block.ChainID==X.ChainID, block.Height==X.Height)
	KPConfirmedHdsByParentInfo = []byte("cp")

	// // prefix+ChainID -> the latest (block height + block Hash) of current chain has been reported
	// KPLastReportedCursor = []byte("cc")
	// prefix+ChainID -> the latest (block height + block Hash + comm Epoch) has been confirmed by parent chain
	KPLastConfirmedCursor = []byte("cca")

	// prefix of Sub Confirmed Info Trie
	KPSubConfirmedNode  = []byte("ca")
	KPSubConfirmedValue = []byte("cb")
	KPRestartHisNode    = []byte("cd")
	KPRestartHisValue   = []byte("cg")

	// the earliest Cursor on the main chain received by the current node and has not yet
	// issued a reward, the reward can be issue from this height to process the Request
	KPRewardHeightCursor = []byte("cf")
	KPRewardBase         = []byte("rb")

	KPRRNode          = []byte("ra") // Required Reserve Trie Node Prefix
	KPRRValue         = []byte("rc") // Required Reserve Trie Value Prefix
	KPRRCNode         = []byte("rd") // Required Reserve Changing Trie Node Prefix
	KPRRCValue        = []byte("re") // Required Reserve Changing Trie Value Prefix
	KPRRRoot          = []byte("rf") // Required Reserve Trie Root Hash: prefix+EraNum -> RootOfRRTrie
	KPSettleInfoNode  = []byte("rg") // Settle info for one node trie node prefix
	KPSettleInfoValue = []byte("ri") // settle info for one node trie value preifx
	KPRRActReceipts   = []byte("rh") // RRAct Receipts in one block, prefix+RRActReceipts.RootHash -> (stream of RRActReceipts)
	KPRRActRptIndex   = []byte("rj") // prefix+TxHash -> (RRActReceipts.RootHash, Index in RRActReceipts)

	KPStorageEntry = []byte("se")

	// prefix + ChainID + Height -> [{BlockHash, AuditPass}]
	KPAuditorMsgs = []byte("aq")

	KPBridgeReqTrieNode  = []byte("ba") // sub-chain: bridge request trie node
	KPBridgeReqTrieValue = []byte("bd") // sub-chain: bridge request trie value
	KPBridgeReqNode      = []byte("bf") // sub-chain: bridge request node
	KPBridgeReqValue     = []byte("bg") // sub-chain: bridge request value
	KPBridgeRespNode     = []byte("bk") // sub-chain: bridge response node
	KPBridgeRespValue    = []byte("bl") // sub-chain: bridge respose value
	KPBridgeInfoNode     = []byte("bi") // main-chain: bridge info node
	KPBridgeInfoValue    = []byte("bj") // main-chain: bridge info value

	//
	// RRProofs for current node, (prefix + RRRoot + NodeID[:5]) -> RRProofs
	KPRRProofs      = []byte("rk")
	KPConfirmBlock  = []byte("cb")
	KPVersionInfo   = []byte("vi")
	KPWorkingChains = []byte("wc")
)

func ToBlockNumberKey(hashOfHeader []byte) []byte {
	return db.PrefixKey(KPBlockNumByHash, hashOfHeader)
}

func ToBlockHashKey(height common.Height) []byte {
	return db.PrefixKey(KPBlockHashByNum, height.Bytes())
}

//
// func ToBlockHeaderKey(hashOfHeader []byte) []byte {
// 	return db.PrefixKey(KPBlockHeader, hashOfHeader)
// }

func ToBlockTXIndexKey(hashOfTransacion []byte) []byte {
	return db.PrefixKey(KPTxIndex, hashOfTransacion)
}

func ToBlockReceiptsKey(hashOfHeader []byte) []byte {
	return db.PrefixKey(KPReceipts, hashOfHeader)
}

func ToBlockKey(hashOfHeader []byte) []byte {
	return db.PrefixKey(KPBlock, hashOfHeader)
}

func ToBlockNotVerified(height common.Height) []byte {
	return db.PrefixKey(KPBlockNotVerified, height.Bytes())
}

func ToCurrentHeightKey() []byte {
	return KPCurrentHeight
}

// func ToReceivedDeltaHashKey(fromID common.ChainID, height common.Height) []byte {
// 	return db.PrefixKey2(KPReceivedDeltaHash, fromID.Formalize(), height.Bytes())
// }

func ToDeltaFromKey(fromID common.ChainID, height common.Height) []byte {
	return db.PrefixKey2(KPDeltaFroms, fromID.Formalize(), height.Bytes())
}

func ToDeltaFromMaxHeightKey(fromID common.ChainID) []byte {
	return db.PrefixKey(KPDeltaFromMaxHeight, fromID.Formalize())
}

func ToDeltaFromWaterlineKey(fromID common.ChainID) []byte {
	return db.PrefixKey(KPDeltaFromWaterline, fromID.Formalize())
}

func ToDeltaToBeSentKey() []byte {
	return KPDeltaToBeSent
}

func ToDFWaterlineSnapshotKey(hashOfWaterlines []byte) []byte {
	return db.PrefixKey(KPDFWaterlineSnapshot, hashOfWaterlines)
}

func ToChainCommitteeKey(chainId common.ChainID, epochNum common.EpochNum) []byte {
	return db.PrefixKey2(KPChainEpochCommittee, chainId.Formalize(), epochNum.Bytes())
}

func ToEpochCommKey(chainId common.ChainID, epoch common.EpochNum) []byte {
	return db.PrefixKey2(KPEpochComm, chainId.Formalize(), epoch.Bytes())
}

func ToEpochCommIndexKey(epoch common.EpochNum) []byte {
	return db.PrefixKey(KPEpochCommIndex, epoch.Bytes())
}

//
// func ToChainHeightHeaderKey(chainId common.ChainID, height common.Height) []byte {
// 	return db.PrefixKey2(KPChainHeightHeader, chainId.Formalize(), height.Bytes())
// }
//
// func ToChainHeightProofKey(chainId common.ChainID, height common.Height) []byte {
// 	return db.PrefixKey2(KPChainHeightProof, chainId.Formalize(), height.Bytes())
// }

func ToFirstRewardCursorKey() []byte {
	return KPRewardHeightCursor
}

func ToLastConfirmedCursorKey(chainId common.ChainID) []byte {
	return db.PrefixKey(KPLastConfirmedCursor, chainId.Formalize())
}

func ToRewardBaseKey(chainId common.ChainID) []byte {
	return db.PrefixKey(KPRewardBase, chainId.Formalize())
}

func ToRRKey(era common.EraNum) []byte {
	return db.PrefixKey(KPRRRoot, era.Bytes())
}

func ToStorageEntryKey(root []byte, num int) []byte {
	nb := make([]byte, 4) // used for data synchronization, has no effect on data storage
	binary.BigEndian.PutUint32(nb, uint32(num))
	return db.PrefixKey2(KPStorageEntry, root, nb)
}

func ToRRActReceiptsKey(rootOfReceipts []byte) []byte {
	return db.PrefixKey(KPRRActReceipts, rootOfReceipts)
}

func ToRRActRptIndexKey(hashOfTx []byte) []byte {
	return db.PrefixKey(KPRRActRptIndex, hashOfTx)
}
