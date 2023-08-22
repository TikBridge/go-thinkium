package dao

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/stephenfire/go-rtl"
)

// Block

func _saveHeaderIndexes(dbase db.Database, hashOfHeader []byte, header *models.BlockHeader) error {
	batch := dbase.NewBatch()
	// save Height->Hash
	hashkey := models.ToBlockHashKey(header.Height)
	if err := batch.Put(hashkey, hashOfHeader); err != nil {
		return err
	}
	// save Hash->Height
	heightkey := models.ToBlockNumberKey(hashOfHeader)
	if err := batch.Put(heightkey, header.Height.Bytes()); err != nil {
		return err
	}

	if err := dbase.Batch(batch); err != nil {
		return err
	}
	return nil
}

func GetBlockHash(dbase db.Database, height common.Height) ([]byte, error) {
	key := models.ToBlockHashKey(height)
	hashOfHeader, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	return hashOfHeader, nil
}

// Returns the number of saved transaction indexes and errors
func SaveBlock(dbase db.Database, block *models.BlockEMessage, hashOfHeader []byte) (int, error) {

	key := models.ToBlockKey(hashOfHeader)
	data, err := rtl.Marshal(block)
	if err != nil {
		return 0, err
	}
	// save Hash->Block
	if err = dbase.Put(key, data); err != nil {
		return 0, fmt.Errorf("save hash->block error: %v", err)
	}

	// Writes the index of all transactions in the block to the database
	txCount, err := SaveBlockTxIndexs(dbase, block)
	if err != nil {
		return 0, fmt.Errorf("save block tx index error: %v", err)
	}

	if err := _saveHeaderIndexes(dbase, hashOfHeader, block.BlockHeader); err != nil {
		return 0, fmt.Errorf("save header index failed: %v", err)
	}

	// Record cursors of blocks reported by child chains
	if block.BlockBody != nil && len(block.BlockBody.Hds) > 0 {
		if err := SaveBlockSummary(dbase, block.BlockBody.Hds); err != nil {
			return 0, fmt.Errorf("save reports error: %v", err)
		}
	}
	return txCount, nil
}

func LoadBlock(dbase db.Database, hashOfHeader []byte) (*models.BlockEMessage, error) {
	if hashOfHeader == nil || bytes.Compare(common.NilHashSlice, hashOfHeader) == 0 {
		return nil, nil
	}
	key := models.ToBlockKey(hashOfHeader)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if err = rtl.Unmarshal(data, block); err != nil {
		return nil, err
	}
	return block, nil
}

// Record the block height cursors of all the children chains that have been packaged and
// confirmed on the parent chain (current is the parent chain)
func SaveBlockSummary(dbase db.Database, hds []*models.BlockSummary) error {
	// cache summary with available committee specified by chain id and epoch number
	cm := make(map[common.ChainID]map[common.EpochNum]*models.BlockSummary)

	// Traverse the confirmed report block information:
	// 1. record the cursors of each chain
	// 2. find the Committee information of the sub-chain that needs to be saved
	for _, hd := range hds {
		if !hd.IsValid() {
			continue
		}

		if hd.NextComm.IsAvailable() {
			// Record the sub chain committee, avoid repeated writing
			curEpoch := hd.GetHeight().EpochNum()
			cmm, ok := cm[hd.GetChainID()]
			if !ok {
				cmm = make(map[common.EpochNum]*models.BlockSummary)
				cm[hd.GetChainID()] = cmm
			}
			cmm[curEpoch+1] = hd
		}
	}

	// write new committees of sub-chains
	// convert sub chain committee information into slice and write it through batch
	var epochs []*models.BlockSummary
	for _, cmm := range cm {
		for _, b := range cmm {
			epochs = append(epochs, b)
		}
	}
	_, _ = db.BatchWrite(dbase, 50, len(epochs), func(j int, w db.Writer) (ok bool, err error) {
		if err := SaveEpochCommittee(w, epochs[j].GetChainID(), epochs[j].GetHeight().EpochNum()+1,
			epochs[j].NextComm); err != nil {
			log.Warnf("save next committee %s failed: %v", epochs[j], err)
		} else {
			if config.IsLogOn(config.DataDebugLog) {
				log.Debugf("next committee of %s saved", epochs[j])
			}
		}
		return true, nil
	})
	return nil
}

// Save transation index in the block
func SaveBlockTxIndexs(dbase db.Database, block *models.BlockEMessage) (count int, err error) {
	if block == nil || block.BlockHeader == nil {
		return
	}
	header := block.BlockHeader
	var txs []*models.Transaction
	if block.BlockBody != nil {
		txs = block.BlockBody.Txs
	}

	return db.BatchWrite(dbase, 100, len(txs), func(j int, w db.Writer) (ok bool, err error) {
		if txs[j] == nil {
			return false, nil
		}
		txIndex := models.NewTXIndex(uint64(header.Height), header.Hash(), uint32(j))
		key := models.ToBlockTXIndexKey(txs[j].Hash().Bytes())
		data, err := rtl.Marshal(txIndex)
		if err != nil {
			return false, err
		}
		// save Tx.Hash->Block.Height_Hash_Index
		// if err = bc.chaindb.Put(key, data); err != nil {
		if err = w.Put(key, data); err != nil {
			log.Errorf("SaveBlockTxIndexes(%x, %s) failed: %v", txs[j].Hash().Bytes(), txIndex, err)
			return false, err
		}
		return true, nil
	})
}

func GetTxIndex(dbase db.Database, txHash []byte) (*models.TXIndex, error) {
	key := models.ToBlockTXIndexKey(txHash)

	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("GetTxIndex not found")
	}
	txIndex := models.NewTXIndex(0, common.Hash{}, 0)

	err = rtl.Unmarshal(data, txIndex)
	if err != nil {
		return nil, err
	}
	return txIndex, err
}

func saveCursor(w db.Writer, key []byte, height common.Height, hashOfBlock []byte) error {
	cursor := models.BlockCursor{
		Height: height,
		Hash:   hashOfBlock,
	}
	cursorBytes, err := rtl.Marshal(cursor)
	if err != nil {
		return err
	}
	if err = w.Put(key, cursorBytes); err != nil {
		return err
	}
	return nil
}

func loadCursor(dbase db.Database, key []byte) (height common.Height, hashOfBlock []byte, exist bool, err error) {
	data, err := dbase.Get(key)
	if err != nil {
		return 0, nil, false, err
	}
	if len(data) == 0 {
		return 0, nil, false, nil
	}
	cursor := &models.BlockCursor{}
	if err = rtl.Unmarshal(data, cursor); err != nil {
		return 0, nil, false, err
	}
	if cursor.Height.IsNil() || len(cursor.Hash) == 0 {
		return 0, nil, false, nil
	}
	return cursor.Height, cursor.Hash, true, nil
}

// Block Cursor
func SaveBlockCursor(dbase db.Database, height common.Height, hashOfHeader []byte) error {
	return saveCursor(dbase, models.ToCurrentHeightKey(), height, hashOfHeader)
}

func LoadBlockCursor(dbase db.Database) (common.Height, []byte, error) {
	height, hob, _, err := loadCursor(dbase, models.ToCurrentHeightKey())
	return height, hob, err
}

func CheckBlockExist(dbase db.Database, height common.Height) ([]byte, bool) {
	hashKey := models.ToBlockHashKey(height)
	hashOfHeader, err := db.GetNilError(dbase, hashKey)
	if err != nil {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("get hash of Height:%d error: %v", height, err)
		}
		return nil, false
	}
	exist, err := dbase.Has(models.ToBlockKey(hashOfHeader))
	if err != nil {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("check existence of block(Height:%d Hash:%x) error: %v", height, hashOfHeader[:5], err)
		}
		return nil, false
	}
	return hashOfHeader, exist
}

func SetCursorManually(dbase db.Database, id common.ChainID, to common.Height) error {
	hoh, exist := CheckBlockExist(dbase, to)
	if !exist {
		return fmt.Errorf("block Height:%d not found", to)
	}
	old, oldhash, err := LoadBlockCursor(dbase)
	if err != nil {
		return common.NewDvppError("load old cursor failed", err)
	}
	log.Infof("old cursor of ChainID:%d is: Height:%d Hash:%x, setting new cursor to: Height:%d Hash:%x",
		id, old, oldhash, to, hoh)
	return SaveBlockCursor(dbase, to, hoh)
}

//
// // Save Chain Epoch Committee
// func SaveChainCommittee(dbase db.Database, chainID common.ChainID, epochNum common.EpochNum, committee *models.Committee) error {
// 	commBytes, err := rtl.Marshal(committee)
// 	if err != nil {
// 		return err
// 	}
// 	if err = dbase.Put(models.ToChainCommitteeKey(chainID, epochNum), commBytes); err != nil {
// 		return err
// 	}
// 	return nil
// }

// Get Chain Epoch Committee
func GetChainCommittee(dbase db.Database, chainID common.ChainID, epochNum common.EpochNum) (*models.Committee, error) {
	bs, err := dbase.Get(models.ToChainCommitteeKey(chainID, epochNum))
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, nil
	}
	comm := new(models.Committee)
	if err = rtl.Unmarshal(bs, comm); err != nil {
		return nil, err
	}
	return comm, nil
}

func SaveNextCommittee(dbase db.Database, chainId common.ChainID, nextEpoch common.EpochNum, current, next *models.Committee) error {
	ec := models.NewEpochComm(next, current)
	return SaveEpochCommittee(dbase, chainId, nextEpoch, ec)
}

func SaveEpochCommittee(dbase db.Writer, chainId common.ChainID, epoch common.EpochNum, ec *models.EpochCommittee) error {
	if ec.IsEmpty() {
		if config.IsLogOn(config.DataLog) {
			log.Warnf("ignoring SaveEpochCommitte(ChainID:%d, Epoch:%d, %s) which is empty", chainId, epoch, ec)
		}
		return nil
	}
	eac := new(models.EpochAllCommittee).From(ec)
	return _saveEpochAllCommittee(dbase, chainId, epoch, eac)
}

// func SaveRestartCommittee(dbase db.Database, chainId common.ChainID, start, electedAt common.Height, comm *models.Committee) error {
// 	if start.IsNil() {
// 		return errors.New("start height is nil")
// 	}
// 	if !comm.IsAvailable() {
// 		return errors.New("comm not available")
// 	}
// 	epoch := start.EpochNum()
// 	eac, err := LoadEpochCommittee(dbase, chainId, epoch)
// 	if err != nil {
// 		return fmt.Errorf("load committee of Epoch:%d failed: %v", epoch, err)
// 	}
// 	if eac == nil {
// 		return fmt.Errorf("no committee of Epoch:%d loaded", epoch)
// 	}
// 	if err = eac.AppendReComm(start, electedAt, comm); err != nil {
// 		return fmt.Errorf("append ReComm failed: %v", err)
// 	}
// 	return _saveEpochAllCommittee(dbase, chainId, epoch, eac)
// }

func ResetEpochAllCommittee(dbase db.Writer, id common.ChainID, epoch common.EpochNum, eac *models.EpochAllCommittee) error {
	return _saveEpochAllCommittee(dbase, id, epoch, eac)
}

func _saveEpochAllCommittee(dbase db.Writer, id common.ChainID, epoch common.EpochNum, eac *models.EpochAllCommittee) (err error) {
	defer func() {
		if config.IsLogOn(config.DataDebugLog) {
			if err != nil {
				log.Errorf("_saveEpochAllCommittee(ChainID:%d, Epoch:%d, %s) with error: %v", id, epoch, eac, err)
			} else {
				log.Debugf("_saveEpochAllCommittee(ChainID:%d, Epoch:%d, %s)", id, epoch, eac)
			}
		}
	}()
	var bs []byte
	if bs, err = rtl.Marshal(eac); err != nil {
		return err
	} else {
		key := models.ToEpochCommKey(id, epoch)
		return dbase.Put(key, bs)
	}
}

func RemoveEpochAllComm(dbase db.Writer, id common.ChainID, epoch common.EpochNum) error {
	key := models.ToEpochCommKey(id, epoch)
	if err := dbase.Delete(key); err != nil {
		log.Errorf("remove EpochAllComm at ChainID:%d Epoch:%d failed: %v", id, epoch, err)
		return err
	} else {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("EpochAllComm at ChainID:%d Epoch:%d removed (if exists)", id, epoch)
		}
	}
	return nil
}

func LoadEpochCommittee(dbase db.Database, chainId common.ChainID, epoch common.EpochNum) (
	eac *models.EpochAllCommittee, errr error) {
	var bs []byte
	defer func() {
		if config.IsLogOn(config.DataDebugLog) {
			if errr != nil {
				log.Errorf("LoadEpochCommittee(ChainID:%d, Epoch:%d) (bytes:%d) with error: %v",
					chainId, epoch, len(bs), errr)
			} else {
				log.Debugf("LoadEpochCommittee(ChainID:%d, Epooh:%d) (bytes:%d): %s",
					chainId, epoch, len(bs), eac)
			}
		}
	}()

	var err error
	bs, err = dbase.Get(models.ToEpochCommKey(chainId, epoch))
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		// to be compatible with old data
		comm, err := GetChainCommittee(dbase, chainId, epoch)
		if err != nil {
			return nil, err
		}
		if comm == nil {
			return nil, nil
		}
		return models.NewEpochAllComm(comm, nil), nil
	}
	eac = new(models.EpochAllCommittee)
	if err = rtl.Unmarshal(bs, eac); err != nil {
		return nil, err
	}
	return eac, nil
}

func SaveCommitteeIndex(dbase db.Database, epoch common.EpochNum, index *models.CommitteeIndex) error {
	if index == nil {
		return errors.New("nil CommitteeIndex")
	}
	bs, err := rtl.Marshal(index)
	if err != nil {
		return fmt.Errorf("marshal CommitteeIndex at Epoch:%d failed: %v", epoch, err)
	}
	key := models.ToEpochCommIndexKey(epoch)
	return dbase.Put(key, bs)
}

func LoadCommitteeIndex(dbase db.Database, epoch common.EpochNum) (*models.CommitteeIndex, error) {
	key := models.ToEpochCommIndexKey(epoch)
	bs, err := dbase.Get(key)
	if err != nil {
		return nil, fmt.Errorf("load CommitteeIndex of Epoch:%d failed:%v", epoch, err)
	}
	if len(bs) == 0 {
		return nil, nil
	}
	index := new(models.CommitteeIndex)
	if err = rtl.Unmarshal(bs, index); err != nil {
		return nil, fmt.Errorf("unmarshal CommitteeIndex of Epoch:%d failed:%v", epoch, err)
	}
	return index, nil
}

func SaveUnverifiedBlock(dbase db.Database, height common.Height, block *models.BlockEMessage) error {
	if block == nil {
		return common.ErrNil
	}
	key := models.ToBlockNotVerified(height)
	data, err := rtl.Marshal(block)
	if err != nil {
		return err
	}
	return dbase.Put(key, data)
}

func LoadUnverifiedBlock(dbase db.Database, height common.Height) (*models.BlockEMessage, error) {
	key := models.ToBlockNotVerified(height)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if err = rtl.Unmarshal(data, block); err != nil {
		return nil, err
	}
	return block, nil
}

func StoreStorageEntries(dbase db.Database, root common.Hash, num int, entries []models.EntryHashHash) error {
	key := models.ToStorageEntryKey(root.Bytes(), num)
	data, err := rtl.Marshal(entries)
	if err != nil {
		return err
	}
	return dbase.Put(key, data)
}

func LoadStorageEntries(dbase db.Database, root common.Hash, num int) ([]models.EntryHashHash, error) {
	key := models.ToStorageEntryKey(root.Bytes(), num)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	var ret []models.EntryHashHash
	if err = rtl.Unmarshal(data, &ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func RemoveStorageEntries(dbase db.Database, root common.Hash, num int) error {
	key := models.ToStorageEntryKey(root.Bytes(), num)
	return dbase.Delete(key)
}

// ReadReceipts retrieves all the transaction receipts belonging to a block.
func ReadReceipts(dbase db.Database, hash common.Hash) models.Receipts {

	// Retrieve the flattened receipt slice
	data, _ := dbase.Get(models.ToBlockReceiptsKey(hash[:]))
	if len(data) == 0 {
		return nil
	}
	// Convert the revceipts from their storage form to their internal representation
	dataBuf := bytes.NewBuffer(data)
	receipts := make([]*models.Receipt, 0)
	if err := rtl.Decode(dataBuf, &receipts); err != nil {
		log.Error("Invalid receipt array", "hash", hash, "err", err)
		return nil
	}
	//
	// if len(receipts) > 0 {
	// 	log.Warnf("read receipts %v: %x", receipts, data)
	// }
	return receipts
}

// WriteReceipts stores all the transaction receipts belonging to a block.
func WriteReceipts(dbase db.Database, header *models.BlockHeader, receipts models.Receipts) ([]byte, error) {
	if len(receipts) == 0 {
		return nil, nil
	}
	dataBuf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(dataBuf)
	dataBuf.Reset()

	err := rtl.Encode(receipts, dataBuf)
	if err != nil {
		log.Error("Failed to encode block receipts", "err", err)
		return nil, err
	}
	bs := dataBuf.Bytes()
	var receiptsHash []byte

	if header != nil && header.Version == models.BlockVersionV0 {
		receiptsHash, err = common.Hash256s(bs)
	} else {
		receiptsHash, err = receipts.HashValue()
	}
	if err != nil {
		return nil, err
	}
	// if len(receipts) > 0 {
	// 	log.Warnf("Write Receipts %s: %x", receipts, bs)
	// }
	// Store the flattened receipt slice
	if err := dbase.Put(models.ToBlockReceiptsKey(receiptsHash), bs); err != nil {
		log.Error("Failed to store block receipts", "err", err)
		return nil, err
	}
	return receiptsHash, nil
}

func WriteRRActReceipts(dbase db.Database, receipts models.RRActReceipts) ([]byte, error) {
	if receipts == nil || len(receipts) == 0 {
		return nil, nil
	}
	// save receipts
	root, err := common.HashObject(receipts)
	if err != nil {
		return nil, err
	}
	bs, err := rtl.Marshal(receipts)
	if err != nil {
		return nil, err
	}
	if err = dbase.Put(models.ToRRActReceiptsKey(root), bs); err != nil {
		return nil, err
	}

	// save indexes of receipts
	_, err = db.BatchWrite(dbase, 100, len(receipts), func(j int, w db.Writer) (ok bool, err error) {
		if receipts[j] == nil {
			return false, nil
		}
		index := models.NewRRActReceiptIndex(root, uint32(j))
		key := models.ToRRActRptIndexKey(receipts[j].TxHash[:])
		data, err := rtl.Marshal(index)
		if err != nil {
			return false, err
		}
		if err = w.Put(key, data); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return root, nil
}

func ReadRRActReceipts(dbase db.Database, rootOfReceipts []byte) (models.RRActReceipts, error) {
	key := models.ToRRActReceiptsKey(rootOfReceipts)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	rpts := make(models.RRActReceipts, 0)
	err = rtl.Unmarshal(data, &rpts)
	if err != nil {
		return nil, err
	}
	return rpts, nil
}

func ReadRRActReceiptIndex(dbase db.Database, txHash []byte) (*models.RRReceiptIndex, error) {
	key := models.ToRRActRptIndexKey(txHash)
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	actIndex := new(models.RRReceiptIndex)
	err = rtl.Unmarshal(data, actIndex)
	if err != nil {
		return nil, err
	}
	return actIndex, nil
}

func ReadRRActReceipt(dbase db.Database, txHash []byte) (*models.RRActReceipt, error) {
	index, err := ReadRRActReceiptIndex(dbase, txHash)
	if err != nil {
		return nil, err
	}
	if index == nil {
		return nil, nil
	}
	rpts, err := ReadRRActReceipts(dbase, index.RootOfReceipts[:])
	if err != nil {
		return nil, fmt.Errorf("read RRActReceipts failed: %v", err)
	}
	if int(index.Index) >= len(rpts) {
		return nil, nil
	}
	return rpts[index.Index], nil
}

// var KPVersionInfo = []byte("vi")

func StoreVersionInfo(dbase db.Database, versionInfo *config.VersionData) error {
	key := models.KPVersionInfo
	if value, err := rtl.Marshal(versionInfo); err != nil {
		return err
	} else {
		return dbase.Put(key, value)
	}
}

func LoadVersionInfo(dbase db.Database) (*config.VersionData, error) {
	key := models.KPVersionInfo
	value, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	ret := new(config.VersionData)
	err = rtl.Unmarshal(value, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func SaveAuditorMsgs(dbase db.Database, id common.ChainID, height common.Height, sigs models.AuditorMsgsForDBs) error {
	if len(sigs) == 0 {
		return nil
	}
	key := db.PrefixKey2(models.KPAuditorMsgs, id.Bytes(), height.Bytes())
	bs, err := rtl.Marshal(sigs)
	if err != nil {
		return err
	}
	return dbase.Put(key, bs)
}

func LoadAuditorMsgs(dbase db.Database, id common.ChainID, height common.Height) (models.AuditorMsgsForDBs, error) {
	key := db.PrefixKey2(models.KPAuditorMsgs, id.Bytes(), height.Bytes())
	bs, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, nil
	}
	m := make(models.AuditorMsgsForDBs, 0)
	err = rtl.Unmarshal(bs, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// var KPConfirmBlock = []byte("cb")

func SaveConfirmBlock(dbase db.Database, block *models.BlockEMessage) error {
	key := db.PrefixKey(models.KPConfirmBlock, block.GetChainID().Bytes())
	val, err := rtl.Marshal(block)
	if err != nil {
		return err
	}
	return dbase.Put(key, val)
}

func LoadConfirmBlock(dbase db.Database, chainId common.ChainID) (*models.BlockEMessage, error) {
	key := db.PrefixKey(models.KPConfirmBlock, chainId.Bytes())
	value, err := dbase.Get(key)
	if err != nil || len(value) == 0 {
		return nil, err
	}
	block := new(models.BlockEMessage)
	if err = rtl.Unmarshal(value, block); err != nil {
		return nil, err
	}
	return block, nil
}

// var KPWorkingChains = []byte("wc")

func StoreWorkingChains(dbase db.Database, chains map[common.ChainID]bool) error {
	key := models.KPWorkingChains
	val, err := rtl.Marshal(chains)
	if err != nil {
		return err
	}
	return dbase.Put(key, val)
}

func LoadWorkingChains(dbase db.Database) (map[common.ChainID]bool, error) {
	key := models.KPWorkingChains
	val, err := dbase.Get(key)
	if err != nil || len(val) == 0 {
		return nil, err
	}
	chains := make(map[common.ChainID]bool)
	if err = rtl.Unmarshal(val, &chains); err != nil {
		return nil, err
	}
	return chains, nil
}

// // RRProofs for current node, (prefix + RRRoot + NodeID[:5]) -> RRProofs
// var KPRRProofs = []byte("rk")

func StoreRRProofs(dbase db.Database, rrRoot []byte, rrproofs *models.RRProofs) error {
	bs, err := rtl.Marshal(rrproofs)
	if err != nil {
		return err
	}
	key := db.PrefixKey2(models.KPRRProofs, rrRoot, common.SystemNodeID[:5])
	err = dbase.Put(key, bs)
	if err != nil {
		return err
	}
	if config.IsLogOn(config.DataDebugLog) {
		log.Debugf("[RRProofs] of RRRoot:%x %s stored", common.ForPrint(rrRoot), rrproofs.PrintString())
	}
	return nil
}

func LoadRRProofs(dbase db.Database, rrRoot []byte) (*models.RRProofs, error) {
	key := db.PrefixKey2(models.KPRRProofs, rrRoot, common.SystemNodeID[:5])
	bs, err := dbase.Get(key)
	if err != nil || bs == nil {
		return nil, err
	}
	rps := new(models.RRProofs)
	if err = rtl.Unmarshal(bs, rps); err != nil {
		return nil, err
	}
	return rps, nil
}

var chainInfosKey = []byte("cik")

func SaveChainInfos(dbase db.Database, chainSlice []*common.ChainInfos) error {
	chainsStream, err := rtl.Marshal(chainSlice)
	if err != nil {
		return err
	}
	return dbase.Put(chainInfosKey, chainsStream)
}

func LoadChainInfos(dbase db.Database) ([]*common.ChainInfos, error) {
	chainsStream, err := dbase.Get(chainInfosKey)
	if err != nil {
		return nil, err
	}
	var chainInfos []*common.ChainInfos
	if err = rtl.Unmarshal(chainsStream, &chainInfos); err != nil {
		return nil, err
	}
	return chainInfos, nil
}

var KPHistoryData = []byte("hdt")

func SaveHistoryData(dbase db.Database, root []byte, historyBytes []byte) error {
	key := db.PrefixKey(KPHistoryData, root)
	return dbase.Put(key, historyBytes)
}

func LoadHistoryData(dbase db.Database, root []byte) ([]byte, error) {
	key := db.PrefixKey(KPHistoryData, root)
	return dbase.Get(key)
}

var KPRRData = []byte("rrd")

func SaveRRData(dbase db.Database, era *common.EraNum, data []byte) error {
	key := db.PrefixKey(KPRRData, era.Bytes())
	return dbase.Put(key, data)
}

func LoadRRData(dbase db.Database, era *common.EraNum) ([]byte, error) {
	key := db.PrefixKey(KPRRData, era.Bytes())
	return dbase.Get(key)
}

var KPPreElects = []byte("pel")

func SavePreElects(dbase db.Database, height common.Height, data []byte) error {
	key := db.PrefixKey(KPPreElects, height.Bytes())
	return dbase.Put(key, data)
}

func LoadPreElects(dbase db.Database, height common.Height) ([]byte, error) {
	key := db.PrefixKey(KPPreElects, height.Bytes())
	return dbase.Get(key)
}

var KPChainCommittees = []byte("cct")

func SaveChainCommittees(dbase db.Database, height common.Height, data []byte) error {
	key := db.PrefixKey(KPChainCommittees, height.Bytes())
	return dbase.Put(key, data)
}

func LoadChainCommittees(dbase db.Database, height common.Height) ([]byte, error) {
	key := db.PrefixKey(KPChainCommittees, height.Bytes())
	return dbase.Get(key)
}

var KeyDBCreateHeight = []byte("dch")

func SaveDBCreateHeight(dbase db.Database, height common.Height) error {
	return dbase.Put(KeyDBCreateHeight, height.Bytes())
}

func LoadDBCreateHeight(dbase db.Database) (common.Height, error) {
	hb, err := dbase.Get(KeyDBCreateHeight)
	if err != nil {
		return common.NilHeight, err
	}
	h := common.BytesToHeight(hb)
	return h, nil
}

var KeyDBGenerating = []byte("dbg")

func SetDBGenerating(dbase db.Database) error {
	return dbase.Put(KeyDBGenerating, KeyDBGenerating)
}

func RemoveDBGenerating(dbase db.Database) error {
	return dbase.Delete(KeyDBGenerating)
}

func CheckDBInGenerating(dbase db.Database) bool {
	r, _ := dbase.Has(KeyDBGenerating)
	return r
}
