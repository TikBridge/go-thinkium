package dao

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/stephenfire/go-rtl"
)

func SaveRRRootIndex(dbase db.Database, era common.EraNum, root []byte) (err error) {
	defer func() {
		log.Debugf("SaveRRRootIndex(%d, %x) with error:%v", era, root, err)
	}()
	key := models.ToRRKey(era)
	return dbase.Put(key, root)
}

func GetRRRootIndex(dbase db.Database, era common.EraNum) (root []byte, err error) {
	defer func() {
		log.Debugf("GetRRRootIndex(%d)=(root:%x, error:%v)", era, root, err)
	}()
	key := models.ToRRKey(era)
	return dbase.Get(key)
}

func SaveRRActRptIndex(dbase db.Database, rractRpts models.RRActReceipts, height common.Height, hashOfBlock common.Hash) (count int, err error) {
	if len(rractRpts) == 0 {
		return
	}
	return db.BatchWrite(dbase, 100, len(rractRpts), func(j int, w db.Writer) (ok bool, err error) {
		if rractRpts[j] == nil {
			return false, nil
		}
		rptIndex := models.NewTXIndex(uint64(height), hashOfBlock, uint32(j))
		key := models.ToRRActRptIndexKey(rractRpts[j].TxHash[:])
		data, err := rtl.Marshal(rptIndex)
		if err != nil {
			return false, err
		}
		if err = w.Put(key, data); err != nil {
			log.Errorf("SaveRRActRptIndex(%x, %s) failed: %v", rractRpts[j].TxHash[:], rptIndex, err)
			return false, err
		}
		return true, nil
	})
}

func GetRRActRptIndx(dbase db.Database, txHash common.Hash) (*models.TXIndex, error) {
	key := models.ToRRActRptIndexKey(txHash[:])
	data, err := dbase.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	txIndex := models.NewTXIndex(uint64(0), common.NilHash, uint32(0))

	err = rtl.Unmarshal(data, txIndex)
	if err != nil {
		return nil, err
	}
	return txIndex, err
}
