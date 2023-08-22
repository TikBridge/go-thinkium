package dao

import (
	"bytes"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/stephenfire/go-rtl"
)

// DeltaFromPool

func SaveDeltaFromPoolMaxHeightLocked(dbase db.Database, fromID common.ChainID, maxHeight common.Height) error {
	maxKey := models.ToDeltaFromMaxHeightKey(fromID)
	maxHeightBytes := maxHeight.Bytes()
	return dbase.Put(maxKey, maxHeightBytes)
}

func LoadDeltaFromPoolMaxHeightLocked(dbase db.Database, fromID common.ChainID) (common.Height, bool) {
	key := models.ToDeltaFromMaxHeightKey(fromID)
	bs, err := dbase.Get(key)
	if err != nil || len(bs) == 0 {
		return 0, false
	}
	return common.BytesToHeight(bs), true
}

//
// func SaveWaterlineLocked(dbase db.Database, fromID common.ChainID, waterline common.Height) error {
// 	key := models.ToDeltaFromWaterlineKey(fromID)
// 	bs := waterline.Bytes()
// 	return dbase.Put(key, bs)
// }

func BatchSaveWaterline(dbase db.Database, linesMap map[common.ChainID]common.Height) error {
	size := 200
	count := 0
	batch := dbase.NewBatch()
	for shardId, line := range linesMap {
		key := models.ToDeltaFromWaterlineKey(shardId)
		bs := line.Bytes()
		if err := batch.Put(key, bs); err != nil {
			return err
		}
		count++
		if count >= size {
			if err := dbase.Batch(batch); err != nil {
				return err
			}
			count = 0
			batch = dbase.NewBatch()
		}
	}
	if count > 0 {
		if err := dbase.Batch(batch); err != nil {
			return err
		}
	}
	return nil
}

func LoadWaterlineLocked(dbase db.Database, fromID common.ChainID) (common.Height, bool) {
	key := models.ToDeltaFromWaterlineKey(fromID)
	bs, err := dbase.Get(key)
	if err != nil || len(bs) == 0 {
		// c.logger.Warnf("load waterline for DeltaFromPool FromID:%d error: %v", fromID, err)
		return 0, false
	}
	return common.BytesToHeight(bs), true
}

func SaveToBeSent(dbase db.Database, toBeSent common.Height) error {
	key := models.ToDeltaToBeSentKey()
	bs := toBeSent.Bytes()
	return dbase.Put(key, bs)
}

func LoadToBeSent(dbase db.Database) (common.Height, bool) {
	key := models.ToDeltaToBeSentKey()
	bs, err := dbase.Get(key)
	if err != nil || len(bs) == 0 {
		return 0, false
	}
	return common.BytesToHeight(bs), true
}

// DeltaFrom

func SaveDeltaFromToDB(dbase db.Database, fromID common.ChainID, height common.Height, deltas []*models.AccountDelta) error {
	key := models.ToDeltaFromKey(fromID, height)
	buf := new(bytes.Buffer)
	if err := rtl.Encode(deltas, buf); err != nil {
		return common.NewDvppError(fmt.Sprintf("encoding DeltaFrom(FromID:%d Height%d) error: ",
			fromID, height), err)
	}
	bs := buf.Bytes()
	if err := dbase.Put(key, bs); err != nil {
		return common.NewDvppError(fmt.Sprintf("save AccountDeltas@(FromID:%d Height:%d) error: ",
			fromID, height), err)
	}
	return nil
}

func GetDeltaFrom(dbase db.Database, fromID common.ChainID, height common.Height) (ok bool,
	deltas []*models.AccountDelta, err error) {
	key := models.ToDeltaFromKey(fromID, height)
	data, err := dbase.Get(key)
	if err != nil {
		return false, nil, common.NewDvppError(fmt.Sprintf("load DeltaFrom(FromID:%d Height:%d) error: ",
			fromID, height), err)
	}
	if data == nil {
		// 当数据库中确实不存在这条记录时
		return false, nil, nil
	}
	deltas = make([]*models.AccountDelta, 0)
	if err = rtl.Unmarshal(data, &deltas); err != nil {
		return false, nil, common.NewDvppError(fmt.Sprintf("decode DeltaFrom(FromID:%d Height:%d Size:%d) error: ",
			fromID, height, len(data)), err)
	}
	return true, deltas, nil
}

// func PreloadDeltaFromLocked(dbase db.Database, fromID common.ChainID, height common.Height) bool {
// 	key := models.ToDeltaFromKey(fromID, height)
// 	data, err := dbase.Get(key)
// 	if err != nil {
// 		return false
// 	}
// 	if data == nil {
// 		// 当数据库中确实不存在这条记录时
// 		return false
// 	}
// 	return true
// }

func LoadDeltaFroms(olddb db.Database, chainid common.ChainID, shardInfo common.ShardInfo) []*models.ShardDeltaMessage {
	var msgs []*models.ShardDeltaMessage
	shardIds := shardInfo.AllIDs()
	for i := 0; i < len(shardIds); i++ {
		if shardIds[i] == shardInfo.LocalID() {
			continue
		}
		waterline, ok := LoadWaterlineLocked(olddb, shardIds[i])
		if !ok {
			log.Errorf("[M] load waterline for ShardID:%d failed", shardIds[i])
			continue
		}
		maxHeight, ok := LoadDeltaFromPoolMaxHeightLocked(olddb, shardIds[i])
		if !ok {
			log.Errorf("[M] load DeltaFromPool maxheight for ShardID:%d failed", shardIds[i])
			continue
		}
		log.Infof("[M] restoring FromID:%d Waterline:%d MaxHeight:%d", shardIds[i], waterline, maxHeight)
		for j := waterline; j <= maxHeight; j++ {
			ok, deltas, err := GetDeltaFrom(olddb, shardIds[i], j)
			if !ok || err != nil {
				log.Errorf("[M] load delta failed at FromID:%d Height:%d, error: %v", shardIds[i], j, err)
			} else {
				msg := &models.ShardDeltaMessage{
					ToChainID:       chainid,
					FromBlockHeader: &models.BlockHeader{ChainID: shardIds[i], Height: j, Version: models.BlockVersion},
					Proof:           nil,
					Deltas:          deltas,
				}
				msgs = append(msgs, msg)
				log.Infof("[M] ShardDeltaMessage %s loaded", msg)
			}
		}
	}
	return msgs
}

func SaveWaterlinesSnapshots(dbase db.Database, how []byte, waterlines models.Waterlines) error {
	key := models.ToDFWaterlineSnapshotKey(how)
	bs, err := rtl.Marshal(waterlines)
	if err != nil {
		return fmt.Errorf("marshal %s error: %v", waterlines, err)
	}
	if err := dbase.Put(key, bs); err != nil {
		return fmt.Errorf("save waterlines %s at %x error: %v", waterlines, how[:5], err)
	}
	return nil
}

func LoadWaterlinesSnapshots(dbase db.Database, how []byte) (models.Waterlines, error) {
	key := models.ToDFWaterlineSnapshotKey(how)
	bytes, err := dbase.Get(key)
	if err != nil {
		return nil, fmt.Errorf("get %x error: %v", key, err)
	}
	waterlines := make(models.Waterlines, 0)
	if err := rtl.Unmarshal(bytes, waterlines); err != nil {
		return nil, fmt.Errorf("unmarshal waterlines error: %v", err)
	}
	return waterlines, nil
}

var KPTmpDeltaFroms = []byte("dfm")

func SaveTmpDeltaFroms(dbase db.Database, froms models.DeltaFroms) error {
	bytes, err := rtl.Marshal(froms)
	if err != nil {
		return err
	}
	return dbase.Put(KPTmpDeltaFroms, bytes)
}

func LoadTmpDeltaFroms(dbase db.Database) (models.DeltaFroms, error) {
	bytes, err := dbase.Get(KPTmpDeltaFroms)
	if err != nil {
		return nil, err
	}
	var froms models.DeltaFroms
	err = rtl.Unmarshal(bytes, &froms)
	return froms, err
}
