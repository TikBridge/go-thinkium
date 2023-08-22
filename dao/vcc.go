package dao

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

func SaveCccTxIndex(dbase db.Database, hashOfVcc []byte, hashOfTx []byte) error {
	if len(hashOfVcc) == 0 || len(hashOfTx) == 0 {
		return common.ErrNil
	}
	key := db.PrefixKey(models.KPCVccTxIndex, hashOfVcc)
	return dbase.Put(key, hashOfTx)
}

func GetCccTxIndex(dbase db.Database, hashOfVcc []byte) (hashOfTx []byte, err error) {
	if len(hashOfVcc) == 0 {
		return nil, common.ErrNil
	}
	key := db.PrefixKey(models.KPCVccTxIndex, hashOfVcc)
	hashOfTx, err = dbase.Get(key)
	return
}
