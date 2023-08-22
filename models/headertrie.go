package models

import (
	"io"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
)

func HashSliceValueEncoder(o interface{}, w io.Writer) error {
	h, ok := o.([]byte)
	if !ok {
		return nil
	}
	_, err := w.Write(h[:])
	return err
}

func HashSliceValueDecoder(r io.Reader) (o interface{}, err error) {
	h := make([]byte, common.HashLength)
	_, err = io.ReadFull(r, h)
	// _, err = r.Read(h)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// Only hash is reserved. The data of CashCheck is provided by the client, so the value itself is the hash value
func HashSliceValueHasher(value interface{}, valueBytes []byte) (hashBytes []byte, err error) {
	if len(valueBytes) != common.HashLength {
		log.Errorf("%x length != HashLength", valueBytes)
		return nil, common.ErrLength
	}
	return valueBytes, nil
}

// It's just a hash value, and the hash value is key, so you don't need to save it
func HashSliceValueExpander(hashBytes []byte, adpater db.DataAdapter) (valueBytes []byte, err error) {
	return hashBytes, nil
}
