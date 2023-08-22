package config

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

var (
	SystemAuditorPrivate cipher.ECCPrivateKey
	SystemAuditorChainID map[common.ChainID]struct{}
)

type AuditorConf struct {
	SKString string           `yaml:"sk" json:"sk"`
	ChainIDs []common.ChainID `yaml:"chains" json:"chainid"`
}

func (a *AuditorConf) Validate() error {
	if a == nil {
		return nil
	}
	SystemAuditorPrivate = nil
	SystemAuditorChainID = nil

	var sk cipher.ECCPrivateKey
	var m map[common.ChainID]struct{}
	if len(a.SKString) > 0 {
		skbytes, err := hex.DecodeString(a.SKString)
		if err != nil {
			return fmt.Errorf("decode auditor private key failed: %v", err)
		}
		sk, err = cipher.RealCipher.BytesToPriv(skbytes)
		if err != nil {
			return fmt.Errorf("parse auditor private key failed: %v", err)
		}
		if len(a.ChainIDs) > 0 {
			m = make(map[common.ChainID]struct{})
			for _, cid := range a.ChainIDs {
				if cid.IsNil() == false {
					m[cid] = struct{}{}
				}
			}
		}

		if sk != nil && len(m) > 0 {
			SystemAuditorPrivate = sk
			SystemAuditorChainID = m
			log.Infof("[CONFIG] auditor config as SK:%x at ChainID:%v", SystemAuditorPrivate.ToBytes(), SystemAuditorChainID)
			return nil
		}
	}

	return errors.New("no auditor set")
}

func IsAuditorOf(chainid common.ChainID) (cipher.ECCPrivateKey, bool) {
	if SystemAuditorPrivate == nil || SystemAuditorChainID == nil || chainid.IsNil() {
		return nil, false
	}
	if _, exist := SystemAuditorChainID[chainid]; exist {
		return SystemAuditorPrivate, true
	}
	return nil, false
}
