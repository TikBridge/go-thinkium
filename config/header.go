package config

import (
	"encoding/hex"
	"errors"

	"github.com/ThinkiumGroup/go-common"
)

type GenesisRootInfos []*GenesisRootInfo

type GenesisRootInfo struct {
	ChainID           common.ChainID `yaml:"chainId" json:"chainId"`
	StateRoot         string         `yaml:"stateRoot"` // load stateRoot from config
	StateRootHash     *common.Hash   `yaml:"-"`
	ChainInfoRoot     string         `yaml:"chaininfoRoot"`
	ChainInfoRootHash *common.Hash   `yaml:"-"`
	RRRoot            string         `yaml:"rrRoot"`
	RRNextRoot        string         `yaml:"rrNextRoot"`
	RRChangingRoot    string         `yaml:"rrChangingRoot"`
}

type GenesisRRInfo struct {
	RRRootHash         *common.Hash
	RRNextRootHash     *common.Hash
	RRChangIngRootHash *common.Hash
}

func (s GenesisRootInfos) validate() error {
	for index, item := range s {
		h, err := hex.DecodeString(item.StateRoot)
		if err != nil {
			return err
		}
		if item.ChainInfoRoot != "" {
			if item.ChainID != common.MainChainID {
				return errors.New("[CONFIG] only main chain can set chaininforoot")
			}
			ChainInfoRoot, err := hex.DecodeString(item.ChainInfoRoot)
			if err != nil {
				return err
			}
			item.ChainInfoRootHash = common.BytesToHashP(ChainInfoRoot)
		}
		s[index].StateRootHash = common.BytesToHashP(h)
	}

	return nil
}

func (s GenesisRootInfos) GetGenesisRRInfo(id common.ChainID) (rrinfo *GenesisRRInfo) {
	rrinfo = new(GenesisRRInfo)
	for _, item := range s {
		if item.ChainID != id {
			continue
		}
		if item.RRRoot != "" {
			rrRootHash, err := hex.DecodeString(item.RRRoot)
			if err != nil {
				panic("[CONFIG] config a invalid rrRoothash" + err.Error())
			}
			rrinfo.RRRootHash = common.BytesToHashP(rrRootHash)
		}
		if item.RRNextRoot != "" {
			rrNextRootHash, err := hex.DecodeString(item.RRNextRoot)
			if err != nil {
				panic("[CONFIG] config a invalid rrNextRoothash" + err.Error())
			}
			rrinfo.RRNextRootHash = common.BytesToHashP(rrNextRootHash)
		}
		if item.RRChangingRoot != "" {
			rrChangingRootHash, err := hex.DecodeString(item.RRChangingRoot)
			if err != nil {
				panic("[CONFIG] config a invalid rrChangingRoothash" + err.Error())
			}
			rrinfo.RRChangIngRootHash = common.BytesToHashP(rrChangingRootHash)
		}
		return rrinfo
	}
	return
}

func (s GenesisRootInfos) GetStateRootHash(id common.ChainID) *common.Hash {
	for _, item := range s {
		if item.ChainID == id {
			return item.StateRootHash
		}
	}
	return nil
}

func (s GenesisRootInfos) GetChainInfoRootHash() *common.Hash {
	for _, item := range s {
		if item.ChainID == common.MainChainID && item.ChainInfoRoot != "" {
			chaininforoot, err := hex.DecodeString(item.ChainInfoRoot)
			if err == nil {
				return common.BytesToHashP(chaininforoot)
			}
		}
	}
	return nil
}

func (s GenesisRootInfos) IsNil() bool {
	if len(s) == 0 {
		return true
	}
	return false
}

func (s GenesisRootInfos) Include(cid common.ChainID) bool {
	if !s.IsNil() {
		for _, item := range s {
			if item.ChainID == cid {
				return true
			}
		}
	}
	return false
}
