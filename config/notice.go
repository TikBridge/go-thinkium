package config

import (
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

const (
	NoticeDefaultAddr  = "127.0.0.1:6379"
	NoticeDefaultPwd   = ""
	NoticeDefaultDB    = 0
	NoticeDefaultQueue = "QueueOfBlocks"
)

type NoticeConf struct {
	ChainID    *common.ChainID `yaml:"chainid" json:"chainid"`
	QueueSize  int             `yaml:"queueSize" json:"queueSize"`
	RedisAddr  string          `yaml:"addr" json:"addr"`
	RedisPwd   string          `yaml:"pwd" json:"pwd"`
	RedisDB    int             `yaml:"db" json:"db"`
	RedisQueue string          `yaml:"queue" json:"queue"`
}

func (n *NoticeConf) Validate() error {
	if n == nil {
		return nil
	}
	if n.ChainID == nil {
		return errors.New("NoticeConf.chainid must be set")
	} else {
		log.Infof("notice.ChainID:%d", *n.ChainID)
	}
	if n.RedisAddr == "" {
		n.RedisAddr = NoticeDefaultAddr
	}
	if n.RedisDB < 0 {
		n.RedisDB = NoticeDefaultDB
	}
	if n.RedisQueue == "" {
		n.RedisQueue = NoticeDefaultQueue
	}
	return nil
}

func (n *NoticeConf) String() string {
	if n == nil {
		return "NoticeConf<nil>"
	}
	if n.ChainID != nil {
		return fmt.Sprintf("NoticeConf{ChainID:%d QueueSize:%d Addr:%s Pwd:%s DB:%d Queue:%s}",
			*n.ChainID, n.QueueSize, n.RedisAddr, n.RedisPwd, n.RedisDB, n.RedisQueue)
	} else {
		return fmt.Sprintf("NoticeConf{ChainID:<nil> QueueSize:%d Addr:%s Pwd:%s DB:%d Queue:%s}",
			n.QueueSize, n.RedisAddr, n.RedisPwd, n.RedisDB, n.RedisQueue)
	}
}
