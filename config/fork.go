package config

import "github.com/ThinkiumGroup/go-common"

type ModelVers struct {
	tx            uint16
	block         uint16
	rewardReq     uint16
	rrInfo        uint16
	rrAct         uint16
	summary       uint16
	syncedNotify  uint64
	chainInfo     uint16
	posInfo       uint16
	network       uint64 // TcpHandShaker/ping/pong/findnode/neighbors/pingSort/pongSort/findnodeSort/neighberSort
	tcpHandShaker uint64
}

type Fork struct {
	at        common.Height
	name      string
	version   common.Version
	modelVers ModelVers
}
