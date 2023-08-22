package models

import (
	"sync"
	"time"

	"github.com/ThinkiumGroup/go-common"
)

const (
	None           = 0
	SendingSyncReq = 1
)

type TimerLock struct {
	flag     int
	targetId *common.NodeID
	timer    *time.Timer
	lock     sync.RWMutex
}

func (l *TimerLock) CASStart(expect, to int, targetId *common.NodeID, timeout time.Duration) bool {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.flag != expect {
		return false
	}
	if l.timer != nil {
		panic("timer is not empty")
	}
	l.flag = to
	l.targetId = targetId.Clone()
	l.timer = time.AfterFunc(timeout, func() {
		l.timer = nil
		if l.flag == to {
			l.flag = expect
			l.targetId = nil
		}
	})
	return true
}

func (l *TimerLock) CASReset(expect, to int) bool {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.flag == expect {
		if l.timer != nil {
			l.timer.Stop()
			l.timer = nil
		}
		l.flag = to
		l.targetId = nil
		return true
	}
	return false
}

func (l *TimerLock) Get() (*common.NodeID, int) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return l.targetId, l.flag
}
