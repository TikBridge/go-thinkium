package models

import (
	"testing"
	"time"
)

func TestTimerLock(t *testing.T) {
	locker := new(TimerLock)
	d := 2 * time.Second
	ok := locker.CASStart(0, 1, nil, d)
	if !ok {
		t.Fatal("start timer locker failed")
	}
	t.Log("start timer locker with timeout:", d)
	if _, v := locker.Get(); v != 1 {
		t.Fatal("timer value is", v, "but expecting 1")
	} else {
		t.Log("timer valie is", v)
	}
	if locker.timer == nil {
		t.Fatal("no timer found in locker")
	}
	w := d + 1*time.Second
	t.Log("waiting...", w)
	time.Sleep(w)
	if _, v := locker.Get(); v != 0 {
		t.Fatal("timer value is", v, "but expecting 0")
	} else {
		t.Log("timer valie is", v)
	}
	if locker.timer != nil {
		t.Fatal("timer still in locker")
	} else {
		t.Log("timer cleared")
	}
}

func TestTimerLock_CASReset(t *testing.T) {
	locker := new(TimerLock)
	d := 2 * time.Second
	ok := locker.CASStart(0, 1, nil, d)
	if !ok {
		t.Fatal("start timer locker failed")
	}
	t.Log("start timer locker with timeout:", d)
	if _, v := locker.Get(); v != 1 {
		t.Fatal("timer value is", v, "but expecting 1")
	} else {
		t.Log("timer valie is", v)
	}
	if locker.timer == nil {
		t.Fatal("no timer found in locker")
	}
	w := 1 * time.Second
	t.Log("waiting...", w)
	time.Sleep(w)
	if locker.timer == nil {
		t.Fatal("no timer found in locker")
	}
	if !locker.CASReset(1, 0) {
		t.Fatal("timer reset failed")
	} else {
		t.Log("timer reset to 0")
	}
	if _, v := locker.Get(); v != 0 {
		t.Fatal("timer value is", v, "but expecting 0")
	} else {
		t.Log("timer valie is", v)
	}
	if locker.timer != nil {
		t.Fatal("timer still in locker")
	} else {
		t.Log("timer cleared")
	}
}
