package models

import "testing"

func TestEventType(t *testing.T) {
	bs := TextEvent.Bytes()
	et := ToEventType(bs)
	if et == TextEvent {
		t.Logf("%s success", TextEvent)
	} else {
		t.Errorf("%s failed", TextEvent)
	}

	et = EventType(65000)
	bs = et.Bytes()
	et1 := ToEventType(bs)
	if et == et1 {
		t.Logf("%s success", et)
	} else {
		t.Errorf("%s failed", et)
	}
}
