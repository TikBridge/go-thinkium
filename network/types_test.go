package network

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

func TestWriteAndReadP2PMsg(t *testing.T) {
	msg0 := models.TextEMessage{
		Body: "begins",
	}
	typ, body, err := models.MarshalEvent(msg0)
	if err != nil {
		t.Error("should marshal successfully")
	}

	msg1 := models.ToOneEMessage{
		Type: typ,
		Body: body,
	}

	t0, p2pmsg0, err0 := WriteP2PMsg(msg0, false)
	t1, p2pmsg1, err1 := WriteP2PMsg(msg1, false)
	if err0 != nil || err1 != nil || t0 != models.TextEvent || t1 != models.ToOneEvent {
		t.Error("message type don't match")
	}

	t00, msg00, err00 := ReadP2PMsg(p2pmsg0)
	t11, msg11, err11 := ReadP2PMsg(p2pmsg1)

	if err00 != nil || err11 != nil || t00 != models.TextEvent || t11 != models.ToOneEvent {
		t.Error("read error!")
	}
	if a, ok := msg00.(*models.TextEMessage); !ok || a.Body != msg0.Body {
		fmt.Println(ok, a.Body)
		t.Error("read wrong message0")
	}
	if a, ok := msg11.(*models.ToOneEMessage); !ok || !bytes.Equal(a.Body, body) {
		t.Error("read wrong message1")
		if mm, err := models.UnmarshalEvent(a.Type, a.Body); err == nil {
			if mmm, _ := mm.(models.TextEMessage); mmm.Body != msg0.Body {
				t.Error("unmarshal error!")
			}

		} else {
			log.Error("unmarshal error!")
		}
	}
}

/*
func TestRecentMsgPool(t *testing.T) {

	RM := RecentMsgPool{}
	msg0 := "dark"
	msg1 := "knight"

	// insert two messages
	h0, err0 := RM.Put(msg0)
	if err0 != nil {
		t.Error("can't insert")
	}
	time.Sleep(MaxWaitingDuration / 2)
	h1, err1 := RM.Put(msg1)
	if err1 != nil {
		t.Error("can't insert")
	}

	// get first message
	if m, ok := RM.Get(h0); !ok || msg0 != m {
		t.Error("error to get")
	}

	time.Sleep(MaxWaitingDuration/2 + time.Second)

	// msg0 should have been deleted
	if _, ok := RM.Get(h0); ok {
		t.Error("should have deleted")
	}

	// msg1 still exists
	if m, ok := RM.Get(h1); !ok || msg1 != m {
		t.Error("error to get")
	}

	time.Sleep(MaxWaitingDuration)

	// msg2 should have been deleted
	if _, ok := RM.Get(h1); ok {
		t.Error("should have deleted")
	}
}
*/

// func TestRecentPool(t *testing.T) {
// 	pool := &RecentPool{
// 		hashToMsg:   make(map[common.Hash][]byte),
// 		hashToNodes: make(map[common.Hash]map[common.NodeID]struct{}),
// 	}
//
// 	payLoad := make([]byte, 200)
// 	io.ReadFull(rand.Reader, payLoad)
// 	h, _ := common.Hash256WithError(payLoad)
// 	nids := make([]common.NodeID, 100)
// 	for i := 0; i < len(nids); i++ {
// 		nids[i].Generate()
// 	}
// 	t.Logf("Generated: nids: %v, payload.Hash: %x", nids, h[:5])
//
// 	var wg sync.WaitGroup
// 	wg.Add(len(nids))
// 	for i := 0; i < len(nids); i++ {
// 		go func(i int) {
// 			added := pool.Add(h, &(nids[i]), payLoad)
// 			alreadyHas := added == false
// 			fmt.Printf("%x alreadyHas: %t\n", nids[i][:5], alreadyHas)
// 			wg.Done()
// 		}(i)
// 	}
// 	wg.Wait()
// }
