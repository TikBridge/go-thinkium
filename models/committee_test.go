package models

import (
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func _randomComm(size int) *Committee {
	if size == 0 {
		return nil
	}
	nids := make([]common.NodeID, 0, size)
	for i := 0; i < size; i++ {
		nid := common.GenerateNodeID()
		nids = append(nids, *nid)
	}
	return &Committee{Members: nids}
}

func TestEpochCommittee(t *testing.T) {
	ec := &EpochCommittee{
		Result: _randomComm(10),
		Real:   _randomComm(4),
	}
	bs, err := rtl.Marshal(ec)
	if err != nil {
		t.Fatal(err)
	}
	eac := new(EpochAllCommittee)
	if err = rtl.Unmarshal(bs, eac); err != nil {
		t.Fatal(err)
	}
	if eac.Real.Equal(ec.Real) == false || eac.Result.Equal(ec.Result) == false || eac.Restarted != nil {
		t.Fatalf("not equal: %s <> %s", ec, eac)
	} else {
		t.Logf("%s -> %s", ec, eac)
	}
}
