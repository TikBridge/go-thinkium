package models

import (
	"fmt"
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

func TestEpochAllCommittee(t *testing.T) {
	resultComm := _randomComm(1)
	realComm := _randomComm(5)
	restartedComm := _randomComm(4)
	eac := &EpochAllCommittee{
		Result: resultComm,
		Real:   realComm,
		Restarted: RestartComms{
			&RestartComm{
				Start:         2073,
				ElectedHeight: 3297,
				Comm:          restartedComm,
			},
		},
	}

	checker := func(h common.Height, comms *EpochAllCommittee, shouldbe *Committee) error {
		comm, err := comms.CommAt(h)
		if err != nil {
			return err
		}
		if comm.Compare(shouldbe) != 0 {
			return fmt.Errorf("CommAt:%d should be %s but %s", h, shouldbe, comm)
		}
		return nil
	}
	if err := checker(2073, eac, restartedComm); err != nil {
		t.Fatal(err)
	}
	if err := checker(2099, eac, restartedComm); err != nil {
		t.Fatal(err)
	}
	if err := checker(2072, eac, realComm); err != nil {
		t.Fatal(err)
	}
	if err := checker(2000, eac, realComm); err != nil {
		t.Fatal(err)
	}
	t.Logf("check")
}
