package network

import (
	"fmt"
	"time"
)

const MsgTypeLength int = 2

type MsgType [MsgTypeLength]byte

var (
	HandProofMsgType MsgType = [MsgTypeLength]byte{0, 0}
	PingMsgType      MsgType = [MsgTypeLength]byte{0, 1}
	PongMsgType      MsgType = [MsgTypeLength]byte{0, 2}
	DiscMsgType      MsgType = [MsgTypeLength]byte{0, 3}
	UnknownMsgType   MsgType = [MsgTypeLength]byte{0, 254}
	EventMsgType     MsgType = [MsgTypeLength]byte{0, 255}

	PingMsg = &Msg{
		MsgType: PingMsgType,
		Payload: []byte{1},
	}
	PongMsg = &Msg{
		MsgType: PongMsgType,
		Payload: []byte{2},
	}
	DiscMsg = &Msg{
		MsgType: DiscMsgType,
		Payload: []byte{3},
	}
)

func (t *MsgType) Bytes() [MsgTypeLength]byte {
	return *t
}

func toMsgType(bytes []byte) MsgType {
	if len(bytes) < MsgTypeLength {
		return UnknownMsgType
	}
	var b [MsgTypeLength]byte
	copy(b[:MsgTypeLength], bytes[:MsgTypeLength])
	return b
}

type Msg struct {
	MsgType    MsgType
	Payload    []byte
	ReceivedAt time.Time
}

// // Discard reads any remaining payload data into a black hole.
// func (msg *Msg) Discard() error {
// 	_, err := io.Copy(ioutil.Discard, bytes.NewReader(msg.Payload))
// 	return err
// }

func (msg *Msg) LoadSize() int {
	return len(msg.Payload)
}

func (msg *Msg) Summary() string {
	if msg == nil {
		return "Msg<nil>"
	}
	return fmt.Sprintf("Msg{}")
}

func (msg *Msg) String() string {
	if msg == nil {
		return "Msg<nil>"
	}
	return fmt.Sprintf("Msg{Type:%x Payload:%x ReceivedAt:%s}", msg.MsgType, msg.Payload, msg.ReceivedAt)
}
