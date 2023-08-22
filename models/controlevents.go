package models

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

// Control class message, carefully forward on the network. The message body is not guaranteed
// to be serializable or deserialized.
// Because of the single execution, there is no need to check the repetition
type (
	RelayType byte

	// RelayEvent Used to forward messages to other networks asynchronously
	RelayEventMsg struct {
		RType     RelayType
		FromChain common.ChainID
		ToChainID common.ChainID
		ToNetType common.NetType
		ToNodeID  *common.NodeID
		Msg       interface{}
		Pub       []byte
		Sig       []byte
	}

	// The system found a chain that did not exist
	MissingChainEventMsg struct {
		ID common.ChainID
	}

	// Unknown error found
	SevereErrorEventMsg struct {
		ChainID common.ChainID
		Err     error
	}
)

var (
	controlEventMap = map[EventType]struct{}{
		RelayEvent:              {},
		StopEvent:               {},
		PreelectionStartEvent:   {},
		PreelectionPrepareEvent: {},
		PreelectionConnectEvent: {},
		PreelectionExamineEvent: {},
		PreelectionExitEvent:    {},
		MissingChainEvent:       {},
		SevereErrEvent:          {},
		ChainStoppedEvent:       {},
		ChainRestartingEvent:    {},
		InitChainEvent:          {},
	}
)

func RegisterControlEvent(eventTypes ...EventType) {
	for _, et := range eventTypes {
		controlEventMap[et] = struct{}{}
	}
}

func IsControlEvent(eventType EventType) bool {
	_, ok := controlEventMap[eventType]
	if ok {
		return true
	}
	return false
}

func (t EventType) IsControl() bool {
	return IsControlEvent(t)
}

func (msg *RelayEventMsg) GetPubAndSig() ([]byte, []byte) {
	return msg.Pub, msg.Sig
}

func (msg *RelayEventMsg) String() string {
	et, ok := FindEventTypeByObjectType(reflect.TypeOf(msg.Msg))
	if !ok {
		et = UNSETEVENT
	}
	return fmt.Sprintf("Relay{RType:%d ChainID:%d NetType:%s To:%s Msg:%s Pub:%x Sig:%x}",
		msg.RType, msg.ToChainID, msg.ToNetType, msg.ToNodeID, et, msg.Pub[:], msg.Sig[:])
}

func (msg *MissingChainEventMsg) String() string {
	if msg == nil {
		return "MissChain<nil>"
	}
	return fmt.Sprintf("MissChain{ID:%s}", msg.ID)
}

func (msg *SevereErrorEventMsg) String() string {
	if msg == nil {
		return "SevereErr<nil>"
	}
	return fmt.Sprintf("SevereErr{ChainID:%s Err:%s}", msg.ChainID, msg.Err)
}

const (
	StartMsg = "start"
	StopMsg  = "stop"
)

type StartEMessage struct {
	Timestamp int64
	Signature []byte
}

type StopEMessage struct {
	Timestamp int64
	Signature []byte
}

type SyncedNotify struct {
	NodeId  common.NodeID
	ChainId common.ChainID
	Height  common.Height
	Version uint64
}

func startOrStopTime(timestamp int64) error {
	local := time.Now().Unix()
	delta := int64(0)
	if local < timestamp {
		delta = timestamp - local
	} else {
		delta = local - timestamp
	}
	if delta > 30 {
		// an start message not in [local-30, local+30]
		return fmt.Errorf("invalid timestamp, now:%d timestamp:%d", local, timestamp)
	}
	return nil
}

func startOrStopDigest(act string, timestamp int64) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	return common.SystemHash256([]byte(act), ts)
}

func (m *StartEMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (m *StartEMessage) Verify() error {
	if m == nil || len(m.Signature) != cipher.RealCipher.LengthOfSignature() {
		return errors.New("wrong size property")
	}
	if err := startOrStopTime(m.Timestamp); err != nil {
		return err
	}
	digest := startOrStopDigest(StartMsg, m.Timestamp)
	if !cipher.RealCipher.Verify(config.SystemStarterPK, digest, m.Signature) {
		return errors.New("signature verify failed")
	}
	return nil
}

func (m *StartEMessage) String() string {
	if m == nil {
		return "Start<nil>"
	}
	return fmt.Sprintf("Start{Timestamp:%d Sig:%x}", m.Timestamp, common.ForPrint(m.Signature))
}

func CreateStartMessage() (*StartEMessage, error) {
	if config.SystemStarterPrivate == nil {
		return nil, errors.New("not a starter")
	}
	timestamp := time.Now().Unix()
	digest := startOrStopDigest(StartMsg, timestamp)
	sig, err := cipher.RealCipher.Sign(config.SystemStarterPrivate.ToBytes(), digest)
	if err != nil {
		return nil, fmt.Errorf("sign the digest %x of start message failed: %v", digest, err)
	}
	return &StartEMessage{Timestamp: timestamp, Signature: sig}, nil
}

func (m *StopEMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (m *StopEMessage) Verify() error {
	if m == nil || len(m.Signature) != cipher.RealCipher.LengthOfSignature() {
		return errors.New("wrong size property")
	}
	if err := startOrStopTime(m.Timestamp); err != nil {
		return err
	}
	digest := startOrStopDigest(StopMsg, m.Timestamp)
	if !cipher.RealCipher.Verify(config.SystemStarterPK, digest, m.Signature) {
		return errors.New("signature verify failed")
	}
	return nil
}

func (m *StopEMessage) String() string {
	if m == nil {
		return "Stop<nil>"
	}
	return fmt.Sprintf("Stop{Timestamp:%d Sig:%x)", m.Timestamp, common.ForPrint(m.Signature))
}

func CreateStopMessage() (*StopEMessage, error) {
	if config.SystemStarterPrivate == nil {
		return nil, errors.New("not a starter")
	}
	timestamp := time.Now().Unix()
	digest := startOrStopDigest(StopMsg, timestamp)
	sig, err := cipher.RealCipher.Sign(config.SystemStarterPrivate.ToBytes(), digest)
	if err != nil {
		return nil, fmt.Errorf("sign the digest %x of stop message failed: %v", digest, err)
	}
	return &StopEMessage{Timestamp: timestamp, Signature: sig}, nil
}

func (m *SyncedNotify) GetChainID() common.ChainID {
	return m.ChainId
}

func (m *SyncedNotify) String() string {
	if m == nil {
		return "SyncedNotify<nil>"
	}
	return fmt.Sprintf("SyncedNotify{NodeId:%s ChainId:%d Height:%d Version:%d)", m.NodeId, m.ChainId, m.Height, m.Version)
}

type ChainStoppedMessage struct {
	// the parent chain id of the stopped chain (always main chain)
	ParentID common.ChainID
	// id of the stopped chain
	ChainID common.ChainID
	// the height of the last block confirmed by parent chain of the stopped chain
	LastHeight common.Height
	// the hash of the last block confirmed by parent chain of the stopped chain
	LastHob []byte
	// the block height of the parent chain containing the last confirmed block of the stopped chain
	LastBy common.Height
	// the current block height of the parent chain
	CurrentMain common.Height
}

func (m *ChainStoppedMessage) GetChainID() common.ChainID {
	return m.ChainID
}

func (m *ChainStoppedMessage) String() string {
	if m == nil {
		return "ChainStopped<nil>"
	}
	return fmt.Sprintf("ChainStopped{ID:%d Parent:%s LastHeight:%s LastHob:%x LastBy:%s CurrentMain:%s}",
		m.ChainID, m.ParentID, &(m.LastHeight), common.ForPrint(m.LastHob), &(m.LastBy), &(m.CurrentMain))
}

type ChainRestartingMessage struct {
	ChainID     common.ChainID
	LastHeight  common.Height
	LastHob     []byte
	CurrentMain common.Height
}

func (m *ChainRestartingMessage) GetChainID() common.ChainID {
	return m.ChainID
}

func (m *ChainRestartingMessage) String() string {
	if m == nil {
		return "ChainRestarting<nil>"
	}
	return fmt.Sprintf("ChainRestarting{ID:%d LastHeight:%s LastHob:%x CurrentMain:%s}",
		m.ChainID, &(m.LastHeight), common.ForPrint(m.LastHob), &(m.CurrentMain))
}

type InitialChainMessage struct {
	ChainID common.ChainID
	Op      OperatorType
}

func (m *InitialChainMessage) String() string {
	if m == nil {
		return "InitChain<nil>"
	}
	return fmt.Sprintf("InitChain{ChainID:%d OP:%s}", m.ChainID, m.Op)
}
