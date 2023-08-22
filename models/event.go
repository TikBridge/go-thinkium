package models

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

type (
	EventType uint16

	Sourcer interface {
		Source() common.NodeID
	}

	HashSourcer interface {
		Source() common.NodeID
		Shipping() common.Hash
	}

	Equaler interface {
		Equals(interface{}) bool
	}
)

func (t EventType) String() string {
	if v, ok := eventDict.GetName(t); ok {
		return v
	}
	return "EventType" + strconv.Itoa(int(t))
}

func (t EventType) Bytes() (b []byte) {
	b = make([]byte, EventTypeLength)
	b[0] = byte(t >> 8)
	b[1] = byte(t)
	return b
}

func (t EventType) IsAuditing() bool {
	return t == AuditingEvent
}

func ToEventType(b []byte) EventType {
	var et EventType
	if len(b) > 0 {
		et = EventType(uint16(b[0]) << 8)
		if len(b) > 1 {
			et += EventType(b[1])
		}
	}
	return et
}

const (
	// basic event types, the number of these types should not exceed 255, otherwise it will
	// confilict with consensus event
	TextEvent EventType = 0x0000 + iota
	ToOneEvent
	JustHashEvent
	WantDetailEvent
	TxEvent
	// ReportBlockEvent
	BlockEvent
	StartEvent
	LastBlockEvent
	LastReportEvent
	SyncRequestEvent
	RelayEvent
	StopEvent
	ShardDeltaEvent
	DeltaRequestEvent
	LastHeightEvent
	BlockRequestEvent
	SyncFinishEvent
	SyncFailureEvent
	HistoryBlockEvent
	// RewardRequestEvent
	RRProofsRequestEvent
	RRProofsMessageEvent
	ReportNodeInfoEvent
	LastCommEvent
	StartCommEvent
	StartConsEvent
	PreelectionStartEvent
	PreelectionConnectEvent
	PreelectionSyncEvent
	PreelectionExamineEvent
	PreelectionExitEvent
	MissingChainEvent
	SevereErrEvent
	DeltasPackEvent
	NodeStateEvent
	SyncedNotifyEvent
	AuditingEvent
	BlockResponseEvent
	ReviveStatusEvent
	RestartCommEvent
	AuditRequestEvent
	ChainStoppedEvent
	ChainRestartingEvent
	PreelectionPrepareEvent
	InitChainEvent
	RebootMainEvent

	UNSETEVENT EventType = 0xFFFF // This is the last EventType, ADD A NEW EventType BEFORE THIS PLEASE.
)

var (
	ErrUnrecognized = errors.New("unrecognized")

	eventTypeMap = map[EventType]reflect.Type{
		TextEvent:       reflect.TypeOf((*TextEMessage)(nil)).Elem(),
		ToOneEvent:      reflect.TypeOf((*ToOneEMessage)(nil)).Elem(),
		JustHashEvent:   reflect.TypeOf((*JustHashEMessage)(nil)).Elem(),
		WantDetailEvent: reflect.TypeOf((*WantDetailEMessage)(nil)).Elem(),
		TxEvent:         reflect.TypeOf((*Transaction)(nil)).Elem(),
		// ReportBlockEvent:        reflect.TypeOf((*BlockReport)(nil)).Elem(),
		BlockEvent:        reflect.TypeOf((*BlockEMessage)(nil)).Elem(),
		StartEvent:        reflect.TypeOf((*StartEMessage)(nil)).Elem(),
		LastBlockEvent:    reflect.TypeOf((*LastBlockMessage)(nil)).Elem(),
		LastReportEvent:   reflect.TypeOf((*LastReportMessage)(nil)).Elem(),
		SyncRequestEvent:  reflect.TypeOf((*SyncRequest)(nil)).Elem(),
		SyncFinishEvent:   reflect.TypeOf((*SyncFinish)(nil)).Elem(),
		SyncFailureEvent:  reflect.TypeOf((*SyncFailure)(nil)).Elem(),
		RelayEvent:        reflect.TypeOf((*RelayEventMsg)(nil)).Elem(),
		StopEvent:         reflect.TypeOf((*StopEMessage)(nil)).Elem(),
		ShardDeltaEvent:   reflect.TypeOf((*ShardDeltaMessage)(nil)).Elem(),
		DeltaRequestEvent: reflect.TypeOf((*DeltaRequestMessage)(nil)).Elem(),
		LastHeightEvent:   reflect.TypeOf((*LastHeightMessage)(nil)).Elem(),
		BlockRequestEvent: reflect.TypeOf((*BlockRequest)(nil)).Elem(),
		HistoryBlockEvent: reflect.TypeOf((*HistoryBlock)(nil)).Elem(),
		// RewardRequestEvent:      reflect.TypeOf((*RewardRequest)(nil)).Elem(),
		RRProofsRequestEvent:    reflect.TypeOf((*RRProofsRequest)(nil)).Elem(),
		RRProofsMessageEvent:    reflect.TypeOf((*RRProofsMessage)(nil)).Elem(),
		ReportNodeInfoEvent:     reflect.TypeOf((*ReportNodeInfoEMessage)(nil)).Elem(),
		LastCommEvent:           reflect.TypeOf((*LastCommEMessage)(nil)).Elem(),
		StartCommEvent:          reflect.TypeOf((*StartCommEMessage)(nil)).Elem(),
		StartConsEvent:          reflect.TypeOf((*StartConsEMessage)(nil)).Elem(),
		PreelectionStartEvent:   reflect.TypeOf((*PreelectionStart)(nil)).Elem(),
		PreelectionPrepareEvent: reflect.TypeOf((*PreelectionPrepare)(nil)).Elem(),
		PreelectionConnectEvent: reflect.TypeOf((*PreelectionConnect)(nil)).Elem(),
		PreelectionSyncEvent:    reflect.TypeOf((*PreelectionSync)(nil)).Elem(),
		PreelectionExamineEvent: reflect.TypeOf((*PreelectionExamine)(nil)).Elem(),
		PreelectionExitEvent:    reflect.TypeOf((*PreelectionExit)(nil)).Elem(),
		MissingChainEvent:       reflect.TypeOf((*MissingChainEventMsg)(nil)).Elem(),
		SevereErrEvent:          reflect.TypeOf((*SevereErrorEventMsg)(nil)).Elem(),
		DeltasPackEvent:         reflect.TypeOf((*DeltasPack)(nil)).Elem(),
		NodeStateEvent:          reflect.TypeOf((*NodeState)(nil)).Elem(),
		SyncedNotifyEvent:       reflect.TypeOf((*SyncedNotify)(nil)).Elem(),
		AuditingEvent:           reflect.TypeOf((*AuditingMessage)(nil)).Elem(),
		BlockResponseEvent:      reflect.TypeOf((*BlockResponse)(nil)).Elem(),
		ReviveStatusEvent:       reflect.TypeOf((*ReviveStatus)(nil)).Elem(),
		RestartCommEvent:        reflect.TypeOf((*RestartCommEMessage)(nil)).Elem(),
		ChainStoppedEvent:       reflect.TypeOf((*ChainStoppedMessage)(nil)).Elem(),
		ChainRestartingEvent:    reflect.TypeOf((*ChainRestartingMessage)(nil)).Elem(),
		AuditRequestEvent:       reflect.TypeOf((*AuditRequest)(nil)).Elem(),
		InitChainEvent:          reflect.TypeOf((*InitialChainMessage)(nil)).Elem(),
		RebootMainEvent:         reflect.TypeOf((*RebootMainChainMessage)(nil)).Elem(),
	}

	// reversedEventTypeMap = reverseEventTypeMap(eventTypeMap)
	eventTypeNames = map[EventType]string{
		TextEvent:       "TextEvent",
		ToOneEvent:      "ToOneEvent",
		JustHashEvent:   "JustHashEvent",
		WantDetailEvent: "WantDetailEvent",
		TxEvent:         "TxEvent",
		// ReportBlockEvent:        "ReportBlockEvent",
		BlockEvent:        "BlockEvent",
		StartEvent:        "Start",
		LastBlockEvent:    "LastBlock",
		LastReportEvent:   "LastReport",
		SyncRequestEvent:  "SyncRequest",
		RelayEvent:        "Ctrl-RelayEvent",
		StopEvent:         "StopEvent",
		ShardDeltaEvent:   "ShardDeltaEvent",
		DeltaRequestEvent: "DeltaRequestEvent",
		LastHeightEvent:   "LastHeightEvent",
		BlockRequestEvent: "BlockRequestEvent",
		UNSETEVENT:        "UNSET",
		SyncFinishEvent:   "SyncFinishEvent",
		SyncFailureEvent:  "SyncFailureEvent",
		HistoryBlockEvent: "HistoryBlockEvent",
		// RewardRequestEvent:      "RewardRequestEvent",
		RRProofsRequestEvent:    "RRProofsRequestEvent",
		RRProofsMessageEvent:    "RRProofsMessageEvent",
		ReportNodeInfoEvent:     "ReportNodeInfoEvent",
		LastCommEvent:           "LastCommEvent",
		StartCommEvent:          "StartCommEvent",
		StartConsEvent:          "StartConsensus",
		PreelectionStartEvent:   "PEStart",
		PreelectionPrepareEvent: "PEPrepare",
		PreelectionConnectEvent: "PEConnect",
		PreelectionSyncEvent:    "PESync",
		PreelectionExamineEvent: "PEExamine",
		PreelectionExitEvent:    "PEExit",
		MissingChainEvent:       "Ctrl-MissingChain",
		SevereErrEvent:          "Ctrl-SevereErr",
		DeltasPackEvent:         "DeltasPack",
		NodeStateEvent:          "NodeStateEvent",
		SyncedNotifyEvent:       "SyncedNotifyEvent",
		AuditingEvent:           "AuditingEvent",
		BlockResponseEvent:      "BlockResponseEvent",
		ReviveStatusEvent:       "ReviveStatusEvent",
		RestartCommEvent:        "RestartCommEvent",
		AuditRequestEvent:       "AuditRequest",
		ChainStoppedEvent:       "ChainStopped",
		ChainRestartingEvent:    "ChainRestarting",
		InitChainEvent:          "InitChain",
		RebootMainEvent:         "RebootMain",
	}
)

func init() {
	RegisterEvents(eventTypeMap, eventTypeNames)
}

func FindObjectTypeByEventType(eventType EventType) (t reflect.Type, ok bool) {
	return eventDict.GetObjectType(eventType)
}

func FindEventTypeByObjectType(typ reflect.Type) (t EventType, ok bool) {
	switch typ.Kind() {
	case reflect.Ptr:
		return eventDict.GetEventType(typ.Elem())
	default:
		return eventDict.GetEventType(typ)
	}
}

func MarshalEvent(m interface{}) (EventType, []byte, error) {
	if m == nil {
		return 0, nil, common.ErrNil
	}
	typ := reflect.TypeOf(m)
	eventType, ok := FindEventTypeByObjectType(typ)
	if !ok {
		return 0, nil, fmt.Errorf("event type not found by object type(%s)", typ.String())
	}

	body, err := rtl.Marshal(m)
	if err != nil {
		return eventType, nil, fmt.Errorf("marshal message failed: %v", err)
	}

	return eventType, body, nil
}

func UnmarshalEvent(eventType EventType, body []byte) (interface{}, error) {
	if len(body) == 0 {
		return nil, nil
	}
	msgType, exist := FindObjectTypeByEventType(eventType)
	if !exist {
		return nil, fmt.Errorf("object type not found with events.EventType(%s)", eventType)
	}

	msg := reflect.New(msgType)
	err := rtl.Unmarshal(body, msg.Interface())
	if err != nil {
		return nil, fmt.Errorf("unmarshal message failed: %v", err)
	}

	return msg.Interface(), nil
}
