package models

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"sync"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/sirupsen/logrus"
)

type (
	OperatorType byte

	OpSet struct {
		onlyOne bool
		one     OperatorType
		ots     map[OperatorType]struct{}
	}

	Operator struct {
		Type       OperatorType
		Operations []interface{}
	}

	RawData interface {
		GetFrom() Location
		GetFromNodeID() *common.NodeID
		GetFromChainID() common.ChainID
		GetFromNetType() common.NetType
		GetEventType() EventType
		GetData() []byte
		GetObject() interface{}
		GetHash() *common.Hash
		GetPublicKey() []byte
		GetSignature() []byte
	}

	ChainEvent interface {
		GetChainID() common.ChainID
	}

	DirectiveMsg interface {
		DestChainID() common.ChainID
	}

	ThresholdEvent interface {
		ChainEvent
		// Whether the current message can join the queue according to the threshold value, threshold can be nil
		Pass(threshold interface{}) bool
	}

	PubAndSig struct {
		PublicKey []byte `json:"pk"`
		Signature []byte `json:"sig"`
	}

	PubAndSigs []*PubAndSig

	Context struct {
		Op        *OpSet
		Eventer   Eventer
		ChainInfo *common.ChainInfos
		ShardInfo common.ShardInfo
		Networker Networker
		Holder    DataHolder
		Engine    Engine

		// source of message
		Source Location

		// for test adapter
		Dmanager DataManager
		Nmanager NetworkManager

		WorkerName string
		Logger     logrus.FieldLogger
		PAS        *PubAndSig

		InBlockBufProc    int32 // avoid deep nesting of ProcessBlockBuf
		InHisBlockBufProc int32
		FatalError        error // if not nil, should break out the
	}

	Eventer interface {
		common.Service
		PrintCounts()
		SetEngine(engine Engine)
		SetDataManager(manager DataManager)
		SetNetworkManager(manager NetworkManager)
		Shutdown()
		HasChainOpType(chainid common.ChainID, opType OperatorType) bool
		GetChainOpTypes(chainid common.ChainID) []OperatorType
		GetNodeOpTypes() map[common.ChainID][]string
		AddChainOpType(id common.ChainID, opType OperatorType)
		AppendChainOpType(id common.ChainID, opType OperatorType)
		RemoveChainOpType(id common.ChainID, opType OperatorType)
		ReplaceChainOpTypes(id common.ChainID, fromType OperatorType, toType OperatorType) bool
		ClearChainOpType(chainid common.ChainID)
		ResetToFailureOpType(chainid common.ChainID)
		SetEventThreshold(chainId common.ChainID, threshold interface{})
		PostMain(RawData)
		SyncPost(event interface{})
		Post(interface{})
		PostEvent(event interface{}, pub, sig []byte) error
		ExitChain(id common.ChainID) // exit from chain
		// check access permission
		CheckPermission(chainId common.ChainID, nodeId common.NodeID, netType common.NetType, proof []byte) error
		ReadOnly() Eventer
		IsReviving(cid common.ChainID) bool
	}

	Location struct {
		nodeID  *common.NodeID
		chainID common.ChainID
		netType common.NetType
	}

	RawDataObj struct {
		from      Location     // source of event
		eventType EventType    // event type
		h         *common.Hash // payload hash, hash(event body serialization, event type)
		data      []byte       // event body serialization
		pub       []byte       // public key
		sig       []byte       // signature of hash of the event: Sign(HashObject(EventObject))
		v         interface{}  // object deserialized from data
	}

	QueueObj struct {
		From      Location     // source of event
		EventType EventType    // event type
		H         *common.Hash // payload hash, hash(event body serialization, event type)
		V         interface{}  // event object
		P         []byte       // public key
		S         []byte       // signature of hash of the event: Sign(HashObject(V))
	}
)

var (
	RawDataPool = sync.Pool{
		New: func() interface{} {
			return new(RawDataObj)
		},
	}

	QueueObjPool = sync.Pool{
		New: func() interface{} {
			return new(QueueObj)
		},
	}

	operatorTypeNames = map[OperatorType]string{
		CtrlOp:      "CTRL",
		DataOp:      "DATA",
		CommitteeOp: "COMM",
		SpectatorOp: "SPEC",
		MemoOp:      "MEMO",
		InitialOp:   "INIT",
		StartOp:     "START",
		FailureOp:   "FAIL",
		PreelectOp:  "PELT",
		ReviveOp:    "REVIVE",
		RestartOp:   "RESTART",
	}

	TypeOfContextPtr = reflect.TypeOf((*Context)(nil))
)

func (o OperatorType) String() string {
	if n, ok := operatorTypeNames[o]; ok {
		return n
	}
	return "OperatorType-" + strconv.Itoa(int(o))
}

func NewOpSet(ots []OperatorType) *OpSet {
	if len(ots) == 0 {
		return &OpSet{
			onlyOne: false,
			one:     0,
			ots:     nil,
		}
	}
	m := make(map[OperatorType]struct{})
	for _, ot := range ots {
		m[ot] = struct{}{}
	}
	if len(m) == 1 {
		set := new(OpSet)
		set.onlyOne = true
		for k := range m {
			set.one = k
		}
		return set
	} else {
		return &OpSet{
			onlyOne: false,
			one:     0,
			ots:     m,
		}
	}
}

func (s *OpSet) Has(opType OperatorType) bool {
	if s == nil || (s.onlyOne == false && len(s.ots) == 0) {
		return false
	}
	if s.onlyOne {
		return opType == s.one
	} else {
		_, exist := s.ots[opType]
		return exist
	}
}

// any one or more
func (s *OpSet) HasAny(opTypes ...OperatorType) bool {
	if s == nil || (s.onlyOne == false && len(s.ots) == 0) {
		return false
	}
	if s.onlyOne {
		for _, opt := range opTypes {
			if opt == s.one {
				return true
			}
		}
		return false
	} else {
		for _, opt := range opTypes {
			_, exist := s.ots[opt]
			if exist {
				return true
			}
		}
		return false
	}
}

func (l Location) NodeID() *common.NodeID {
	return l.nodeID
}

func (l Location) ChainID() common.ChainID {
	return l.chainID
}

func (l Location) NetType() common.NetType {
	return l.netType
}

func (l *Location) SetNodeID(nid *common.NodeID) {
	l.nodeID = nid
}

func (l *Location) SetChainID(chainID common.ChainID) {
	l.chainID = chainID
}

func (l *Location) SetNetType(netType common.NetType) {
	l.netType = netType
}

func (l Location) NoWhere() bool {
	return l.nodeID == nil
}

func (l Location) String() string {
	return fmt.Sprintf("Location{NID:%s, ChainID:%d, NetType:%s}", l.nodeID, l.chainID, l.netType)
}

func NewRawData(fromNodeID *common.NodeID, fromChainID common.ChainID,
	fromNetType common.NetType, eventType EventType, data, pub, sig []byte, dataHash *common.Hash, v interface{}) *RawDataObj {
	rawdata, _ := RawDataPool.Get().(*RawDataObj)
	rawdata.from.nodeID = fromNodeID
	rawdata.from.chainID = fromChainID
	rawdata.from.netType = fromNetType
	rawdata.eventType = eventType
	rawdata.data = data
	rawdata.v = v
	rawdata.pub = pub
	rawdata.sig = sig
	if dataHash == nil {
		msgLoad := append(data, eventType.Bytes()...)
		rawdata.h = common.Hash256p(msgLoad)
	} else {
		rawdata.h = dataHash
	}
	return rawdata
}

func ReleaseRawData(rawData *RawDataObj) {
	RawDataPool.Put(rawData)
}

func (r *RawDataObj) GetFrom() Location {
	return r.from
}

func (r *RawDataObj) GetFromNodeID() *common.NodeID {
	return r.from.NodeID()
}

func (r *RawDataObj) GetFromChainID() common.ChainID {
	return r.from.ChainID()
}

func (r *RawDataObj) GetFromNetType() common.NetType {
	return r.from.NetType()
}

func (r *RawDataObj) GetEventType() EventType {
	return r.eventType
}

func (r *RawDataObj) GetData() []byte {
	return r.data
}

func (r *RawDataObj) GetObject() interface{} {
	return r.v
}

func (r *RawDataObj) GetHash() *common.Hash {
	return r.h
}

func (r *RawDataObj) GetPublicKey() []byte {
	return r.pub
}

func (r *RawDataObj) GetSignature() []byte {
	return r.sig
}

func (r *RawDataObj) String() string {
	return fmt.Sprintf("{eventType:%s, from:%s len(data)=%d, hash=%x, v==nil:%t}",
		r.eventType, r.from, len(r.data), r.h[:5], r.v == nil)
}

func NewQueueObj(fromNodeID *common.NodeID, fromChainID common.ChainID, fromNetType common.NetType,
	eventType EventType, hashOfPayLoad *common.Hash, event interface{}, pub, sig []byte) *QueueObj {
	o := QueueObjPool.Get().(*QueueObj)
	o.From.SetNodeID(fromNodeID)
	o.From.SetChainID(fromChainID)
	o.From.SetNetType(fromNetType)
	o.EventType = eventType
	o.H = hashOfPayLoad
	o.V = event
	o.P = pub
	o.S = sig
	return o
}

func ReleaseQueueObj(obj *QueueObj) {
	QueueObjPool.Put(obj)
}

func (r *QueueObj) String() string {
	if r == nil {
		return ""
	}
	var h []byte
	if r.H != nil {
		h = r.H[:5]
	}
	return fmt.Sprintf("QueueObj{%s, Hash:%x, %s}", r.EventType, h, r.From)
}

// return public key bytes slice and signature bytes slice
func (ctx *Context) GetPAS() ([]byte, []byte) {
	if ctx.PAS == nil {
		return nil, nil
	}
	return ctx.PAS.PublicKey, ctx.PAS.Signature
}

// clear public key and signature in context
func (ctx *Context) ClearPAS() {
	ctx.PAS = nil
}

// set public key and signature in context
func (ctx *Context) SetPAS(pub, sig []byte) {
	ctx.PAS = &PubAndSig{PublicKey: pub, Signature: sig}
}

func (ctx *Context) Clone() *Context {
	if ctx == nil {
		return nil
	}
	return &Context{
		ChainInfo:         ctx.ChainInfo,
		ShardInfo:         ctx.ShardInfo,
		Holder:            ctx.Holder,
		Engine:            ctx.Engine,
		Op:                ctx.Op,
		Source:            ctx.Source,
		Networker:         ctx.Networker,
		Eventer:           ctx.Eventer,
		Dmanager:          ctx.Dmanager,
		Nmanager:          ctx.Nmanager,
		WorkerName:        ctx.WorkerName,
		InBlockBufProc:    ctx.InBlockBufProc,
		InHisBlockBufProc: ctx.InHisBlockBufProc,
		Logger:            ctx.Logger,
	}
}

func (ctx *Context) RebuildContext(newChainID common.ChainID) *Context {
	newctx := ctx.Clone()

	if !newChainID.IsNil() {
		holder, err := ctx.Dmanager.GetChainData(newChainID)
		if err != nil {
			newctx.Holder = nil
		} else {
			newctx.Holder = holder
		}
		if newctx.Holder != nil {
			newctx.ChainInfo, _ = newctx.Dmanager.GetChainInfos(newChainID)
			newctx.ShardInfo = newctx.Holder.GetShardInfo()
		} else {
			newctx.ChainInfo = nil
			newctx.ShardInfo = nil
		}
		newctx.Networker = ctx.Nmanager.GetNetworker(newChainID)
	}
	newctx.Logger = newctx.Logger.WithFields(logrus.Fields{"C": newChainID})

	return newctx
}

func nilName(name string, isNil bool) string {
	if isNil {
		return name + "<nil>"
	}
	return name
}

func (ctx *Context) String() string {
	if ctx == nil {
		return "Context<nil>"
	}
	shard := "ShardInfo<nil>"
	if ctx.ShardInfo != nil {
		shard = fmt.Sprintf("%s", ctx.ShardInfo)
	}
	return fmt.Sprintf("Context{%s %s %s %s %s %s %s %s %s %s %s}",
		nilName("Eventer", ctx.Eventer == nil),
		ctx.ChainInfo, shard, nilName("Networker", ctx.Networker == nil),
		nilName("Holder", ctx.Holder == nil), nilName("Engine", ctx.Engine == nil),
		nilName("DManager", ctx.Dmanager == nil), nilName("NManager", ctx.Nmanager == nil),
		ctx.Source, ctx.WorkerName, nilName("PaS", ctx.PAS == nil))
}

func (ctx *Context) RandomDataNode() (common.NodeID, error) {
	if ctx == nil || ctx.ChainInfo == nil || len(ctx.ChainInfo.Datas) == 0 {
		return common.NodeID{}, errors.New("nil context or nil chain info or no data nodes")
	}
	all := len(ctx.ChainInfo.Datas)
	if all == 1 {
		if ctx.ChainInfo.Datas[0] == common.SystemNodeID {
			return common.NodeID{}, errors.New("data node only self, can't sync")
		}
		return ctx.ChainInfo.Datas[0], nil
	} else {
		idx := rand.Intn(all)
		if ctx.ChainInfo.Datas[idx] == common.SystemNodeID {
			if idx > 0 {
				idx--
			} else {
				idx++
			}
		}
		return ctx.ChainInfo.Datas[idx], nil
	}
}

func (p *PubAndSig) Equal(o *PubAndSig) bool {
	if p == o {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	return bytes.Equal(p.PublicKey, o.PublicKey) && bytes.Equal(p.Signature, o.Signature)
}

func (p *PubAndSig) Equals(v interface{}) bool {
	o, ok := v.(*PubAndSig)
	if !ok {
		return false
	}
	if p == o {
		return true
	}
	if p != nil && o != nil &&
		bytes.Equal(p.Signature, o.Signature) &&
		bytes.Equal(p.PublicKey, o.PublicKey) {
		return true
	}
	return false
}

func (p *PubAndSig) IsValid() bool {
	if p == nil {
		return false
	}
	if len(p.Signature) != cipher.RealCipher.LengthOfSignature() {
		return false
	}
	if len(p.PublicKey) != 0 && len(p.PublicKey) != cipher.RealCipher.LengthOfPublicKey() {
		return false
	}
	return true
}

// order by (signature, public key)
func (p *PubAndSig) Compare(o *PubAndSig) int {
	if cmp, needCompare := common.PointerCompare(p, o); !needCompare {
		return cmp
	}
	if c := bytes.Compare(p.Signature, o.Signature); c == 0 {
		return bytes.Compare(p.PublicKey, o.PublicKey)
	} else {
		return c
	}
}

func (p *PubAndSig) Clone() *PubAndSig {
	if p == nil {
		return nil
	}
	n := new(PubAndSig)
	n.PublicKey = common.CopyBytes(p.PublicKey)
	n.Signature = common.CopyBytes(p.Signature)
	return n
}

func (p *PubAndSig) Key() []byte {
	if p == nil {
		return nil
	}
	i := 0
	key := make([]byte, len(p.PublicKey)+1+len(p.Signature))
	if len(p.PublicKey) > 0 {
		copy(key[i:], p.PublicKey)
		i += len(p.PublicKey)
	}
	key[i] = '-'
	i++
	if len(p.Signature) > 0 {
		copy(key[i:], p.Signature)
	}
	return key
}

func (p *PubAndSig) String() string {
	if p == nil {
		return "PaS<nil>"
	}
	return fmt.Sprintf("PaS{P:%x S:%x}", common.ForPrint(p.PublicKey),
		common.ForPrint(p.Signature))
}

func (p *PubAndSig) FullString() string {
	if p == nil {
		return "PaS<nil>"
	}
	return fmt.Sprintf("PaS{P:%x S:%x}", p.PublicKey, p.Signature)
}

func (p *PubAndSig) InfoString(_ common.IndentLevel) string {
	return p.FullString()
}

func (p *PubAndSig) GetPublicKey(hashOfMsg []byte) ([]byte, error) {
	if len(p.PublicKey) > 0 {
		return p.PublicKey, nil
	}
	if !PubKeyCanRecover() {
		return nil, errors.New("public key cannot be recoverred")
	}
	if len(p.Signature) == 0 {
		return nil, errors.New("signature is missing")
	}
	return cipher.RealCipher.RecoverPub(hashOfMsg, p.Signature)
}

func (p *PubAndSig) Sign(objHash []byte) (*PubAndSig, error) {
	pub, sig, err := SignHash(objHash)
	if err != nil {
		return nil, err
	}
	r := p
	if r == nil {
		r = new(PubAndSig)
	}
	r.PublicKey = pub
	r.Signature = sig
	return r, nil
}

func (p *PubAndSig) Signer(hashOfMsg []byte) (common.NodeID, error) {
	if p == nil {
		return common.NodeID{}, errors.New("nil sig")
	}
	if pk, err := p.GetPublicKey(hashOfMsg); err != nil {
		return common.NodeID{}, err
	} else {
		return PubToNodeID(pk)
	}
}

func (p *PubAndSig) Verify(hashOfMsg []byte) (pubKey []byte, err error) {
	if p == nil {
		return nil, errors.New("nil PubAndSig")
	}
	var ok bool
	ok, pubKey = VerifyHashWithPub(hashOfMsg, p.PublicKey, p.Signature)
	if !ok {
		return nil, errors.New("wrong PubAndSig")
	}
	return
}

func (p *PubAndSig) VerifiedNodeID(hashOfMsg []byte) (common.NodeID, error) {
	pk, err := p.Verify(hashOfMsg)
	if err != nil {
		return common.NodeID{}, err
	}
	return PubToNodeID(pk)
}

func (ps PubAndSigs) Len() int {
	return len(ps)
}

func (ps PubAndSigs) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// sort by (signature, public key), in order to be compatible with the original bug version
func (ps PubAndSigs) Less(i, j int) bool {
	return ps[i].Compare(ps[j]) < 0
}

func (ps PubAndSigs) Equal(os PubAndSigs) bool {
	if ps == nil && os == nil {
		return true
	}
	if ps == nil || os == nil {
		return false
	}
	if len(ps) != len(os) {
		return false
	}
	for i := 0; i < len(ps); i++ {
		if !ps[i].Equal(os[i]) {
			return false
		}
	}
	return true
}

func (ps PubAndSigs) Equals(o interface{}) bool {
	os, _ := o.(PubAndSigs)
	return ps.Equal(os)
}

func (ps PubAndSigs) Clone() PubAndSigs {
	if ps == nil {
		return nil
	}
	ns := make(PubAndSigs, len(ps))
	for i := 0; i < len(ps); i++ {
		ns[i] = ps[i].Clone()
	}
	return ns
}

func (ps PubAndSigs) Verify(h []byte) (int, error) {
	count := 0
	dedup := make(map[string]struct{})
	for _, pas := range ps {
		if pas == nil {
			continue
		}
		if pas.PublicKey != nil {
			if _, exist := dedup[string(pas.PublicKey)]; exist {
				continue
			}
		}
		ok, pubkey := VerifyHashWithPub(h, pas.PublicKey, pas.Signature)
		if !ok {
			return 0, fmt.Errorf("%s verify failed", pas)
		}
		if _, exist := dedup[string(pubkey)]; !exist {
			dedup[string(pubkey)] = struct{}{}
			count++
		}
	}
	return count, nil
}

func (ps PubAndSigs) VerifyByPubs(pks [][]byte, hashOfObject []byte, sizeChecker func(int) error) (PubAndSigs, error) {
	if sizeChecker != nil {
		if err := sizeChecker(len(ps)); err != nil {
			return nil, fmt.Errorf("size of pass(%d), pks(%d), verify failed: %v", len(ps), len(pks), err)
		}
	}
	pkMap := make(map[string]struct{})
	for _, pk := range pks {
		if len(pk) == 0 {
			continue
		}
		pkMap[string(pk)] = struct{}{}
	}

	var ret PubAndSigs
	notList := make(map[string]struct{})
	inList := make(map[string]struct{})
	for _, pas := range ps {
		if pas == nil {
			continue
		}
		ok, pk := VerifyHashWithPub(hashOfObject, pas.PublicKey, pas.Signature)
		if !ok {
			log.Warnf("%s signature verify by %x failed", pas, hashOfObject)
			continue
		}
		pkstr := string(pk)
		if _, exist := pkMap[pkstr]; exist {
			if _, alreadyIn := inList[pkstr]; !alreadyIn {
				inList[pkstr] = struct{}{}
				ret = append(ret, pas)
			}
		}
	}
	if sizeChecker != nil {
		if err := sizeChecker(len(inList)); err != nil {
			return nil, fmt.Errorf("size of valid pass(%d), not in(%d), pks(%d), verify failed: %v",
				len(inList), len(notList), len(pkMap), err)
		}
	}
	return ret, nil
}

func (ps PubAndSigs) VerifyByNodeIDs(nids common.NodeIDs, hashOfObject []byte, sizeChecker func(int) error) (PubAndSigs, error) {
	if sizeChecker != nil {
		if err := sizeChecker(len(ps)); err != nil {
			return nil, fmt.Errorf("size of pass(%d), nids(%d), verify failed: %v", len(ps), len(nids), err)
		}
	}
	var nidMap map[common.NodeID]struct{}
	if len(nids) > 0 {
		nidMap = nids.ToMap()
	} else {
		nidMap = make(map[common.NodeID]struct{})
	}
	var ret PubAndSigs
	notList := make(map[common.NodeID]struct{})
	inList := make(map[common.NodeID]struct{})
	for _, pas := range ps {
		if pas == nil {
			continue
		}
		ok, pk := VerifyHashWithPub(hashOfObject, pas.PublicKey, pas.Signature)
		if !ok {
			log.Warnf("%s signature verify by %x failed", pas, hashOfObject)
			continue
		}
		nid, err := PubToNodeID(pk)
		if err != nil {
			log.Warnf("Pub(%x) -> NodeID failed: %v", common.ForPrint(pk, 0, -1), err)
			continue
		}
		if _, exist := nidMap[nid]; !exist {
			notList[nid] = struct{}{}
		} else {
			if _, alreadyIn := inList[nid]; !alreadyIn {
				inList[nid] = struct{}{}
				ret = append(ret, pas)
			}
		}
	}
	if sizeChecker != nil {
		if err := sizeChecker(len(inList)); err != nil {
			return nil, fmt.Errorf("size of valid pass(%d), not in(%d), nids(%d), verify failed: %v",
				len(inList), len(notList), len(nidMap), err)
		}
	}
	return ret, nil
}

func (ps PubAndSigs) VerifyByComm(comm *Committee, h []byte) error {
	if comm == nil {
		return nil
	}
	sizeChecker := func(size int) error {
		if !comm.ReachRequires(size) {
			return fmt.Errorf("not reach the comm(%d)*2/3", comm.Size())
		}
		return nil
	}
	_, err := ps.VerifyByNodeIDs(common.NodeIDs(comm.Members), h, sizeChecker)
	return err
}

func (ps PubAndSigs) InfoString(level common.IndentLevel) string {
	return level.InfoString(ps)
}

func (ps PubAndSigs) Merge(os PubAndSigs) PubAndSigs {
	if len(os) == 0 {
		return ps
	}
	dedup := make(map[string]*PubAndSig)
	tomap := func(pss PubAndSigs) {
		for _, p := range pss {
			if p == nil {
				continue
			}
			key := p.Key()
			dedup[string(key)] = p
		}
	}
	tomap(os)
	tomap(ps)
	if len(dedup) == 0 {
		return nil
	}
	ret := make(PubAndSigs, 0, len(dedup))
	for _, p := range dedup {
		ret = append(ret, p)
	}
	if len(ret) > 1 {
		sort.Sort(ret)
	}
	return ret
}

// create new PubAndSigs with pubs & sigs
func (ps PubAndSigs) FromPubsAndSigs(pubs, sigs [][]byte) (PubAndSigs, error) {
	var ret PubAndSigs
	if len(sigs) > 0 || len(pubs) > 0 {
		if len(sigs) != len(pubs) {
			return nil, errors.New("lengths of multi public keys and signatures not equal")
		}
		for i := 0; i < len(sigs); i++ {
			if len(sigs[i]) == 0 {
				return nil, fmt.Errorf("invalid signature at index %d", i)
			}
			ret = append(ret, &PubAndSig{
				PublicKey: common.CopyBytes(pubs[i]),
				Signature: common.CopyBytes(sigs[i]),
			})
		}
	}
	return ret, nil
}
