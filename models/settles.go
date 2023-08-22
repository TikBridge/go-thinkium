package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
)

type RRSyncData struct {
	CurrentInfos     []*RRInfo
	NextChangedInfos []*RRInfo
	Deleted          []common.Hash
	Changing         []*RRC
}

func (d *RRSyncData) String() string {
	if d == nil {
		return "RRData<nil>"
	}
	return fmt.Sprintf("RRData{RR:%d RRN:%d RRD:%d RRC:%d}",
		len(d.CurrentInfos), len(d.NextChangedInfos), len(d.Deleted), len(d.Changing))
}

func (d *RRSyncData) InfoString() string {
	if d == nil {
		return "RRData<nil>"
	}
	if len(d.CurrentInfos) <= 200 {
		return fmt.Sprintf("RRData{RR:%s RRN:%s RRD:%s RRC:%s}",
			d.CurrentInfos, d.NextChangedInfos, d.Deleted, d.Changing)
	} else {
		return fmt.Sprintf("RRData{RR:%d RRN:%s RRD:%s RRC:%s}", len(d.CurrentInfos), d.NextChangedInfos, d.Deleted, d.Changing)
	}
}

type NodeAddresses struct {
	NIDH  common.Hash
	Addrs []common.Address
}

func (n *NodeAddresses) Compare(o *NodeAddresses) int {
	if cmp, needCompare := common.PointerCompare(n, o); !needCompare {
		return cmp
	}
	p := bytes.Compare(n.NIDH[:], o.NIDH[:])
	if p == 0 {
		return common.CompareSlices(n.Addrs, o.Addrs, func(c, d interface{}) int {
			a := c.(common.Address)
			b := d.(common.Address)
			return bytes.Compare(a[:], b[:])
		})
	} else {
		return p
	}
}

func (n *NodeAddresses) String() string {
	if n == nil {
		return "Addrs<nil>"
	}
	return fmt.Sprintf("Addrs{NIDH:%x Addrs:%s}", n.NIDH[:], n.Addrs)
}

type NodeAddressesList []*NodeAddresses

func (l NodeAddressesList) ToMap() map[common.Hash][]common.Address {
	if len(l) == 0 {
		return nil
	}
	m := make(map[common.Hash][]common.Address)
	for _, n := range l {
		if n == nil {
			continue
		}
		m[n.NIDH] = n.Addrs
	}
	return m
}

func (l NodeAddressesList) String() string {
	if l == nil {
		return "AddrsList<nil>"
	}
	return fmt.Sprintf("AddrsList(%d)%s", len(l), ([]*NodeAddresses)(l))
}

type (
	ActRptType byte

	// used to record the result of each RRAct generated by the transaction specified by (TxChainID, TxHash)
	// after asynchronous execution
	RRActReceipt struct {
		TxHash common.Hash `json:"txHash"`
		Status uint8       `json:"status"`
		Type   ActRptType  `json:"type"`
		Msg    string      `json:"msg"` // json format of returned value
	}

	RRActReceipts []*RRActReceipt

	RRReceiptIndex struct {
		RootOfReceipts common.Hash
		Index          uint32
	}

	ActResult interface {
		Receipt() *RRActReceipt
		String() string
	}

	ActFailedResult struct {
		TxHash common.Hash
		Error  error
	}

	CreateResult struct {
		TxHash common.Hash    `json:"-"`
		NIDH   common.Hash    `json:"nidh"`
		Addr   common.Address `json:"binding"`
		Amount *big.Int       `json:"amount"`
	}

	WithdrawResult struct {
		TxHash common.Hash  `json:"-"`
		Type   ActRptType   `json:"-"`
		NIDH   common.Hash  `json:"nidh"`
		Result *Withdrawing `json:"result,omitempty"`
	}

	DepositResult struct {
		TxHash common.Hash    `json:"-"`
		Type   ActRptType     `json:"-"`
		NIDH   common.Hash    `json:"nidh"`
		Addr   common.Address `json:"address"`
		Prev   *big.Int       `json:"pervAmount,omitempty"`
		New    *big.Int       `json:"newAmount,omitempty"`
	}

	StatusResult struct {
		TxHash common.Hash `json:"-"`
		Type   ActRptType  `json:"-"`
		NIDH   common.Hash `json:"nidh"`
		Prev   uint16      `json:"prev"`
		New    uint16      `json:"new"`
	}

	PenalizeResult struct {
		TxHash common.Hash `json:"-"`
		Type   ActRptType  `json:"-"`
		NIDH   common.Hash `json:"nidh"`
		Amount *big.Int    `json:"penalized"`
	}
	//
	// VoteResult struct {
	// 	TxHash common.Hash   `json:"-"`
	// 	Target common.NodeID `json:"nodeid"`
	// }
)

const (
	ARMerged ActRptType = iota
	ARCreated
	ARIgnored
)

func (t ActRptType) String() string {
	switch t {
	case ARMerged:
		return "MERGED"
	case ARCreated:
		return "CREATED"
	case ARIgnored:
		return "IGNORED"
	default:
		return fmt.Sprintf("UNKNOWN-%02x", byte(t))
	}
}

func (r *RRActReceipt) String() string {
	if r == nil {
		return "RRRPT<nil>"
	}
	return fmt.Sprintf("RRRPT{Tx:%x Status:%d Type:%s Msg:%s}", r.TxHash[:], r.Status, r.Type, r.Msg)
}

func (r *RRActReceipt) InfoString(level common.IndentLevel) string {
	if r == nil {
		return "RRReceipt<nil>"
	}
	base := level.IndentString()
	indent := (level + 1).IndentString()
	return fmt.Sprintf("RRReceipt{"+
		"\n%sTxHash: %x"+
		"\n%sStatus: 0x%x"+
		"\n%sType: %s"+
		"\n%sMsg: %s"+
		"\n%s}",
		indent, r.TxHash[:],
		indent, r.Status,
		indent, r.Type,
		indent, r.Msg,
		base)
}

func (rs RRActReceipts) String() string {
	if rs == nil {
		return "RRRPTs<nil>"
	}
	return fmt.Sprintf("RRRPTs%s", ([]*RRActReceipt)(rs))
}

func (rs RRActReceipts) HashValue() ([]byte, error) {
	if len(rs) == 0 {
		return nil, nil
	}
	hashList := make([][]byte, len(rs))
	var err error
	for i, r := range rs {
		hashList[i], err = common.HashObject(r)
		if err != nil {
			return nil, fmt.Errorf("HashObject(%d) failed: %v", i, err)
		}
	}
	return common.MerkleHash(hashList, 0, nil)
}

func NewRRActReceiptIndex(rootOfReceipts []byte, index uint32) *RRReceiptIndex {
	return &RRReceiptIndex{RootOfReceipts: common.BytesToHash(rootOfReceipts), Index: index}
}

func (r *ActFailedResult) Receipt() *RRActReceipt {
	msg := map[string]string{"error": r.Error.Error()}
	bs, _ := json.Marshal(msg)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusFailed, Type: ARIgnored, Msg: string(bs)}
}

func (r *ActFailedResult) String() string {
	if r == nil {
		return "FAILR<nil>"
	}
	return fmt.Sprintf("FAILR{Tx:%x Err:%v}", r.TxHash, r.Error)
}

func (r *CreateResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(r)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: ARCreated, Msg: string(bs)}
}

func (r *CreateResult) String() string {
	if r == nil {
		return "CREATE<nil>"
	}
	return fmt.Sprintf("CREATE{Tx:%x NIDH:%x Addr:%x Amount:%s}", r.TxHash[:], r.NIDH[:],
		r.Addr[:], math.BigIntForPrint(r.Amount))
}

func (r *WithdrawResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(r)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: r.Type, Msg: string(bs)}
}

func (r *WithdrawResult) String() string {
	if r == nil {
		return "WDR<nil>"
	}
	return fmt.Sprintf("WDR{Tx:%x Typ:%d NIDH:%x %s}", r.TxHash[:], r.Type, r.NIDH[:], r.Result)
}

func (r *DepositResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(r)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: r.Type, Msg: string(bs)}
}

func (r *DepositResult) String() string {
	if r == nil {
		return "DEPR<nil>"
	}
	return fmt.Sprintf("DEPR{Tx:%x Typ:%d NIDH:%x Prev:%s New:%s}", r.TxHash[:], r.Type, r.NIDH,
		math.BigIntForPrint(r.Prev), math.BigIntForPrint(r.New))
}

func (r *StatusResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(r)
	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: ARMerged, Msg: string(bs)}
}

func (r *StatusResult) String() string {
	if r == nil {
		return "STR<nil>"
	}
	return fmt.Sprintf("STR{Tx:%x Typ:%d NIDH:%x Prev:%d New:%d}", r.TxHash[:], r.Type, r.NIDH[:], r.Prev, r.New)
}

func (p *PenalizeResult) Receipt() *RRActReceipt {
	bs, _ := json.Marshal(p)
	return &RRActReceipt{TxHash: p.TxHash, Status: ReceiptStatusSuccessful, Type: p.Type, Msg: string(bs)}
}

func (p *PenalizeResult) String() string {
	if p == nil {
		return "PEN<nil>"
	}
	return fmt.Sprintf("PEN{Tx:%x Typ:%d NIDH:%x Amount:%s}", p.TxHash[:], p.Type, p.NIDH[:], math.BigForPrint(p.Amount))
}

//
// func (r *VoteResult) Receipt() *RRActReceipt {
// 	bs, _ := json.Marshal(r)
// 	return &RRActReceipt{TxHash: r.TxHash, Status: ReceiptStatusSuccessful, Type: ARCreated, Msg: string(bs)}
// }
//
// func (r *VoteResult) String() string {
// 	if r == nil {
// 		return "VOTER<nil>"
// 	}
// 	return fmt.Sprintf("VOTER{Tx:%x Target:%x TargetIDH:%x}", r.TxHash[:], r.Target[:], r.Target.Hash().Bytes())
// }