package ethrpc

import (
	"context"

	"github.com/ThinkiumGroup/go-common"
)

// ServerCodec implements reading, parsing and writing RPC messages for the server side of
// a RPC session. Implementations must be go-routine safe since the codec can be called in
// multiple go-routines concurrently.

type ServerCodec interface {
	readBatch() (msgs []*jsonrpcMessage, isBatch bool, err error)
	close()
	jsonWriter
}

// jsonWriter can write JSON messages to its underlying connection.
// Implementations must be safe for concurrent use.
type jsonWriter interface {
	writeJSON(context.Context, interface{}) error
	// Closed returns a channel which is closed when the connection is closed.
	closed() <-chan interface{}
	// RemoteAddr returns the peer address of the connection.
	remoteAddr() string
}

// API describes the set of methods offered over the RPC interface
type API struct {
	Namespace string     // namespace under which the rpc methods of Service are exposed
	Version   string     // api version for DApp's
	Service   ApiService // receiver instance which holds the methods
	Public    bool       // indication if the methods must be considered safe for public use
}

type ApiService interface {
	SetChainID(chainid common.ChainID)
}

func (a *API) SetServiceChainID(chainid common.ChainID) {
	a.Service.SetChainID(chainid)
}
