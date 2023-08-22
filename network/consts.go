package network

const (
	TimesToRetryConnect   = 10    // connect retry times
	MaxBytesCanBroadcast  = 65536 // the max length of a full broadcast msg
	NumOfFullBroadcast    = 1     // full msg count to broadcast when msg was too large
	RecentReceivePoolSize = 5000  // recent receive msg pool size
	RecentMsgPoolSize     = 200   // recent send msg pool size
	NewWantDetailLockSize = 500   // recent WantDetail msg pool size

	SECLen = 16
	MACLen = 16
)
