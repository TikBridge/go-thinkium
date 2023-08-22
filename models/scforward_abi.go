package models

import (
	"bytes"
	"fmt"

	"github.com/ThinkiumGroup/go-common/abi"
)

const scForwardAbiJson = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes",
				"name": "principal",
				"type": "bytes"
			}
		],
		"name": "forward",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "outOfPrincipal",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`

const (
	ForwarderForwardMName = "forward"
)

var ForwarderAbi abi.ABI

func init() {
	InitForwarderAbi()
}

func InitForwarderAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(scForwardAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read forwarder abi error: %v", err))
	}
	ForwarderAbi = a
}
