package models

import (
	"bytes"
	"fmt"

	"github.com/ThinkiumGroup/go-common/abi"
)

var MCommAbi abi.ABI

const mCommAbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes[]",
				"name": "nodeIds",
				"type": "bytes[]"
			}
		],
		"name": "addNodes",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			},
			{
				"internalType": "uint8",
				"name": "delta",
				"type": "uint8"
			},
			{
				"internalType": "string",
				"name": "errMsg",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes[]",
				"name": "nodeIds",
				"type": "bytes[]"
			}
		],
		"name": "delNodes",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			},
			{
				"internalType": "uint8",
				"name": "delta",
				"type": "uint8"
			},
			{
				"internalType": "string",
				"name": "errMsg",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [],
		"name": "listNodes",
		"outputs": [
			{
				"internalType": "bytes[]",
				"name": "nodeIds",
				"type": "bytes[]"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
`
const (
	MCommAddNode   = "addNodes"
	MCommDelNode   = "delNodes"
	MCommListNodes = "listNodes"
)

func init() {
	InitMCommAbi()
}

func InitMCommAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(mCommAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read mComm abi error: %v", err))
	}
	MCommAbi = a
}
