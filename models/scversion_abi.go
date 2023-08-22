package models

import (
	"bytes"
	"fmt"

	"github.com/ThinkiumGroup/go-common/abi"
)

var VersionAbi abi.ABI

const versionAbiJson string = `
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint64",
				"name": "version",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "beginning",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "deadline",
				"type": "uint64"
			},
			{
				"internalType": "bytes",
				"name": "sum",
				"type": "bytes"
			},
			{
				"internalType": "string",
				"name": "url",
				"type": "string"
			}
		],
		"name": "updateVersion",
		"outputs": [
			{
				"internalType": "bool",
				"name": "success",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [],
		"name": "getVersion",
		"outputs": [
			{
				"internalType": "uint64",
				"name": "version",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "beginning",
				"type": "uint64"
			},
			{
				"internalType": "uint64",
				"name": "deadline",
				"type": "uint64"
			},
			{
				"internalType": "bytes",
				"name": "sum",
				"type": "bytes"
			},
			{
				"internalType": "string",
				"name": "url",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`

const (
	UpdateVersionName = "updateVersion"
	GetVersionName    = "getVersion"
)

func init() {
	InitVersionAbi()
}

func InitVersionAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(versionAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read version abi error: %v", err))
	}
	VersionAbi = a
}
