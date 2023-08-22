package models

import (
	"bytes"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/abi"
)

var (
	SRAbi                  abi.ABI
	SRRewardDetailEventSig common.Hash
)

const (
	SRShareRewardName  = "shareReward"
	SRRewardDetailName = "RewardDetail"

	scsrAbiJson string = `
[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "string",
				"name": "rewardName",
				"type": "string"
			},{
				"indexed": false,
				"internalType": "address",
				"name": "addr",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "deposit",
				"type": "uint256"
			}
		],
		"name": "RewardDetail",
		"type": "event"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "string",
				"name": "chargeRatio",
				"type": "string"
			},
			{
				"internalType": "bytes",
				"name": "settleRoot",
				"type": "bytes"
			},
			{
				"internalType": "bytes",
				"name": "poolAddress",
				"type": "bytes"
			}
		],
		"name": "shareReward",
		"outputs": [
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			}
		],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	}
]
`
)

func init() {
	InitSRAbi()
}

func InitSRAbi() {
	a, err := abi.JSON(bytes.NewReader([]byte(scsrAbiJson)))
	if err != nil {
		panic(fmt.Sprintf("read share reward abi error: %v", err))
	}
	SRAbi = a
	// rewardDetailSig := SRAbi.Events[SRRewardDetailName].Sig()
	// SRRewardDetailEventSig = common.Hash256([]byte(rewardDetailSig))
	SRRewardDetailEventSig = SRAbi.Events[SRRewardDetailName].ID
}
