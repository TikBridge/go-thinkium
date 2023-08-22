package models

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func TestShowScMcMethods(t *testing.T) {
	for name, m := range MChainsAbi.Methods {
		t.Logf("%s ID is: %x", name, m.ID)
	}
}

func TestMChainCreateParams(t *testing.T) {
	boot1 := MChainBootNode{[]byte("bootnode1"), "1.1.1.1", 1111, 1111, 1111, 1111, 1111, 1111}
	boot2 := MChainBootNode{[]byte("bootnode2"), "1.1.1.2", 1112, 1112, 1112, 1112, 1112, 1112}
	req := &MChainInfoInput{
		ID:           1,
		ParentChain:  0,
		CoinID:       0,
		CoinName:     "",
		Admins:       [][]byte{[]byte("admin1"), []byte("admin2")},
		BootNodes:    []MChainBootNode{boot1, boot2},
		ElectionType: "VRF",
		ChainVersion: "",
		GenesisDatas: [][]byte{[]byte("datanodeid1"), []byte("datanodeid2")},
		RRProofs:     [][]byte{[]byte("datanodeid1proofs"), []byte("datanodeid2proofs")},
		Attrs:        []string{"POC", "REWARD"},
	}
	bs, err := MChainsAbi.PackInputWithoutID("createChain", req)
	if err != nil {
		t.Errorf("pack error: %v", err)
	} else {
		t.Logf("packed: %x", bs)
	}

	params := new(struct {
		Info MChainInfoInput `abi:"info"`
	})
	if err := MChainsAbi.UnpackInput(params, MChainCreateChain, bs); err != nil {
		t.Errorf("unpack error: %v", err)
	} else {
		t.Logf("unpacked: %+v", params)
	}
}

func TestMChainGetChain(t *testing.T) {
	boot1 := MChainBootNode{[]byte("bootnode1"), "1.1.1.1", 1111, 1111, 1111, 1111, 1111, 1111}
	boot2 := MChainBootNode{[]byte("bootnode2"), "1.1.1.2", 1112, 1112, 1112, 1112, 1112, 1112}
	resp := MChainInfoOutput{
		ID:             1,
		ParentChain:    0,
		Mode:           common.Branch.String(),
		CoinID:         0,
		CoinName:       "",
		Admins:         [][]byte{[]byte("admin1"), []byte("admin2")},
		GenesisCommIds: [][]byte{[]byte("comm1"), []byte("comm2")},
		BootNodes:      []MChainBootNode{boot1, boot2},
		ElectionType:   "MANAGED",
		ChainVersion:   "chainversion",
		GenesisDatas:   [][]byte{[]byte("gendata1"), []byte("gendata2")},
		DataNodeIds:    [][]byte{[]byte("datanodeid1"), []byte("datanodeid2")},
		Attrs:          []string{"POC", "REWARD"},
	}

	bs, err := MChainsAbi.PackReturns("getChainInfo", true, resp)
	if err != nil {
		t.Errorf("pack output error: %v", err)
	} else {
		t.Logf("output packed: %x", bs)
	}

	output := new(struct {
		Exist           bool             `abi:"exist"`
		ChainInfoOutput MChainInfoOutput `abi:"info"`
	})
	if err := MChainsAbi.UnpackReturns(output, "getChainInfo", bs); err != nil {
		t.Errorf("unpack output error: %v", err)
	} else {
		t.Logf("output unpacked: %+v", output)
	}

	if reflect.DeepEqual(resp, output.ChainInfoOutput) {
		t.Logf("pack check")
	} else {
		t.Errorf("pack failed: %+v -> %+v", resp, output.ChainInfoOutput)
	}
}

// 因为输入就是错的，所以使用fmt.Printf
func TestUnmarshalInput(t *testing.T) {
	// bs, _ := hex.DecodeString("24c505890000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000380000000000000000000000000000000000000000000000000000000000000056000000000000000000000000000000000000000000000000000000000000005a000000000000000000000000000000000000000000000000000000000000005c00000000000000000000000000000000000000000000000000000000000000660000000000000000000000000000000000000000000000000000000000000086000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000004104c2154e245d5726e5c54498c821a7aa96966b05e8d829927b9e55ca98b565dc9c41433e8afc90d06ea0ff4d384d25d0d1307887dfbaaf002c78bdf3d0a8529027000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041047cecfd2e39942ebdb963c6fd6aa24158ab3798c9f95dd739006455269c338106815b5a5bc9601aa997f17307fabbc13313e6c85081ed7a4d3f52aab9c16a732d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041042554d0a87632f638dab13bdbfbd2785bc717ab18e1c1c009859fb4550b45bfa4e59e32a553686f906b9e892d7f1780e702af7a5a23d608938082d138e8981f9e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000275d000000000000000000000000000000000000000000000000000000000000275e000000000000000000000000000000000000000000000000000000000000275f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000056050000000000000000000000000000000000000000000000000000000000000040a9d8dd87c9ece1787cbb16ba179df6d1d4b29580c03ae1da6e4634b154f8e2feb052fc1c07ca1e362f9b3e2b5f43822df9dd6578e782701de83afeca91a7b45300000000000000000000000000000000000000000000000000000000000000093132372e302e302e310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000356524600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040a9d8dd87c9ece1787cbb16ba179df6d1d4b29580c03ae1da6e4634b154f8e2feb052fc1c07ca1e362f9b3e2b5f43822df9dd6578e782701de83afeca91a7b453000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001529299c0a26fb15b0081752ee9d6133aaa894464990c7d15e539fc11507d12d4e43617b22b018000b10a2a5a058fc295ed00000080d48f08a7d174a90c2301eb3343e9f98433a148414c8093941093a1a0df6fb15b0081752ee9d6133aaa894464990c7d15e539fc11507d12d4e43617b2c2000080809402934080c21c00808100020dd54d01d1fd50209f74a6899934405bc1835346c41d9d05adb1b4e3a89a9541ade1a72e3943daae5eb169956ce2cf89a5a46d5f6736ae1b383492a926d2b38e0000940a934080c2fe5f80810004049c4bb79f1478ffb1b2fe73fe97aacf202535e250b5a084ad289831deb65fb9af5e60ad24ada1bd45e9d6ee756b7d5a1a34a79b4a7e6172feb44de176b48900389c224a0c74fe00a8b391575554ec3356c3d3cdd731537ff36521fbb3390e8ef9c150e0914d0b39a2dfb0f6b3cc23f8ce6f0fe9012456c8c8269d315226d56800010900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	// input := new(MChainInfoInput)
	// if err := MChainsAbi.UnpackInput(input, MChainCreateChain, bs); err != nil {
	// 	t.Errorf("unpack error: %v", err)
	// } else {
	// 	t.Logf("unpacked: %+v", input)
	// 	if len(input.GenesisDatas) != len(input.RRProofs) {
	// 		fmt.Printf("genesisDatas:%d, RRProofs:%d", len(input.GenesisDatas), len(input.RRProofs))
	// 	} else {
	// 		for _, proofbytes := range input.RRProofs {
	// 			proof := new(RRProofs)
	// 			if err := rtl.Unmarshal(proofbytes, proof); err != nil {
	// 				fmt.Printf("unmarshal proof error: %v", err)
	// 			} else {
	// 				fmt.Printf("unmarshaled: %s", proof)
	// 			}
	// 		}
	// 	}
	// }
}

func TestMChainAddBootNode(t *testing.T) {
	bn := MChainBootNode{[]byte("bootnode1"), "1.1.1.1", 1111, 1111, 1111, 1111, 1111, 1111}
	bs, err := MChainsAbi.PackInputWithoutID(MChainAddBootNode, uint32(0), bn)
	if err != nil {
		t.Errorf("pack error: %v", err)
	} else {
		t.Logf("packed: %x", bs)
	}

	params := new(struct {
		Id uint32         `abi:"id"`
		Bn MChainBootNode `abi:"bn"`
	})
	if err := MChainsAbi.UnpackInput(params, MChainAddBootNode, bs); err != nil {
		t.Errorf("unpack error: %v", err)
	} else {
		t.Logf("unpacked: %+v", params)
	}
}

func TestMChainUnmarshalReturns(t *testing.T) {
	{
		bs, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000766164642064617461206e6f6465206572726f723a2076657269667920525250726f6f6673206f66204e6f646549443a353062386437336234635f37205252526f6f743a33333437636261306661206661696c65643a20636865636b2052524e65787450726f6f6673206d697373696e672070726f6f6600000000000000000000")
		output := new(struct {
			Status bool   `abi:"status"`
			ErrMsg string `abi:"errMsg"`
		})
		if err := MChainsAbi.UnpackReturns(output, MChainAddDataNode, bs); err != nil {
			t.Fatalf("unmarshal returns failed: %v", err)
		} else {
			t.Logf("status: %t, errMsg: %s", output.Status, output.ErrMsg)
		}
	}
	{
		bs, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000746164642064617461206e6f6465206572726f723a2076657269667920525250726f6f6673206f66204e6f646549443a35306238643733623463205252526f6f743a33333437636261306661206661696c65643a20636865636b2052524e65787450726f6f6673206d697373696e672070726f6f66000000000000000000000000")
		output := new(struct {
			Status bool   `abi:"status"`
			ErrMsg string `abi:"errMsg"`
		})
		if err := MChainsAbi.UnpackReturns(output, MChainAddDataNode, bs); err != nil {
			t.Fatalf("unmarshal returns failed: %v", err)
		} else {
			t.Logf("status: %t, errMsg: %s", output.Status, output.ErrMsg)
		}
	}
}

func TestMChainAddDataNode(t *testing.T) {
	{
		bs, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000004050b8d73b4cc9d172f20ef1474a44a3aa7760789ea1bf72a213a0187929b1b0d8c61f6cdbb49f57dfd43b9d7f214dfe22ff2f2d6ee0d3cd6b0ea7e07a66ccb12700000000000000000000000000000000000000000000000000000000000001eb9290c0a7ce254a7429737aaf4801164eea5715a7bab7b2b097e37caaede4f687ed037aa3ec428d018000b10a69e10de76676d080000080d4d8754d7d4e4c720127b8a6af8cf40856347d40ea800200008080808094941093a1bede254a7429737aaf4801164eea5715a7bab7b2b097e37caaede4f687ed037ac200008080940c934080c2001a80810002c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4707aef3e6c902c6372450e74f2e8d5bf163f375d6a8fec404db804d185c98c6fc50001029407934080c2aedf8081000478e260dc64ee2de36798a705112e045d4824090f21862ba6f6b105c575d59548544536a154eb9d424b3457ef1af46ff45ea569f1b703bf26454fb932477dd8966e8a6b8280f7b2647736727717a58800b5ada268a42588e73a80c3127eaa0690fd6e805529c3ae9ce0b187ee0f0abeeb3617844d3c39de9c4424fd8d2a18da54000104940a934080c2ffff80810004829ba61a322ffe2d1c67335d1c117ec0197ea89e3ce2abb6f58b53edd651fc44d1eb23f8582cd93e95898d886d83919ecc429d34e77c47039d8982248b8e3d99dc654133a0fab12e402036f5eafbcdfdec4e3973dbf6033bdbb876d20f12bb54114c811214a275c4daac55d1684f486efb7f213c65a3e79be89d8affb503997700010a000000000000000000000000000000000000000000")
		param := new(struct {
			Id    uint32 `abi:"id"`
			NID   []byte `abi:"nodeId"`
			Proof []byte `abi:"rrProof"`
		})
		if err := MChainsAbi.UnpackInput(param, MChainAddDataNode, bs); err != nil {
			t.Fatalf("unpack input failed: %v", err)
		} else {
			rrProof := new(RRProofs)
			if errr := rtl.Unmarshal(param.Proof, rrProof); errr != nil {
				t.Fatalf("unmarshal proof failed: %v", errr)
			}
			t.Logf("id: %d\nNID: %x\nProof: %x\n%s", param.Id, param.NID, param.Proof, rrProof)
		}
	}
	{
		bs, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000746164642064617461206e6f6465206572726f723a2076657269667920525250726f6f6673206f66204e6f646549443a35306238643733623463205252526f6f743a36326231306264346438206661696c65643a20636865636b2052524e65787450726f6f6673206d697373696e672070726f6f66000000000000000000000000")
		output := new(struct {
			Status bool   `abi:"status"`
			ErrMsg string `abi:"errMsg"`
		})
		if err := MChainsAbi.UnpackReturns(output, MChainAddDataNode, bs); err != nil {
			t.Fatalf("unmarshal returns failed: %v", err)
		} else {
			t.Logf("status: %t, errMsg: %s", output.Status, output.ErrMsg)
		}
	}
}