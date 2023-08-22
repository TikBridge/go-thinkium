package models

import (
	"encoding/hex"
	"errors"

	cr "github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

var (
	ErrSignatureVerifyFailed = errors.New("signature verify failed")

	EmptyPublicKey = make([]byte, LengthOfPublicKey)
	EmptySignature = make([]byte, LengthOfSignature)
)

func PubKeyCanRecover() bool {
	return cr.RealCipher.Name() == "secp256k1_sha3"
}

func PrivateToPublicSlice(priv []byte) ([]byte, error) {
	eccpriv, err := cr.RealCipher.BytesToPriv(priv)
	if err != nil {
		return nil, err
	}
	return eccpriv.GetPublicKey().ToBytes(), nil
}

func PubToNodeID(pub []byte) (common.NodeID, error) {
	nidbs, err := cr.RealCipher.PubToNodeIdBytes(pub)
	if err != nil {
		return common.NodeID{}, err
	}
	return common.BytesToNodeID(nidbs), nil
}

// sign msg
func SignMsg(msg interface{}) (pub, sig []byte, err error) {
	pub = cr.SystemPrivKey.GetPublicKey().ToBytes()
	mh, err := common.HashObject(msg)
	if err != nil {
		return nil, nil, err
	}
	sig, err = cr.RealCipher.Sign(cr.RealCipher.PrivToBytes(cr.SystemPrivKey), mh)
	return pub, sig, err
}

// sign msg
func SignHash(hash []byte) (pub, sig []byte, err error) {
	pub = cr.SystemPrivKey.GetPublicKey().ToBytes()
	sig, err = cr.RealCipher.Sign(cr.RealCipher.PrivToBytes(cr.SystemPrivKey), hash)
	return pub, sig, err
}

func VerifyMsgWithPub(v interface{}, pub, sig []byte) (bool, []byte) {
	if sig == nil {
		return false, pub
	}
	mh, err := common.HashObject(v)
	if err != nil {
		log.Errorf("verify msg %v", err)
		return false, pub
	}
	if pub == nil {
		if PubKeyCanRecover() {
			pub, err = cr.RealCipher.RecoverPub(mh, sig)
			if err != nil || pub == nil {
				return false, nil
			}
		} else {
			return false, nil
		}
	}
	return cr.RealCipher.Verify(pub, mh, sig), pub
}

// verify msg signature
func VerifyMsg(v interface{}, pub, sig []byte) bool {
	ok, _ := VerifyMsgWithPub(v, pub, sig)
	return ok
}

func VerifyHashWithPub(hash, pub, sig []byte) (bool, []byte) {
	if sig == nil || hash == nil {
		return false, nil
	}
	if len(pub) == 0 {
		if PubKeyCanRecover() {
			p, err := cr.RealCipher.RecoverPub(hash[:], sig)
			if err != nil || p == nil {
				return false, nil
			}
			pub = p
		} else {
			return false, nil
		}
	}
	return cr.RealCipher.Verify(pub, hash, sig), pub
}

// VerifyHash verify msg hash signature
func VerifyHash(hash, pub, sig []byte) bool {
	ok, _ := VerifyHashWithPub(hash, pub, sig)
	return ok
}

func HexToPrivKey(h string) (cr.ECCPrivateKey, error) {
	bs, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return cr.RealCipher.BytesToPriv(bs)
}
