package config

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

var (
	SystemStarterPrivate cipher.ECCPrivateKey
	SystemStarterPublic  cipher.ECCPublicKey
	SystemStarterPK      []byte
)

type Starter struct {
	SKString string `yaml:"sk" json:"sk"`
	PKString string `yaml:"pk" json:"pk"`
}

func (s *Starter) Validate() error {
	if s == nil {
		return nil
	}
	SystemStarterPrivate = nil
	SystemStarterPublic = nil

	var ecsk cipher.ECCPrivateKey
	var ecpk cipher.ECCPublicKey

	if len(s.SKString) > 0 {
		skbytes, err := hex.DecodeString(s.SKString)
		if err == nil {
			ecsk, err = cipher.RealCipher.BytesToPriv(skbytes)
			if err != nil {
				log.Warnf("[CONFIG] starter private key parse error: %v, ignored", err)
				ecsk = nil
			}
		} else {
			log.Warnf("[CONFIG] starter private key hex error: %v, ignored", err)
		}
	}

	pkstring := s.PKString
	if len(pkstring) == 0 && ecsk == nil {
		pkstring = common.DefaultStarterPK
	}
	pkbytes, err := hex.DecodeString(pkstring)
	if err == nil {
		ecpk, err = cipher.RealCipher.BytesToPub(pkbytes)
		if err != nil {
			if ecsk == nil {
				log.Warnf("[CONFIG] start public key parse error: %v, ignored", err)
			}
			ecpk = nil
		}
	} else {
		if ecsk == nil {
			log.Warnf("[CONFIG] starter public key hex error: %v, ignored", err)
		}
	}

	if ecsk == nil && ecpk == nil {
		return errors.New("starter sk and pk are both not set")
	}

	if ecsk != nil && ecpk != nil {
		kb := ecsk.GetPublicKey().ToBytes()
		if !bytes.Equal(kb, ecpk.ToBytes()) {
			return errors.New("starter private key and public key not match")
		}
	}

	SystemStarterPrivate = ecsk
	SystemStarterPublic = ecpk

	if SystemStarterPublic == nil {
		SystemStarterPublic = SystemStarterPrivate.GetPublicKey()
	}
	SystemStarterPK = SystemStarterPublic.ToBytes()
	if SystemStarterPrivate != nil {
		log.Infof("[CONFIG] I'm a STARTER with public key: %x", SystemStarterPK)
	} else {
		log.Infof("[CONFIG] I have a starter public key: %x", SystemStarterPK)
	}

	return nil
}
