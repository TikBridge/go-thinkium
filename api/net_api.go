package api

import (
	"fmt"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type PublicNetAPI struct {
	chainID common.ChainID
}

func NewPublicNetAPI() *PublicNetAPI {
	return &PublicNetAPI{}
}

func (s *PublicNetAPI) Listening() bool {
	return true
}

func (s *PublicNetAPI) Version() string {
	return fmt.Sprintf("%d", models.ETHChainID(s.chainID, models.TxVersion))
}

func (s *PublicNetAPI) SetChainID(chainID common.ChainID) {
	s.chainID = chainID
}
