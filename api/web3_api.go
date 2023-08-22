package api

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/consts"
)

// PublicWeb3API offers helper utils
type PublicWeb3API struct{}

// ClientVersion returns the node name
func (api *PublicWeb3API) ClientVersion() string {
	return consts.Version.String()
	// return strconv.FormatUint(consts.Version, 10)
}

func (api *PublicWeb3API) SetChainID(chainID common.ChainID) {}
