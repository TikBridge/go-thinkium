package ethrpc

import (
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

// RegisterApis checks the given modules' availability, generates an allowlist based on the allowed modules,
// and then registers all of the APIs exposed by the services.
func RegisterApis(apis []API, chainID common.ChainID, modules []string, srv *Server, exposeAll bool) error {
	allowList := make(map[string]bool)
	for _, module := range modules {
		allowList[module] = true
	}
	// Register all the APIs exposed by the services
	for _, api := range apis {
		api.SetServiceChainID(chainID)
		if exposeAll || allowList[api.Namespace] || (len(allowList) == 0 && api.Public) {
			if err := srv.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
		}
	}
	if config.IsLogOn(config.NetLog) {
		log.Infof("[ETHRPC] %s (all:%t) of ChainID:%d registered to %s", modules, exposeAll, chainID, srv)
	}
	return nil
}
