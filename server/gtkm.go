package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/api"
	cmd2 "github.com/ThinkiumGroup/go-thinkium/cmd"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/dao"
	"github.com/ThinkiumGroup/go-thinkium/ethrpc"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/ThinkiumGroup/go-thinkium/network"
	"github.com/ThinkiumGroup/go-thinkium/tkmrpc"
)

type thinkium struct {
	Dmanager     models.DataManager
	Nmanager     models.NetworkManager
	Cmanager     models.Engine
	Controller   models.Eventer
	RpcServer    *tkmrpc.RPCServer
	EthRpcServer *ethrpc.Servers
	BlockNoticer models.Noticer

	services []common.Service

	status common.ServiceStatus
	lock   sync.Mutex

	Shutdown chan interface{}
}

type runContext struct {
	d *thinkium
	c *config.Config
}

func (c *runContext) NetworkManager() models.NetworkManager {
	return c.d.Nmanager
}

func (c *runContext) DataManager() models.DataManager {
	return c.d.Dmanager
}

func (c *runContext) Engine() models.Engine {
	return c.d.Cmanager
}

func (c *runContext) Eventer() models.Eventer {
	return c.d.Controller
}

func (c *runContext) Noticer() models.Noticer {
	return c.d.BlockNoticer
}

func (c *runContext) Config() *config.Config {
	return c.c
}

var (
	flagConfigPath   string
	flagSetCursorTo  string
	flagGenKey       bool
	serviceInterface = reflect.TypeOf(new(common.Service)).Elem()
)

func init() {
	flag.StringVar(&flagConfigPath, "conf", "./gtkm.yaml", "system config file path")
	flag.StringVar(&flagSetCursorTo, "cursorto", "", "set cursor of chain y to xxxx")
	flag.BoolVar(&flagGenKey, "genkey", false, "generate a key pair")
	flag.Parse()
}

func cmdCursorTo(conf *config.Config) error {
	parts := strings.Split(flagSetCursorTo, ".")
	if len(parts) != 2 {
		return fmt.Errorf("parse error: [%s], should be (chainid).(height)", flagSetCursorTo)
	}
	chainid, err := strconv.Atoi(parts[0])
	if err != nil {
		return err
	}
	height, err := strconv.Atoi(parts[1])
	if err != nil {
		return err
	}

	dbpath := conf.DataConf.GetRealPath(common.ChainID(chainid))
	dbp, err := db.NewLDB(dbpath)
	if err != nil {
		return common.NewDvppError(fmt.Sprintf("creating database at %s error", dbpath), err)
	}
	for dbp != nil && dao.CheckDBInGenerating(dbp) {
		dbp.Close()
		os.RemoveAll(dbpath)
		dbpath = conf.DataConf.GetRealPath(common.ChainID(chainid))
		dbp, err = db.NewLDB(dbpath)
	}
	if err != nil || dbp == nil {
		return common.NewDvppError(fmt.Sprintf("creating database at %s error", dbpath), err)
	}

	return dao.SetCursorManually(dbp, common.ChainID(chainid), common.Height(height))
}

var autoRestart = false
var waitRestart = false

func main() {
	if flagGenKey {
		sk, err := cipher.RealCipher.GenerateKey()
		if err != nil {
			fmt.Printf("generate failed: %v\n", err)
			return
		}
		pk := sk.GetPublicKey()
		fmt.Printf("PrivateKey:\t %x\n", sk.ToBytes())
		fmt.Printf("PublicKey:\t %x\n", pk.ToBytes())
		fmt.Printf("Address:\t %x\n", pk.ToAddress())
		return
	}

	systemsignal := make(chan os.Signal, 1)
	signal.Notify(systemsignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(systemsignal)

	defer checkAutoRestart()

	conf, err := config.LoadConfig(flagConfigPath)
	if err != nil {
		panic("load config file error: " + err.Error())
	}

	// initial log type
	conf.MakeLogTypeMap()

	common.TxCount = conf.TxCount
	common.NetDelay = conf.NetDelay
	if conf.WaitingTime != nil {
		common.WaitingTime = *conf.WaitingTime
	} else {
		common.WaitingTime = consts.DefaultTBFTWaitingTime
	}

	common.StandAlone = conf.StandAlone
	common.NdType = conf.NodeType
	common.ForChain = conf.ForChain
	common.FullData = conf.FullData
	common.SystemNodeID = *conf.Nid
	cipher.SystemPrivKey = conf.PrivKey
	if conf.BlocksInEpoch > 0 {
		common.BlocksInEpoch = conf.BlocksInEpoch
	}
	if conf.EpochsInEra > 0 {
		common.EpochsInEra = conf.EpochsInEra
	}
	if conf.BaseChainID > 0 {
		common.BigChainIDBase = conf.BaseChainID
	}

	// create log file
	log.InitLog(conf.LogPath, conf.Nid[:])
	log.Warnf("starting THINKIUM by EpochLength:%d EpochInEra:%d BaseChainID:%d",
		common.BlocksInEpoch, common.EpochsInEra, common.BigChainIDBase)
	log.Warnf("configuration: %+v", conf)
	// log.Warnf("IsCompatible()=%t", conf.IsCompatible())

	if len(flagSetCursorTo) > 0 {
		// If this command parameter is set, the subsequent startup process will not be started
		if err := cmdCursorTo(conf); err != nil {
			log.Errorf("set cursor to failed: %v", err)
		}
		return
	}

	tkm, err := NewTkm(conf)
	if err != nil {
		log.Error("thinkium create error: ", err)
		os.Exit(3)
	}

	if err := tkm.Init(); err != nil {
		log.Error("thinkium init error: ", err)
		os.Exit(4)
	}

	if err := tkm.Start(); err != nil {
		log.Error("thinkium start error: ", err)
		os.Exit(5)
	}

	if err := tkm.Cmanager.ReviveMainChain(); err != nil {
		log.Error("thinkium revive working chains error: ", err)
		os.Exit(6)
	}

	defer func() {
		_ = tkm.Close()
	}()

	runCtx := &runContext{d: tkm, c: conf}

	// The length is 1, which solves the problem that the processor of channel cannot be closed after being killed
	cmd := make(chan *string, 1)
	defer close(cmd)

	// start to read stdin to send msg
	inputreader := bufio.NewReader(os.Stdin)
	go func() {
		for {
			input, _, _ := inputreader.ReadLine()
			// if err != nil {
			// 	log.Error("read line error:", err)
			// }
			s := string(input)
			if s != "" {
				cmd <- &s
			}
		}
	}()

outer1:
	for {
		select {
		case <-tkm.Shutdown:
			log.Warn("GOT A SHUTDOWN SIGNAL, SHUTTING DOWN.")
			break outer1
		case ss := <-systemsignal:
			log.Warn("GOT A SYSTEM SIGNAL[", ss, "], SHUTTING DOWN.")
			if ss == os.Signal(syscall.SIGUSR1) {
				autoRestart = true
			}
			if ss == os.Signal(syscall.SIGUSR2) {
				autoRestart = true
				waitRestart = true
			}
			break outer1
		case cc := <-cmd:
			if exist, err := cmd2.AllCommands.Run(*cc, runCtx); err != nil {
				log.Errorf("Cmd Error: %v", err)
				// } else if !exist {
			} else if !exist {
				log.Warnf("Cmd %s not found", *cc)
			} else {
				// nothing to do
			}
		}
	}

	log.Infof("exiting thinkium")
	tkm.Controller.PrintCounts()
	tkm.Nmanager.Status()
}

func checkAutoRestart() {
	if !autoRestart {
		return
	}
	if waitRestart {
		// wait resource release
		time.Sleep(time.Minute)
	}
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	err = syscall.Exec(exe, os.Args, os.Environ())
	if err != nil {
		log.Errorf("[RESTART] start process error %v", err)
	}
}

func NewTkm(conf *config.Config) (*thinkium, error) {
	log.Infof("creating THINKIUM version:%s nodeId:%s", consts.Version, hex.EncodeToString(conf.Nid[:]))
	tkm := &thinkium{}
	tkm.status = common.SSCreated
	tkm.Shutdown = make(chan interface{})

	models.VMPlugin = common.InitShareObject("./vm.so")
	dataPlug := common.InitShareObject("./data.so")
	eventerPlug := common.InitShareObject("./sysq.so")
	enginePlug := common.InitShareObject("./consensus.so")

	// Bucket size = number of chains that can participate in consensus * 2 (assuming there are parent chains) + 1 (main chain)
	barrelSize := len(conf.Chains)*2 + 1
	eventer := models.NewEventer(eventerPlug, 100000, barrelSize, 10, func() {
		log.Warn("****************stopping system****************")
		tkm.Shutdown <- 1
	}, models.LocateIsInCommittee(enginePlug))
	dmanager, err := models.NewDManager(dataPlug, conf.DataConf.Path, eventer)
	if err != nil {
		log.Error("create data manager error:", err)
		return nil, err
	}
	dmanager.SetChainStructs(conf)

	nmanager, err := network.NewManager(conf.NetworkConf.P2Ps.GetPortRange(), eventer)
	if err != nil {
		log.Error("create network manager error:", err)
		return nil, err
	}
	nmanager.SetDataManager(dmanager)

	engine := models.NewConsensusEngine(enginePlug, eventer, nmanager, dmanager, conf)

	eventer.SetEngine(engine)
	eventer.SetDataManager(dmanager)
	eventer.SetNetworkManager(nmanager)

	var rpcsrv *tkmrpc.RPCServer
	rpcsrv, err = tkmrpc.NewRPCServer(conf.NetworkConf.RPCs.GetRpcEndpoint(), nmanager, dmanager, engine, eventer)

	tkm.Nmanager = nmanager
	tkm.Dmanager = dmanager
	tkm.Cmanager = engine
	tkm.Controller = eventer
	tkm.RpcServer = rpcsrv
	ethrpcconfig := tkm.filterethrpcconfig(conf.NetworkConf.ETHRPC)
	ethservs := ethrpc.NewRPCServers()
	for _, item := range ethrpcconfig {
		ethrpcsrv, errethrpc := ethrpc.NewServer(item.GetRpcEndpoint())
		if errethrpc != nil {
			panic(err)
		}
		rpcAPI := []ethrpc.API{
			{
				Namespace: "eth",
				Public:    true,
				Service:   api.NewPublicBlockChainAPI(nmanager, dmanager, engine, eventer),
				Version:   "1.0",
			},
			{
				Namespace: "web3",
				Public:    true,
				Service:   &api.PublicWeb3API{},
				Version:   "1.0",
			},
			{
				Namespace: "net",
				Public:    true,
				Service:   api.NewPublicNetAPI(),
				Version:   "1.0",
			},
		}
		if err = ethrpc.RegisterApis(rpcAPI, item.GetChainID(), []string{"eth", "web3", "net"}, ethrpcsrv, false); err != nil {
			panic(err)
		}
		ethservs.AddServe(ethrpcsrv)
	}

	// }

	if conf.NetworkConf.Pprof != nil && len(*conf.NetworkConf.Pprof) > 0 {
		log.Infof("[PPROF] starting pprof http server [%s]", *conf.NetworkConf.Pprof)
		go func() {
			_ = http.ListenAndServe(*conf.NetworkConf.Pprof, nil)
		}()
	}

	tkm.EthRpcServer = ethservs
	// if tkm.Dmanager.IsDataNode() || tkm.Dmanager.IsMemoNode() {
	// 	models.ETHSigner = models.NewLondonSigner(new(big.Int).SetUint64(uint64(tkm.Dmanager.DataNodeOf() + common.BigChainIDBase)))
	// }
	var noticer models.Noticer
	if conf.Noticer != nil {
		log.Debugf("load NOTICE with config: %v", conf.Noticer)
		noticer = models.LoadNoticer("./notice.so", conf.Noticer.QueueSize, *conf.Noticer.ChainID,
			conf.Noticer.RedisAddr, conf.Noticer.RedisPwd, conf.Noticer.RedisDB, conf.Noticer.RedisQueue)
	} else {
		log.Debug("no NOTICE")
		noticer = nil
		// log.Debug("load NOTICE with default configs")
		// noticer = models.LoadNoticer("./notice.so", 0, *conf.Noticer.ChainID, config.NoticeDefaultAddr,
		// 	config.NoticeDefaultPwd, config.NoticeDefaultDB, config.NoticeDefaultQueue)
	}
	tkm.BlockNoticer = noticer
	models.SystemNoticer = noticer
	models.SystemConfig = conf

	return tkm, nil
}

func (d *thinkium) filterethrpcconfig(ethconfig []config.ETHRPCConfig) []config.ETHRPCConfig {
	if !d.Dmanager.IsDataOrMemo() {
		return ethconfig
	}
	for _, item := range ethconfig {
		if (item.ChainID == nil || (item.ChainID != nil && *item.ChainID == d.Dmanager.DataOrMemoOf())) && item.ETHRPCServer.Address != "" {
			cid := d.Dmanager.DataOrMemoOf()
			return []config.ETHRPCConfig{
				{
					ChainID:      &cid,
					ETHRPCServer: item.ETHRPCServer,
				},
			}
		}
	}

	return nil
}

func (d *thinkium) String() string {
	dataOf := common.NilChainID
	if d != nil && d.Dmanager != nil && d.Dmanager.IsDataNode() {
		dataOf = d.Dmanager.DataNodeOf()
	}
	if !dataOf.IsNil() {
		return fmt.Sprintf("THINKIUM{%s, DataOf:%d}", common.SystemNodeID, dataOf)
	}
	return fmt.Sprintf("THINKIUM{%s}", common.SystemNodeID)
}

func (d *thinkium) findAllServices() {
	if d.services != nil {
		return
	}

	d.services = make([]common.Service, 0)

	value := reflect.ValueOf(d).Elem()
	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Implements(serviceInterface) {
			if value.FieldByName(f.Name).IsNil() {
				continue
			}
			service := value.FieldByName(f.Name).Interface().(common.Service)
			if service != nil {
				log.Debug("service found: (", f.Name, ",", f.Type, ")")
				d.services = append(d.services, service)
			}
		}
	}
}

func (d *thinkium) Init() error {
	d.lock.Lock()
	defer d.lock.Unlock()
	if err := d.status.CheckInit(); err != nil {
		return err
	}

	d.findAllServices()

	for _, service := range d.services {
		if service == nil {
			continue
		}
		if err := service.Init(); err != nil {
			log.Error(service.String(), "initialize error:", err)
			return err
		}
	}

	log.Info("thinkium initialized")
	return nil
}

func (d *thinkium) Start() error {
	d.lock.Lock()
	defer d.lock.Unlock()
	if err := d.status.CheckStart(); err != nil {
		return err
	}

	for _, service := range d.services {
		if err := service.Start(); err != nil {
			log.Error(service.String(), "start error:", err)
			return err
		}
	}

	log.Infof("%s started", d)
	return nil
}

func (d *thinkium) Close() error {
	d.lock.Lock()
	defer d.lock.Unlock()
	if err := d.status.CheckStop(); err != nil {
		return err
	}

	for _, service := range d.services {
		_ = service.Close()
	}

	log.Infof("%s stopped", d)
	return nil
}
