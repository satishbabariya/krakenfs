package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin"
	"go.uber.org/zap"

	"github.com/uber/krakenfs/lib/filesystem"
	"github.com/uber/krakenfs/lib/security"
	"github.com/uber/krakenfs/lib/sync"
	"github.com/uber/krakenfs/lib/volume"
	"github.com/uber/krakenfs/utils/configutil"
	"github.com/uber/krakenfs/utils/log"
)

// Config defines the complete KrakenFS agent configuration.
type Config struct {
	Log        log.Config              `yaml:"log"`
	Filesystem filesystem.Config       `yaml:"filesystem"`
	Sync       sync.Config             `yaml:"sync"`
	Volume     volume.Config           `yaml:"volume"`
	Security   security.SecurityConfig `yaml:"security"`
}

// Agent represents the complete KrakenFS agent.
type Agent struct {
	config          Config
	logger          *zap.Logger
	fsWatcher       *filesystem.Watcher
	syncEngine      *sync.Engine
	volumeDriver    *volume.Driver
	volumePlugin    *volume.Plugin
	securityManager *security.SecurityManager
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewAgent creates a new KrakenFS agent.
func NewAgent(config Config, logger *zap.Logger) (*Agent, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize file system watcher
	fsWatcher, err := filesystem.NewWatcher(config.Filesystem, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create file system watcher: %s", err)
	}

	// Initialize sync engine
	syncEngine, err := sync.NewEngine(config.Sync, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create sync engine: %s", err)
	}

	// Initialize volume driver
	volumeDriver, err := volume.NewDriver(config.Volume, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create volume driver: %s", err)
	}

	// Initialize volume plugin
	volumePlugin := volume.NewPlugin(volumeDriver, logger)

	// Initialize security manager
	securityManager, err := security.NewSecurityManager(config.Security, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create security manager: %s", err)
	}

	agent := &Agent{
		config:          config,
		logger:          logger,
		fsWatcher:       fsWatcher,
		syncEngine:      syncEngine,
		volumeDriver:    volumeDriver,
		volumePlugin:    volumePlugin,
		securityManager: securityManager,
		ctx:             ctx,
		cancel:          cancel,
	}

	return agent, nil
}

// Start starts the KrakenFS agent.
func (a *Agent) Start() error {
	a.logger.Info("Starting KrakenFS agent...")

	// Start file system watcher
	if err := a.fsWatcher.Start(); err != nil {
		return fmt.Errorf("start file system watcher: %s", err)
	}

	// Start sync engine
	if err := a.syncEngine.Start(); err != nil {
		return fmt.Errorf("start sync engine: %s", err)
	}

	// Start volume driver
	if err := a.volumeDriver.Start(); err != nil {
		return fmt.Errorf("start volume driver: %s", err)
	}

	// Start event processing
	go a.processEvents()

	// Start health monitoring
	go a.monitorHealth()

	a.logger.Info("KrakenFS agent started successfully")
	return nil
}

// Stop stops the KrakenFS agent.
func (a *Agent) Stop() {
	a.logger.Info("Stopping KrakenFS agent...")

	a.cancel()

	// Stop components gracefully
	a.fsWatcher.Stop()
	a.syncEngine.Stop()
	a.volumeDriver.Stop()
	a.securityManager.Close()

	a.logger.Info("KrakenFS agent stopped")
}

// processEvents processes file system events and syncs them.
func (a *Agent) processEvents() {
	for {
		select {
		case event := <-a.fsWatcher.Events():
			a.logger.Info("Processing file event",
				zap.String("path", event.Path),
				zap.String("operation", event.Operation.String()),
				zap.String("node_id", event.NodeID))

			// Process event in sync engine
			a.syncEngine.ProcessEvent(event)

		case <-a.ctx.Done():
			return
		}
	}
}

// monitorHealth monitors the health of all components.
func (a *Agent) monitorHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.logger.Info("Health check - all components running")
		case <-a.ctx.Done():
			return
		}
	}
}

// HandlePluginRequest handles Docker volume plugin requests.
func (a *Agent) HandlePluginRequest() error {
	return a.volumePlugin.HandleRequest()
}

// Run starts the KrakenFS agent.
func Run(config Config) {
	logger, err := log.New(config.Log, nil)
	if err != nil {
		panic(fmt.Sprintf("log: %s", err))
	}
	defer logger.Sync()

	agent, err := NewAgent(config, logger)
	if err != nil {
		logger.Fatal("Failed to create agent", zap.Error(err))
	}

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
		agent.Stop()
	}()

	// Start the agent
	if err := agent.Start(); err != nil {
		logger.Fatal("Failed to start agent", zap.Error(err))
	}

	// Wait for shutdown
	<-agent.ctx.Done()
}

// ParseFlags parses command line flags and returns the configuration.
func ParseFlags() Config {
	var (
		app = kingpin.New("krakenfs-agent", "KrakenFS P2P volume replication agent")

		configFile = app.Flag("config", "Configuration file path").Default("config.yaml").String()
		pluginMode = app.Flag("plugin", "Run in Docker plugin mode").Bool()
	)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Check if running in plugin mode
	if *pluginMode {
		// Handle plugin request
		config := Config{}
		if err := configutil.Load(*configFile, &config); err != nil {
			panic(fmt.Sprintf("load config: %s", err))
		}

		logger, _ := log.New(config.Log, nil)
		agent, err := NewAgent(config, logger)
		if err != nil {
			panic(fmt.Sprintf("create agent: %s", err))
		}

		if err := agent.HandlePluginRequest(); err != nil {
			panic(fmt.Sprintf("handle plugin request: %s", err))
		}
		os.Exit(0)
	}

	config := Config{}
	if err := configutil.Load(*configFile, &config); err != nil {
		panic(fmt.Sprintf("load config: %s", err))
	}

	// Override configuration with environment variables
	overrideConfigWithEnv(&config)

	return config
}

// overrideConfigWithEnv overrides configuration with environment variables
func overrideConfigWithEnv(config *Config) {
	// Override node ID
	if nodeID := os.Getenv("NODE_ID"); nodeID != "" {
		config.Sync.NodeID = nodeID
	}

	// Override cluster nodes
	if clusterNodes := os.Getenv("CLUSTER_NODES"); clusterNodes != "" {
		// Parse cluster nodes from environment variable
		// Format: "node1:ip1,node2:ip2,node3:ip3"
		config.Sync.ClusterNodes = []string{}
		nodes := strings.Split(clusterNodes, ",")
		for _, node := range nodes {
			if strings.TrimSpace(node) != "" {
				config.Sync.ClusterNodes = append(config.Sync.ClusterNodes, strings.TrimSpace(node))
			}
		}
	}

	// Override P2P port
	if p2pPort := os.Getenv("KRAKENFS_PORT"); p2pPort != "" {
		if port, err := strconv.Atoi(p2pPort); err == nil {
			config.Sync.P2PPort = port
		}
	}

	// Override tracker port
	if trackerPort := os.Getenv("KRAKENFS_PEER_PORT"); trackerPort != "" {
		if port, err := strconv.Atoi(trackerPort); err == nil {
			config.Sync.TrackerPort = port
		}
	}

	// Override log level
	if logLevel := os.Getenv("KRAKENFS_LOG_LEVEL"); logLevel != "" {
		config.Log.Level = logLevel
	}

	// Override TLS settings
	if tlsEnable := os.Getenv("KRAKENFS_TLS_ENABLE"); tlsEnable != "" {
		if enable, err := strconv.ParseBool(tlsEnable); err == nil {
			config.Sync.TLS.Enable = enable
		}
	}

	if certFile := os.Getenv("KRAKENFS_TLS_CERT_FILE"); certFile != "" {
		config.Sync.TLS.CertFile = certFile
	}

	if keyFile := os.Getenv("KRAKENFS_TLS_KEY_FILE"); keyFile != "" {
		config.Sync.TLS.KeyFile = keyFile
	}

	if caFile := os.Getenv("KRAKENFS_TLS_CA_FILE"); caFile != "" {
		config.Sync.TLS.CAFile = caFile
	}

	if verifyPeer := os.Getenv("KRAKENFS_TLS_VERIFY_PEER"); verifyPeer != "" {
		if verify, err := strconv.ParseBool(verifyPeer); err == nil {
			config.Sync.TLS.VerifyPeer = verify
		}
	}

	if minVersion := os.Getenv("KRAKENFS_TLS_MIN_VERSION"); minVersion != "" {
		config.Sync.TLS.MinVersion = minVersion
	}

	if maxVersion := os.Getenv("KRAKENFS_TLS_MAX_VERSION"); maxVersion != "" {
		config.Sync.TLS.MaxVersion = maxVersion
	}

	if insecureSkipVerify := os.Getenv("KRAKENFS_TLS_INSECURE_SKIP_VERIFY"); insecureSkipVerify != "" {
		if skip, err := strconv.ParseBool(insecureSkipVerify); err == nil {
			config.Sync.TLS.InsecureSkipVerify = skip
		}
	}
}

func main() {
	config := ParseFlags()
	Run(config)
}
