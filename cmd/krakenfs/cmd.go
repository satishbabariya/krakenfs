// Copyright (c) 2024 KrakenFS Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package krakenfs

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin"
	"github.com/uber-go/tally"
	"go.uber.org/zap"

	"github.com/uber/krakenfs/lib/filesystem"
	"github.com/uber/krakenfs/lib/sync"
	"github.com/uber/krakenfs/lib/volume"
	"github.com/uber/krakenfs/utils/configutil"
	"github.com/uber/krakenfs/utils/log"
)

// Config defines KrakenFS configuration.
type Config struct {
	Log        log.Config        `yaml:"log"`
	Filesystem filesystem.Config `yaml:"filesystem"`
	Sync       sync.Config       `yaml:"sync"`
	Volume     volume.Config     `yaml:"volume"`
	Metrics    tally.Scope       `yaml:"-"`
}

// Run starts the KrakenFS agent.
func Run(config Config) {
	logger, err := log.New(config.Log, nil)
	if err != nil {
		panic(fmt.Sprintf("log: %s", err))
	}
	defer logger.Sync()

	logger.Info("Starting KrakenFS agent...")

	// Initialize file system watcher
	fsWatcher, err := filesystem.NewWatcher(config.Filesystem, logger)
	if err != nil {
		logger.Fatal("Failed to create file system watcher", zap.Error(err))
	}

	// Initialize P2P sync engine
	syncEngine, err := sync.NewEngine(config.Sync, logger)
	if err != nil {
		logger.Fatal("Failed to create sync engine", zap.Error(err))
	}

	// Initialize volume driver
	volumeDriver, err := volume.NewDriver(config.Volume, logger)
	if err != nil {
		logger.Fatal("Failed to create volume driver", zap.Error(err))
	}

	// Start all components
	if err := fsWatcher.Start(); err != nil {
		logger.Fatal("Failed to start file system watcher", zap.Error(err))
	}

	if err := syncEngine.Start(); err != nil {
		logger.Fatal("Failed to start sync engine", zap.Error(err))
	}

	if err := volumeDriver.Start(); err != nil {
		logger.Fatal("Failed to start volume driver", zap.Error(err))
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// Wait for shutdown
	<-ctx.Done()
	logger.Info("Shutting down KrakenFS agent...")

	// Stop components gracefully
	fsWatcher.Stop()
	syncEngine.Stop()
	volumeDriver.Stop()

	logger.Info("KrakenFS agent stopped")
}

// ParseFlags parses command line flags and returns the configuration.
func ParseFlags() Config {
	var (
		app = kingpin.New("krakenfs", "P2P-powered Docker volume replication system")

		configFile = app.Flag("config", "Configuration file path").Required().String()
	)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	config := Config{}
	if err := configutil.Load(*configFile, &config); err != nil {
		panic(fmt.Sprintf("load config: %s", err))
	}

	return config
}
