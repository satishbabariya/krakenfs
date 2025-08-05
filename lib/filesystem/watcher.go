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
package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// FileOperation represents the type of file operation.
type FileOperation int

const (
	Create FileOperation = iota
	Write
	Remove
	Rename
	Chmod
)

// FileChangeEvent represents a file system change event.
type FileChangeEvent struct {
	Path      string
	Operation FileOperation
	Timestamp time.Time
	NodeID    string
}

// Config defines filesystem watcher configuration.
type Config struct {
	WatchPaths      []string `yaml:"watch_paths"`
	ExcludePatterns []string `yaml:"exclude_patterns"`
	Recursive       bool     `yaml:"recursive"`
	DebounceTime    string   `yaml:"debounce_time"`
}

// Watcher monitors file system changes and emits events.
type Watcher struct {
	config    Config
	logger    *zap.Logger
	watcher   *fsnotify.Watcher
	eventChan chan FileChangeEvent
	stopChan  chan struct{}
	wg        sync.WaitGroup
	nodeID    string
}

// NewWatcher creates a new file system watcher.
func NewWatcher(config Config, logger *zap.Logger) (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %s", err)
	}

	return &Watcher{
		config:    config,
		logger:    logger,
		watcher:   watcher,
		eventChan: make(chan FileChangeEvent, 100),
		stopChan:  make(chan struct{}),
		nodeID:    "node1", // TODO: Get from config
	}, nil
}

// Start starts the file system watcher.
func (w *Watcher) Start() error {
	w.logger.Info("Starting file system watcher")

	// Add watch paths
	for _, path := range w.config.WatchPaths {
		if err := w.addWatchPath(path); err != nil {
			return fmt.Errorf("add watch path %s: %s", path, err)
		}
	}

	w.wg.Add(1)
	go w.watchLoop()

	return nil
}

// Stop stops the file system watcher.
func (w *Watcher) Stop() {
	w.logger.Info("Stopping file system watcher")
	close(w.stopChan)
	w.watcher.Close()
	w.wg.Wait()
}

// Events returns the channel for file change events.
func (w *Watcher) Events() <-chan FileChangeEvent {
	return w.eventChan
}

// addWatchPath adds a path to watch, recursively if configured.
func (w *Watcher) addWatchPath(path string) error {
	if w.config.Recursive {
		return filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return w.watcher.Add(path)
			}
			return nil
		})
	}
	return w.watcher.Add(path)
}

// watchLoop processes file system events.
func (w *Watcher) watchLoop() {
	defer w.wg.Done()

	for {
		select {
		case event := <-w.watcher.Events:
			w.handleEvent(event)
		case err := <-w.watcher.Errors:
			w.logger.Error("File system watcher error", zap.Error(err))
		case <-w.stopChan:
			return
		}
	}
}

// handleEvent processes a single file system event.
func (w *Watcher) handleEvent(event fsnotify.Event) {
	// Skip excluded patterns
	if w.isExcluded(event.Name) {
		return
	}

	operation := w.mapOperation(event.Op)
	if operation == -1 {
		return // Skip unsupported operations
	}

	fileEvent := FileChangeEvent{
		Path:      event.Name,
		Operation: operation,
		Timestamp: time.Now(),
		NodeID:    w.nodeID,
	}

	select {
	case w.eventChan <- fileEvent:
		w.logger.Debug("File change event",
			zap.String("path", event.Name),
			zap.String("operation", event.Op.String()))
	default:
		w.logger.Warn("Event channel full, dropping event",
			zap.String("path", event.Name))
	}
}

// isExcluded checks if a path should be excluded from monitoring.
func (w *Watcher) isExcluded(path string) bool {
	for _, pattern := range w.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

// String returns the string representation of FileOperation.
func (op FileOperation) String() string {
	switch op {
	case Create:
		return "Create"
	case Write:
		return "Write"
	case Remove:
		return "Remove"
	case Rename:
		return "Rename"
	case Chmod:
		return "Chmod"
	default:
		return "Unknown"
	}
}

// mapOperation maps fsnotify operations to our FileOperation type.
func (w *Watcher) mapOperation(op fsnotify.Op) FileOperation {
	switch {
	case op&fsnotify.Create == fsnotify.Create:
		return Create
	case op&fsnotify.Write == fsnotify.Write:
		return Write
	case op&fsnotify.Remove == fsnotify.Remove:
		return Remove
	case op&fsnotify.Rename == fsnotify.Rename:
		return Rename
	case op&fsnotify.Chmod == fsnotify.Chmod:
		return Chmod
	default:
		return -1
	}
}
