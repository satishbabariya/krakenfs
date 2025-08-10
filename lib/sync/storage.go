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
package sync

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dgraph-io/badger/v3"
	"go.uber.org/zap"
)

// Storage manages persistent storage for file states and cluster metadata.
type Storage struct {
	db     *badger.DB
	logger *zap.Logger
}

// StorageConfig defines storage configuration.
type StorageConfig struct {
	Path string `yaml:"path"`
}

// NewStorage creates a new storage instance.
func NewStorage(config StorageConfig, logger *zap.Logger) (*Storage, error) {
	// Ensure storage directory exists
	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}

	// Configure BadgerDB options
	opts := badger.DefaultOptions(config.Path)
	opts.Logger = &badgerLogger{logger: logger}

	// Open database
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger database: %w", err)
	}

	return &Storage{
		db:     db,
		logger: logger,
	}, nil
}

// Close closes the storage.
func (s *Storage) Close() error {
	return s.db.Close()
}

// SaveFileState saves a file state to persistent storage.
func (s *Storage) SaveFileState(state *FileState) error {
	key := fmt.Sprintf("file:%s", state.Path)
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal file state: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetFileState retrieves a file state from persistent storage.
func (s *Storage) GetFileState(path string) (*FileState, error) {
	key := fmt.Sprintf("file:%s", path)
	var state FileState

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &state)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, nil // File not found, return nil
	}
	if err != nil {
		return nil, fmt.Errorf("get file state: %w", err)
	}

	return &state, nil
}

// DeleteFileState removes a file state from persistent storage.
func (s *Storage) DeleteFileState(path string) error {
	key := fmt.Sprintf("file:%s", path)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// ListFileStates returns all file states.
func (s *Storage) ListFileStates() ([]*FileState, error) {
	var states []*FileState

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("file:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var state FileState
				if err := json.Unmarshal(val, &state); err != nil {
					return err
				}
				states = append(states, &state)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return states, err
}

// SavePeerInfo saves peer information.
func (s *Storage) SavePeerInfo(peer *Peer) error {
	key := fmt.Sprintf("peer:%s", peer.ID)
	data, err := json.Marshal(peer)
	if err != nil {
		return fmt.Errorf("marshal peer info: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), data)
	})
}

// GetPeerInfo retrieves peer information.
func (s *Storage) GetPeerInfo(peerID string) (*Peer, error) {
	key := fmt.Sprintf("peer:%s", peerID)
	var peer Peer

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &peer)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get peer info: %w", err)
	}

	return &peer, nil
}

// DeletePeerInfo removes peer information.
func (s *Storage) DeletePeerInfo(peerID string) error {
	key := fmt.Sprintf("peer:%s", peerID)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// RunGC runs garbage collection on the database.
func (s *Storage) RunGC() error {
	return s.db.RunValueLogGC(0.5)
}

// badgerLogger implements badger.Logger interface.
type badgerLogger struct {
	logger *zap.Logger
}

func (bl *badgerLogger) Errorf(format string, args ...interface{}) {
	bl.logger.Error(fmt.Sprintf(format, args...))
}

func (bl *badgerLogger) Warningf(format string, args ...interface{}) {
	bl.logger.Warn(fmt.Sprintf(format, args...))
}

func (bl *badgerLogger) Infof(format string, args ...interface{}) {
	bl.logger.Info(fmt.Sprintf(format, args...))
}

func (bl *badgerLogger) Debugf(format string, args ...interface{}) {
	bl.logger.Debug(fmt.Sprintf(format, args...))
}