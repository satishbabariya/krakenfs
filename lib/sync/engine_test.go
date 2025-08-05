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
	"testing"
	"time"

	"github.com/uber/krakenfs/lib/filesystem"
	"go.uber.org/zap"
)

func TestConflictResolver(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	resolver := NewConflictResolver(TimestampStrategy, logger)

	// Create test events
	event1 := filesystem.FileChangeEvent{
		Path:      "/test/file.txt",
		Operation: filesystem.Write,
		Timestamp: time.Now(),
		NodeID:    "node1",
	}

	event2 := filesystem.FileChangeEvent{
		Path:      "/test/file.txt",
		Operation: filesystem.Write,
		Timestamp: time.Now().Add(time.Second), // Later timestamp
		NodeID:    "node2",
	}

	// Test conflict detection
	if !resolver.DetectConflict(event1, event2) {
		t.Error("Expected conflict to be detected")
	}

	// Test conflict resolution
	resolved, err := resolver.Resolve([]filesystem.FileChangeEvent{event1, event2})
	if err != nil {
		t.Errorf("Failed to resolve conflict: %v", err)
	}

	if resolved.NodeID != "node2" {
		t.Errorf("Expected node2 to win (latest timestamp), got %s", resolved.NodeID)
	}
}

func TestFileTransfer(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	transfer := NewFileTransfer(1024, logger) // 1KB chunks

	// Test chunk size validation
	if transfer.chunkSize != 1024 {
		t.Errorf("Expected chunk size 1024, got %d", transfer.chunkSize)
	}

	// Test with invalid chunk size
	transfer2 := NewFileTransfer(-1, logger)
	if transfer2.chunkSize != DefaultChunkSize {
		t.Errorf("Expected default chunk size %d, got %d", DefaultChunkSize, transfer2.chunkSize)
	}

	// Test with oversized chunk size
	transfer3 := NewFileTransfer(MaxChunkSize+1, logger)
	if transfer3.chunkSize != MaxChunkSize {
		t.Errorf("Expected max chunk size %d, got %d", MaxChunkSize, transfer3.chunkSize)
	}
}

func TestProtocol(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	protocol := NewProtocol("test-node", "1.0", logger)

	if protocol.nodeID != "test-node" {
		t.Errorf("Expected node ID 'test-node', got %s", protocol.nodeID)
	}

	if protocol.version != "1.0" {
		t.Errorf("Expected version '1.0', got %s", protocol.version)
	}
}
