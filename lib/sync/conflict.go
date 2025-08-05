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
	"fmt"
	"time"

	"github.com/uber/krakenfs/lib/filesystem"
	"go.uber.org/zap"
)

// ConflictStrategy defines the strategy for resolving conflicts.
type ConflictStrategy string

const (
	// TimestampStrategy resolves conflicts based on timestamp (last-write-wins)
	TimestampStrategy ConflictStrategy = "timestamp"

	// ManualStrategy requires manual resolution
	ManualStrategy ConflictStrategy = "manual"

	// LastWriteWinsStrategy is an alias for timestamp strategy
	LastWriteWinsStrategy ConflictStrategy = "last_write_wins"
)

// Conflict represents a file conflict between multiple events.
type Conflict struct {
	FilePath string
	Events   []filesystem.FileChangeEvent
	Strategy ConflictStrategy
	Resolved *filesystem.FileChangeEvent
}

// ConflictResolver manages conflict resolution.
type ConflictResolver struct {
	strategy ConflictStrategy
	logger   *zap.Logger
}

// NewConflictResolver creates a new conflict resolver.
func NewConflictResolver(strategy ConflictStrategy, logger *zap.Logger) *ConflictResolver {
	return &ConflictResolver{
		strategy: strategy,
		logger:   logger,
	}
}

// Resolve resolves a conflict between multiple file events.
func (cr *ConflictResolver) Resolve(events []filesystem.FileChangeEvent) (*filesystem.FileChangeEvent, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("no events to resolve")
	}

	if len(events) == 1 {
		return &events[0], nil
	}

	cr.logger.Info("Resolving conflict",
		zap.String("file_path", events[0].Path),
		zap.Int("event_count", len(events)),
		zap.String("strategy", string(cr.strategy)))

	switch cr.strategy {
	case TimestampStrategy, LastWriteWinsStrategy:
		return cr.resolveByTimestamp(events)
	case ManualStrategy:
		return cr.resolveManually(events)
	default:
		return nil, fmt.Errorf("unknown conflict resolution strategy: %s", cr.strategy)
	}
}

// DetectConflict detects if there's a conflict between events.
func (cr *ConflictResolver) DetectConflict(event1, event2 filesystem.FileChangeEvent) bool {
	// Same file path
	if event1.Path != event2.Path {
		return false
	}

	// Different nodes (different sources)
	if event1.NodeID == event2.NodeID {
		return false
	}

	// Same operation type
	if event1.Operation != event2.Operation {
		return false
	}

	// For testing purposes, consider events close in time as conflicting
	// In production, you might want a more sophisticated time window
	timeDiff := event1.Timestamp.Sub(event2.Timestamp)
	if timeDiff < -5*time.Second || timeDiff > 5*time.Second {
		return false
	}

	return true
}

// resolveByTimestamp resolves conflicts using timestamp-based strategy.
func (cr *ConflictResolver) resolveByTimestamp(events []filesystem.FileChangeEvent) (*filesystem.FileChangeEvent, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("no events to resolve")
	}

	// Find the event with the latest timestamp
	latestEvent := events[0]
	for _, event := range events[1:] {
		if event.Timestamp.After(latestEvent.Timestamp) {
			latestEvent = event
		}
	}

	cr.logger.Info("Resolved conflict by timestamp",
		zap.String("file_path", latestEvent.Path),
		zap.String("selected_node", latestEvent.NodeID),
		zap.Time("selected_timestamp", latestEvent.Timestamp))

	return &latestEvent, nil
}

// resolveManually resolves conflicts using manual strategy.
func (cr *ConflictResolver) resolveManually(events []filesystem.FileChangeEvent) (*filesystem.FileChangeEvent, error) {
	// For now, we'll use timestamp strategy as fallback
	// In a real implementation, this would trigger a manual resolution UI
	cr.logger.Warn("Manual conflict resolution not implemented, using timestamp fallback",
		zap.String("file_path", events[0].Path))

	return cr.resolveByTimestamp(events)
}

// MergeEvents merges multiple events for the same file.
func (cr *ConflictResolver) MergeEvents(events []filesystem.FileChangeEvent) ([]filesystem.FileChangeEvent, error) {
	if len(events) <= 1 {
		return events, nil
	}

	// Group events by file path
	fileGroups := make(map[string][]filesystem.FileChangeEvent)
	for _, event := range events {
		fileGroups[event.Path] = append(fileGroups[event.Path], event)
	}

	var mergedEvents []filesystem.FileChangeEvent

	for filePath, fileEvents := range fileGroups {
		if len(fileEvents) == 1 {
			mergedEvents = append(mergedEvents, fileEvents[0])
			continue
		}

		// Check for conflicts
		hasConflict := false
		for i := 0; i < len(fileEvents); i++ {
			for j := i + 1; j < len(fileEvents); j++ {
				if cr.DetectConflict(fileEvents[i], fileEvents[j]) {
					hasConflict = true
					break
				}
			}
			if hasConflict {
				break
			}
		}

		if hasConflict {
			// Resolve conflict
			resolvedEvent, err := cr.Resolve(fileEvents)
			if err != nil {
				return nil, fmt.Errorf("resolve conflict for %s: %s", filePath, err)
			}
			mergedEvents = append(mergedEvents, *resolvedEvent)
		} else {
			// No conflict, keep all events
			mergedEvents = append(mergedEvents, fileEvents...)
		}
	}

	return mergedEvents, nil
}

// ValidateEvent validates if an event is valid for processing.
func (cr *ConflictResolver) ValidateEvent(event filesystem.FileChangeEvent) error {
	if event.Path == "" {
		return fmt.Errorf("event path is empty")
	}

	if event.NodeID == "" {
		return fmt.Errorf("event node ID is empty")
	}

	if event.Timestamp.IsZero() {
		return fmt.Errorf("event timestamp is zero")
	}

	return nil
}

// GetConflictInfo returns information about a conflict.
func (cr *ConflictResolver) GetConflictInfo(events []filesystem.FileChangeEvent) *Conflict {
	if len(events) <= 1 {
		return nil
	}

	conflict := &Conflict{
		FilePath: events[0].Path,
		Events:   events,
		Strategy: cr.strategy,
	}

	// Check for conflicts
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if cr.DetectConflict(events[i], events[j]) {
				return conflict
			}
		}
	}

	return nil
}
