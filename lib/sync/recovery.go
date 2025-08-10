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
	"context"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RecoveryManager handles error recovery and retry logic.
type RecoveryManager struct {
	logger       *zap.Logger
	config       RecoveryConfig
	failureCounts map[string]int
	lastFailures  map[string]time.Time
	mutex         sync.RWMutex
}

// RecoveryConfig defines recovery configuration.
type RecoveryConfig struct {
	MaxRetries         int           `yaml:"max_retries"`
	InitialDelay       time.Duration `yaml:"initial_delay"`
	MaxDelay           time.Duration `yaml:"max_delay"`
	BackoffMultiplier  float64       `yaml:"backoff_multiplier"`
	ResetAfter         time.Duration `yaml:"reset_after"`
	EnableCircuitBreaker bool        `yaml:"enable_circuit_breaker"`
	CircuitBreakerThreshold int      `yaml:"circuit_breaker_threshold"`
}

// RetryableOperation represents an operation that can be retried.
type RetryableOperation func() error

// OperationResult represents the result of a retryable operation.
type OperationResult struct {
	Success      bool
	Error        error
	Attempts     int
	TotalDelay   time.Duration
}

// ErrorType represents different types of errors for recovery strategies.
type ErrorType int

const (
	NetworkError ErrorType = iota
	PeerError
	FileSystemError
	AuthenticationError
	ConfigurationError
	UnknownError
)

// RecoverableError wraps an error with recovery information.
type RecoverableError struct {
	Type       ErrorType
	Temporary  bool
	Retryable  bool
	Underlying error
}

func (re *RecoverableError) Error() string {
	return fmt.Sprintf("recoverable error (type: %v, temporary: %v, retryable: %v): %v",
		re.Type, re.Temporary, re.Retryable, re.Underlying)
}

// NewRecoveryManager creates a new recovery manager.
func NewRecoveryManager(config RecoveryConfig, logger *zap.Logger) *RecoveryManager {
	// Set defaults
	if config.MaxRetries == 0 {
		config.MaxRetries = 5
	}
	if config.InitialDelay == 0 {
		config.InitialDelay = 1 * time.Second
	}
	if config.MaxDelay == 0 {
		config.MaxDelay = 30 * time.Second
	}
	if config.BackoffMultiplier == 0 {
		config.BackoffMultiplier = 2.0
	}
	if config.ResetAfter == 0 {
		config.ResetAfter = 5 * time.Minute
	}
	if config.CircuitBreakerThreshold == 0 {
		config.CircuitBreakerThreshold = 10
	}

	return &RecoveryManager{
		logger:        logger,
		config:        config,
		failureCounts: make(map[string]int),
		lastFailures:  make(map[string]time.Time),
	}
}

// ExecuteWithRetry executes an operation with retry logic.
func (rm *RecoveryManager) ExecuteWithRetry(ctx context.Context, operationName string, op RetryableOperation) *OperationResult {
	start := time.Now()
	
	result := &OperationResult{
		Success:    false,
		Attempts:   0,
		TotalDelay: 0,
	}

	// Check circuit breaker
	if rm.isCircuitOpen(operationName) {
		result.Error = fmt.Errorf("circuit breaker open for operation: %s", operationName)
		return result
	}

	for attempt := 0; attempt <= rm.config.MaxRetries; attempt++ {
		result.Attempts = attempt + 1

		// Execute the operation
		err := op()
		if err == nil {
			// Success - reset failure count
			rm.resetFailureCount(operationName)
			result.Success = true
			result.TotalDelay = time.Since(start)
			
			rm.logger.Debug("Operation succeeded",
				zap.String("operation", operationName),
				zap.Int("attempts", result.Attempts),
				zap.Duration("total_delay", result.TotalDelay))
			
			return result
		}

		// Handle error
		result.Error = err
		rm.recordFailure(operationName)

		// Check if error is retryable
		if !rm.isRetryable(err) {
			rm.logger.Error("Non-retryable error",
				zap.String("operation", operationName),
				zap.Error(err))
			break
		}

		// Don't sleep on the last attempt
		if attempt == rm.config.MaxRetries {
			break
		}

		// Calculate delay for next attempt
		delay := rm.calculateDelay(attempt)
		
		rm.logger.Warn("Operation failed, retrying",
			zap.String("operation", operationName),
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", rm.config.MaxRetries),
			zap.Duration("delay", delay),
			zap.Error(err))

		// Wait before next attempt (with context cancellation support)
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			result.TotalDelay = time.Since(start)
			return result
		case <-time.After(delay):
			result.TotalDelay += delay
		}
	}

	result.TotalDelay = time.Since(start)
	
	rm.logger.Error("Operation failed after all retries",
		zap.String("operation", operationName),
		zap.Int("attempts", result.Attempts),
		zap.Duration("total_delay", result.TotalDelay),
		zap.Error(result.Error))

	return result
}

// calculateDelay calculates the delay for a retry attempt using exponential backoff.
func (rm *RecoveryManager) calculateDelay(attempt int) time.Duration {
	delay := float64(rm.config.InitialDelay) * math.Pow(rm.config.BackoffMultiplier, float64(attempt))
	
	// Add jitter (±20%)
	jitter := delay * 0.2 * (2*rand.Float64() - 1)
	delay += jitter
	
	// Cap at maximum delay
	if delay > float64(rm.config.MaxDelay) {
		delay = float64(rm.config.MaxDelay)
	}
	
	return time.Duration(delay)
}

// isRetryable determines if an error is retryable.
func (rm *RecoveryManager) isRetryable(err error) bool {
	if recErr, ok := err.(*RecoverableError); ok {
		return recErr.Retryable
	}

	// Default retry logic for common error types
	errStr := err.Error()
	
	// Network errors are usually retryable
	if contains(errStr, "connection refused") ||
		contains(errStr, "connection reset") ||
		contains(errStr, "timeout") ||
		contains(errStr, "network is unreachable") ||
		contains(errStr, "no route to host") {
		return true
	}

	// File system errors might be retryable
	if contains(errStr, "device or resource busy") ||
		contains(errStr, "temporary failure") {
		return true
	}

	// Authentication errors are usually not retryable
	if contains(errStr, "unauthorized") ||
		contains(errStr, "authentication failed") ||
		contains(errStr, "access denied") {
		return false
	}

	// Default to non-retryable for safety
	return false
}

// recordFailure records a failure for an operation.
func (rm *RecoveryManager) recordFailure(operationName string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rm.failureCounts[operationName]++
	rm.lastFailures[operationName] = time.Now()
}

// resetFailureCount resets the failure count for an operation.
func (rm *RecoveryManager) resetFailureCount(operationName string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	delete(rm.failureCounts, operationName)
	delete(rm.lastFailures, operationName)
}

// isCircuitOpen checks if the circuit breaker is open for an operation.
func (rm *RecoveryManager) isCircuitOpen(operationName string) bool {
	if !rm.config.EnableCircuitBreaker {
		return false
	}

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	count := rm.failureCounts[operationName]
	lastFailure := rm.lastFailures[operationName]

	// Reset if enough time has passed
	if time.Since(lastFailure) > rm.config.ResetAfter {
		go rm.resetFailureCount(operationName) // Reset in background
		return false
	}

	return count >= rm.config.CircuitBreakerThreshold
}

// GetStats returns recovery manager statistics.
func (rm *RecoveryManager) GetStats() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_operations": len(rm.failureCounts),
		"circuit_breaker_enabled": rm.config.EnableCircuitBreaker,
		"operations": make(map[string]interface{}),
	}

	for op, count := range rm.failureCounts {
		lastFailure := rm.lastFailures[op]
		circuitOpen := rm.isCircuitOpen(op)
		
		stats["operations"].(map[string]interface{})[op] = map[string]interface{}{
			"failure_count":   count,
			"last_failure":    lastFailure,
			"circuit_open":    circuitOpen,
		}
	}

	return stats
}

// ClassifyError classifies an error for recovery purposes.
func ClassifyError(err error) *RecoverableError {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	
	// Network errors
	if contains(errStr, "connection") || contains(errStr, "network") || contains(errStr, "timeout") {
		return &RecoverableError{
			Type:       NetworkError,
			Temporary:  true,
			Retryable:  true,
			Underlying: err,
		}
	}

	// File system errors
	if contains(errStr, "no such file") || contains(errStr, "permission denied") {
		return &RecoverableError{
			Type:       FileSystemError,
			Temporary:  false,
			Retryable:  false,
			Underlying: err,
		}
	}

	if contains(errStr, "device or resource busy") {
		return &RecoverableError{
			Type:       FileSystemError,
			Temporary:  true,
			Retryable:  true,
			Underlying: err,
		}
	}

	// Authentication errors
	if contains(errStr, "unauthorized") || contains(errStr, "authentication") {
		return &RecoverableError{
			Type:       AuthenticationError,
			Temporary:  false,
			Retryable:  false,
			Underlying: err,
		}
	}

	// Default classification
	return &RecoverableError{
		Type:       UnknownError,
		Temporary:  false,
		Retryable:  false,
		Underlying: err,
	}
}

// contains checks if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

