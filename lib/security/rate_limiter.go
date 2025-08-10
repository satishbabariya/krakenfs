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
package security

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"go.uber.org/zap"
)

// RateLimiter provides rate limiting functionality for security-sensitive endpoints.
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mutex    sync.RWMutex
	logger   *zap.Logger
	
	// Configuration
	requestsPerMinute int
	burstSize         int
	cleanupInterval   time.Duration
}

// RateLimiterConfig defines rate limiter configuration.
type RateLimiterConfig struct {
	RequestsPerMinute int           `yaml:"requests_per_minute"`
	BurstSize         int           `yaml:"burst_size"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval"`
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(config RateLimiterConfig, logger *zap.Logger) *RateLimiter {
	if config.RequestsPerMinute == 0 {
		config.RequestsPerMinute = 10 // Default: 10 requests per minute
	}
	if config.BurstSize == 0 {
		config.BurstSize = 3 // Default: 3 burst requests
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 10 * time.Minute // Default: cleanup every 10 minutes
	}

	rl := &RateLimiter{
		limiters:          make(map[string]*rate.Limiter),
		logger:            logger,
		requestsPerMinute: config.RequestsPerMinute,
		burstSize:         config.BurstSize,
		cleanupInterval:   config.CleanupInterval,
	}

	// Start cleanup goroutine
	go rl.cleanupRoutine()

	return rl
}

// Allow checks if a request from the given IP should be allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		// Create new limiter for this IP
		limiter = rate.NewLimiter(
			rate.Limit(float64(rl.requestsPerMinute)/60.0), // Convert to per-second rate
			rl.burstSize,
		)
		rl.limiters[ip] = limiter
	}

	return limiter.Allow()
}

// GetClientIPFromRequest extracts the client IP from a request.
func GetClientIPFromRequest(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// RateLimitMiddleware returns a middleware that applies rate limiting.
func (rl *RateLimiter) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := GetClientIPFromRequest(r.RemoteAddr)
		
		if !rl.Allow(clientIP) {
			rl.logger.Warn("Rate limit exceeded",
				zap.String("ip", clientIP),
				zap.String("path", r.URL.Path))
			
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// cleanupRoutine periodically removes old limiters to prevent memory leaks.
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes rate limiters that haven't been used recently.
func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Remove limiters that have enough tokens (indicating they haven't been used recently)
	for ip, limiter := range rl.limiters {
		if limiter.Tokens() >= float64(rl.burstSize) {
			delete(rl.limiters, ip)
		}
	}

	rl.logger.Debug("Rate limiter cleanup completed",
		zap.Int("active_limiters", len(rl.limiters)))
}

// GetStats returns rate limiter statistics.
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	return map[string]interface{}{
		"active_limiters":     len(rl.limiters),
		"requests_per_minute": rl.requestsPerMinute,
		"burst_size":          rl.burstSize,
		"cleanup_interval":    rl.cleanupInterval.String(),
	}
}

// Reset clears all rate limiters (useful for testing).
func (rl *RateLimiter) Reset() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	rl.limiters = make(map[string]*rate.Limiter)
}