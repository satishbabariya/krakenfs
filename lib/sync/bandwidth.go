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
	"io"
	"net"
	"time"

	"golang.org/x/time/rate"
	"go.uber.org/zap"
)

// BandwidthLimiter manages bandwidth limiting for network operations.
type BandwidthLimiter struct {
	egressLimiter  *rate.Limiter
	ingressLimiter *rate.Limiter
	enabled        bool
	logger         *zap.Logger
}

// NewBandwidthLimiter creates a new bandwidth limiter.
func NewBandwidthLimiter(config BandwidthConfig, logger *zap.Logger) *BandwidthLimiter {
	if !config.Enable {
		return &BandwidthLimiter{
			enabled: false,
			logger:  logger,
		}
	}

	// Convert bits per second to bytes per second
	egressBytesPerSec := config.EgressBitsPerSec / 8
	ingressBytesPerSec := config.IngressBitsPerSec / 8

	// Create rate limiters with burst capacity of 1 second worth of data
	egressLimiter := rate.NewLimiter(rate.Limit(egressBytesPerSec), int(egressBytesPerSec))
	ingressLimiter := rate.NewLimiter(rate.Limit(ingressBytesPerSec), int(ingressBytesPerSec))

	logger.Info("Bandwidth limiting enabled",
		zap.Int64("egress_bytes_per_sec", egressBytesPerSec),
		zap.Int64("ingress_bytes_per_sec", ingressBytesPerSec))

	return &BandwidthLimiter{
		egressLimiter:  egressLimiter,
		ingressLimiter: ingressLimiter,
		enabled:        true,
		logger:         logger,
	}
}

// LimitedConn wraps a net.Conn with bandwidth limiting.
type LimitedConn struct {
	net.Conn
	limiter *BandwidthLimiter
}

// WrapConnection wraps a connection with bandwidth limiting.
func (bl *BandwidthLimiter) WrapConnection(conn net.Conn) net.Conn {
	if !bl.enabled {
		return conn
	}

	return &LimitedConn{
		Conn:    conn,
		limiter: bl,
	}
}

// Read implements io.Reader with ingress bandwidth limiting.
func (lc *LimitedConn) Read(b []byte) (int, error) {
	if !lc.limiter.enabled {
		return lc.Conn.Read(b)
	}

	// Wait for permission to read
	ctx := context.Background()
	if err := lc.limiter.ingressLimiter.WaitN(ctx, len(b)); err != nil {
		return 0, err
	}

	return lc.Conn.Read(b)
}

// Write implements io.Writer with egress bandwidth limiting.
func (lc *LimitedConn) Write(b []byte) (int, error) {
	if !lc.limiter.enabled {
		return lc.Conn.Write(b)
	}

	// Wait for permission to write
	ctx := context.Background()
	if err := lc.limiter.egressLimiter.WaitN(ctx, len(b)); err != nil {
		return 0, err
	}

	return lc.Conn.Write(b)
}

// LimitedReader wraps an io.Reader with bandwidth limiting.
type LimitedReader struct {
	reader  io.Reader
	limiter *rate.Limiter
}

// NewLimitedReader creates a new bandwidth-limited reader.
func (bl *BandwidthLimiter) NewLimitedReader(reader io.Reader) io.Reader {
	if !bl.enabled {
		return reader
	}

	return &LimitedReader{
		reader:  reader,
		limiter: bl.ingressLimiter,
	}
}

// Read implements io.Reader with bandwidth limiting.
func (lr *LimitedReader) Read(p []byte) (int, error) {
	// Wait for permission to read
	ctx := context.Background()
	if err := lr.limiter.WaitN(ctx, len(p)); err != nil {
		return 0, err
	}

	return lr.reader.Read(p)
}

// LimitedWriter wraps an io.Writer with bandwidth limiting.
type LimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
}

// NewLimitedWriter creates a new bandwidth-limited writer.
func (bl *BandwidthLimiter) NewLimitedWriter(writer io.Writer) io.Writer {
	if !bl.enabled {
		return writer
	}

	return &LimitedWriter{
		writer:  writer,
		limiter: bl.egressLimiter,
	}
}

// Write implements io.Writer with bandwidth limiting.
func (lw *LimitedWriter) Write(p []byte) (int, error) {
	// Wait for permission to write
	ctx := context.Background()
	if err := lw.limiter.WaitN(ctx, len(p)); err != nil {
		return 0, err
	}

	return lw.writer.Write(p)
}

// ReserveEgress reserves bandwidth for egress traffic.
func (bl *BandwidthLimiter) ReserveEgress(bytes int) *rate.Reservation {
	if !bl.enabled {
		return nil
	}
	return bl.egressLimiter.ReserveN(time.Now(), bytes)
}

// ReserveIngress reserves bandwidth for ingress traffic.
func (bl *BandwidthLimiter) ReserveIngress(bytes int) *rate.Reservation {
	if !bl.enabled {
		return nil
	}
	return bl.ingressLimiter.ReserveN(time.Now(), bytes)
}

// WaitEgress waits for permission to send bytes.
func (bl *BandwidthLimiter) WaitEgress(ctx context.Context, bytes int) error {
	if !bl.enabled {
		return nil
	}
	return bl.egressLimiter.WaitN(ctx, bytes)
}

// WaitIngress waits for permission to receive bytes.
func (bl *BandwidthLimiter) WaitIngress(ctx context.Context, bytes int) error {
	if !bl.enabled {
		return nil
	}
	return bl.ingressLimiter.WaitN(ctx, bytes)
}

// GetEgressRate returns the current egress rate in bytes per second.
func (bl *BandwidthLimiter) GetEgressRate() float64 {
	if !bl.enabled {
		return 0
	}
	return float64(bl.egressLimiter.Limit())
}

// GetIngressRate returns the current ingress rate in bytes per second.
func (bl *BandwidthLimiter) GetIngressRate() float64 {
	if !bl.enabled {
		return 0
	}
	return float64(bl.ingressLimiter.Limit())
}

// SetEgressRate updates the egress rate limit.
func (bl *BandwidthLimiter) SetEgressRate(bytesPerSec int64) {
	if !bl.enabled {
		return
	}
	bl.egressLimiter.SetLimit(rate.Limit(bytesPerSec))
	bl.egressLimiter.SetBurst(int(bytesPerSec))
}

// SetIngressRate updates the ingress rate limit.
func (bl *BandwidthLimiter) SetIngressRate(bytesPerSec int64) {
	if !bl.enabled {
		return
	}
	bl.ingressLimiter.SetLimit(rate.Limit(bytesPerSec))
	bl.ingressLimiter.SetBurst(int(bytesPerSec))
}

// IsEnabled returns whether bandwidth limiting is enabled.
func (bl *BandwidthLimiter) IsEnabled() bool {
	return bl.enabled
}

// GetStats returns bandwidth limiter statistics.
func (bl *BandwidthLimiter) GetStats() map[string]interface{} {
	if !bl.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return map[string]interface{}{
		"enabled":            true,
		"egress_rate_bps":    bl.GetEgressRate(),
		"ingress_rate_bps":   bl.GetIngressRate(),
		"egress_burst":       bl.egressLimiter.Burst(),
		"ingress_burst":      bl.ingressLimiter.Burst(),
		"egress_tokens":      bl.egressLimiter.Tokens(),
		"ingress_tokens":     bl.ingressLimiter.Tokens(),
	}
}