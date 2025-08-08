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
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/uber/krakenfs/lib/security"
	"go.uber.org/zap"
)

// Server represents the HTTP API server.
type Server struct {
	config          ServerConfig
	logger          *zap.Logger
	securityManager *security.SecurityManager
	authHandler     *AuthHandler
	server          *http.Server
}

// ServerConfig defines the server configuration.
type ServerConfig struct {
	Port         int    `yaml:"port"`
	Host         string `yaml:"host"`
	ReadTimeout  string `yaml:"read_timeout"`
	WriteTimeout string `yaml:"write_timeout"`
	IdleTimeout  string `yaml:"idle_timeout"`
}

// NewServer creates a new HTTP API server.
func NewServer(config ServerConfig, securityManager *security.SecurityManager, logger *zap.Logger) *Server {
	authHandler := NewAuthHandler(securityManager, logger)

	server := &Server{
		config:          config,
		logger:          logger,
		securityManager: securityManager,
		authHandler:     authHandler,
	}

	// Create HTTP server
	server.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Handler:      server.createMux(),
		ReadTimeout:  server.parseDuration(config.ReadTimeout, 30*time.Second),
		WriteTimeout: server.parseDuration(config.WriteTimeout, 30*time.Second),
		IdleTimeout:  server.parseDuration(config.IdleTimeout, 60*time.Second),
	}

	return server
}

// createMux creates the HTTP router with all endpoints.
func (s *Server) createMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Public endpoints (no authentication required)
	mux.HandleFunc("/api/v1/auth/login", s.authHandler.HandleLogin)
	mux.HandleFunc("/api/v1/auth/validate", s.authHandler.HandleValidateToken)

	// Protected endpoints (authentication required)
	mux.HandleFunc("/api/v1/auth/logout", s.securityManager.RequireAuth(s.authHandler.HandleLogout))
	mux.HandleFunc("/api/v1/auth/user", s.securityManager.RequireAuth(s.authHandler.HandleGetUserInfo))

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Default handler for unmatched routes
	mux.HandleFunc("/", s.handleNotFound)

	return mux
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.logger.Info("Starting HTTP API server",
		zap.String("addr", s.server.Addr),
		zap.Int("port", s.config.Port))

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	return nil
}

// Stop stops the HTTP server gracefully.
func (s *Server) Stop() error {
	s.logger.Info("Stopping HTTP API server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("Error shutting down HTTP server", zap.Error(err))
		return err
	}

	s.logger.Info("HTTP API server stopped")
	return nil
}

// handleHealth handles health check requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "krakenfs-api",
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode health response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleNotFound handles unmatched routes.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"error":   "Not Found",
		"message": "The requested resource was not found",
		"path":    r.URL.Path,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode not found response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// parseDuration parses a duration string with a default fallback.
func (s *Server) parseDuration(durationStr string, defaultDuration time.Duration) time.Duration {
	if durationStr == "" {
		return defaultDuration
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		s.logger.Warn("Invalid duration format, using default",
			zap.String("duration", durationStr),
			zap.Duration("default", defaultDuration))
		return defaultDuration
	}

	return duration
}

// GetServer returns the underlying HTTP server.
func (s *Server) GetServer() *http.Server {
	return s.server
}
