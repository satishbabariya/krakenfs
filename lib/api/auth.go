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
	"encoding/json"
	"net/http"
	"time"

	"github.com/uber/krakenfs/lib/security"
	"go.uber.org/zap"
)

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	securityManager *security.SecurityManager
	logger          *zap.Logger
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response.
type LoginResponse struct {
	Token     string         `json:"token"`
	User      *security.User `json:"user"`
	ExpiresAt time.Time      `json:"expires_at"`
	SessionID string         `json:"session_id"`
}

// LogoutRequest represents a logout request.
type LogoutRequest struct {
	SessionID string `json:"session_id"`
}

// LogoutResponse represents a logout response.
type LogoutResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ValidateTokenRequest represents a token validation request.
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse represents a token validation response.
type ValidateTokenResponse struct {
	Valid bool           `json:"valid"`
	User  *security.User `json:"user,omitempty"`
}

// NewAuthHandler creates a new authentication handler.
func NewAuthHandler(securityManager *security.SecurityManager, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		securityManager: securityManager,
		logger:          logger,
	}
}

// HandleLogin handles login requests.
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Get client IP and user agent
	ipAddress := security.GetClientIP(r.RemoteAddr)
	userAgent := r.UserAgent()

	// Authenticate user
	creds := security.Credentials{
		Username: req.Username,
		Password: req.Password,
	}

	session, err := h.securityManager.AuthenticateUser(creds, ipAddress, userAgent)
	if err != nil {
		h.logger.Warn("Login failed",
			zap.String("username", req.Username),
			zap.String("ip_address", ipAddress),
			zap.Error(err))

		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create response
	response := LoginResponse{
		Token:     session.Token,
		User:      session.User,
		ExpiresAt: session.ExpiresAt,
		SessionID: session.ID,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode login response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Login successful",
		zap.String("username", req.Username),
		zap.String("ip_address", ipAddress),
		zap.String("session_id", session.ID))
}

// HandleLogout handles logout requests.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from request context
	user := security.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Log logout event
	ipAddress := security.GetClientIP(r.RemoteAddr)
	h.securityManager.GetAuditor().LogLogout(user, ipAddress, req.SessionID)

	// Create response
	response := LogoutResponse{
		Success: true,
		Message: "Logout successful",
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode logout response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Logout successful",
		zap.String("username", user.Username),
		zap.String("ip_address", ipAddress),
		zap.String("session_id", req.SessionID))
}

// HandleValidateToken handles token validation requests.
func (h *AuthHandler) HandleValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ValidateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	// Validate token
	user, err := h.securityManager.ValidateToken(req.Token)
	if err != nil {
		response := ValidateTokenResponse{
			Valid: false,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			h.logger.Error("Failed to encode token validation response", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Create response
	response := ValidateTokenResponse{
		Valid: true,
		User:  user,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode token validation response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Token validation successful",
		zap.String("username", user.Username))
}

// HandleGetUserInfo handles user info requests.
func (h *AuthHandler) HandleGetUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user from request context
	user := security.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user permissions
	permissions := h.securityManager.GetAuthorizer().GetUserPermissions(user)

	// Create response
	response := map[string]interface{}{
		"user":        user,
		"permissions": permissions,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode user info response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("User info retrieved",
		zap.String("username", user.Username))
}
