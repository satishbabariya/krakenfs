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
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// SecurityManager manages all security components.
type SecurityManager struct {
	config  SecurityConfig
	logger  *zap.Logger
	auth    *Authenticator
	authz   *Authorizer
	auditor *Auditor
}

// SecurityConfig defines the complete security configuration.
type SecurityConfig struct {
	Authentication AuthConfig  `yaml:"authentication"`
	Authorization  AuthzConfig `yaml:"authorization"`
	Audit          AuditConfig `yaml:"audit"`
}

// NewSecurityManager creates a new security manager.
func NewSecurityManager(config SecurityConfig, logger *zap.Logger) (*SecurityManager, error) {
	// Initialize authenticator
	auth := NewAuthenticator(config.Authentication, logger)

	// Initialize authorizer
	authz := NewAuthorizer(config.Authorization, logger)

	// Initialize auditor
	auditor, err := NewAuditor(config.Audit, logger)
	if err != nil {
		return nil, fmt.Errorf("create auditor: %s", err)
	}

	manager := &SecurityManager{
		config:  config,
		logger:  logger,
		auth:    auth,
		authz:   authz,
		auditor: auditor,
	}

	return manager, nil
}

// AuthenticateUser authenticates a user with credentials.
func (sm *SecurityManager) AuthenticateUser(creds Credentials, ipAddress, userAgent string) (*Session, error) {
	user, err := sm.auth.Authenticate(creds)
	if err != nil {
		// Log failed login attempt
		sm.auditor.LogLoginFailed(creds.Username, ipAddress, userAgent, err.Error())
		return nil, err
	}

	// Create session
	session, err := sm.auth.CreateSession(user, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create session: %s", err)
	}

	// Log successful login
	sm.auditor.LogLogin(user, ipAddress, userAgent, session.ID)

	return session, nil
}

// ValidateToken validates a JWT token and returns the user.
func (sm *SecurityManager) ValidateToken(tokenString string) (*User, error) {
	user, err := sm.auth.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// CheckAccess checks if a user can perform an action on a resource.
func (sm *SecurityManager) CheckAccess(user *User, resource, action, ipAddress string) *AccessResponse {
	response := sm.authz.CheckAccess(user, resource, action)

	// Log access attempt
	if response.Allowed {
		sm.auditor.LogAccessGranted(user, resource, action, ipAddress)
	} else {
		sm.auditor.LogAccessDenied(user, resource, action, ipAddress, response.Reason)
	}

	return response
}

// CanAccess checks if a user can perform an action on a resource.
func (sm *SecurityManager) CanAccess(user *User, resource, action string) bool {
	return sm.authz.CanAccess(user, resource, action)
}

// ValidateFileAccess validates if a user can access a specific file path.
func (sm *SecurityManager) ValidateFileAccess(user *User, filePath, action string) bool {
	return sm.authz.ValidateResourcePath(user, filePath, action)
}

// LogFileAccess logs a file access event.
func (sm *SecurityManager) LogFileAccess(user *User, filePath, action, ipAddress string, success bool) error {
	return sm.auditor.LogFileAccess(user, filePath, action, ipAddress, success)
}

// LogUserManagement logs a user management event.
func (sm *SecurityManager) LogUserManagement(adminUser *User, targetUser *User, action, ipAddress string) error {
	return sm.auditor.LogUserManagement(adminUser, targetUser, action, ipAddress)
}

// LogSystemEvent logs a system event.
func (sm *SecurityManager) LogSystemEvent(eventType EventType, details map[string]interface{}) error {
	return sm.auditor.LogSystemEvent(eventType, details)
}

// ExtractTokenFromRequest extracts a JWT token from an HTTP request.
func (sm *SecurityManager) ExtractTokenFromRequest(r *http.Request) (string, error) {
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			return token, nil
		}
	}

	// Check cookie
	cookie, err := r.Cookie("krakenfs_token")
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	// Check query parameter
	token := r.URL.Query().Get("token")
	if token != "" {
		return token, nil
	}

	return "", fmt.Errorf("no token found in request")
}

// GetUserFromRequest extracts and validates a user from an HTTP request.
func (sm *SecurityManager) GetUserFromRequest(r *http.Request) (*User, error) {
	token, err := sm.ExtractTokenFromRequest(r)
	if err != nil {
		return nil, err
	}

	user, err := sm.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// RequireAuth middleware requires authentication for a request.
func (sm *SecurityManager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := sm.GetUserFromRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user to request context
		ctx := r.Context()
		ctx = contextWithUser(ctx, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// RequireRole middleware requires a specific role for a request.
func (sm *SecurityManager) RequireRole(role string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if user.Role != role {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// RequirePermission middleware requires a specific permission for a request.
func (sm *SecurityManager) RequirePermission(resource, action string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ipAddress := GetClientIP(r.RemoteAddr)
			response := sm.CheckAccess(user, resource, action, ipAddress)
			if !response.Allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// GetAuthenticator returns the authenticator.
func (sm *SecurityManager) GetAuthenticator() *Authenticator {
	return sm.auth
}

// GetAuthorizer returns the authorizer.
func (sm *SecurityManager) GetAuthorizer() *Authorizer {
	return sm.authz
}

// GetAuditor returns the auditor.
func (sm *SecurityManager) GetAuditor() *Auditor {
	return sm.auditor
}

// Close closes the security manager and its resources.
func (sm *SecurityManager) Close() error {
	return sm.auditor.Close()
}

// contextKey is a type for context keys.
type contextKey string

const userContextKey contextKey = "user"

// contextWithUser adds a user to the context.
func contextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext extracts a user from the context.
func UserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(userContextKey).(*User); ok {
		return user
	}
	return nil
}

// IsSecurityEnabled checks if security is enabled.
func (sm *SecurityManager) IsSecurityEnabled() bool {
	return sm.config.Authentication.Enable || sm.config.Authorization.Enable
}

// GetDefaultUsers returns the default users for the system.
func (sm *SecurityManager) GetDefaultUsers() map[string]interface{} {
	return map[string]interface{}{
		"admin": map[string]interface{}{
			"username": "admin",
			"password": "admin123",
			"role":     "admin",
		},
		"user": map[string]interface{}{
			"username": "user",
			"password": "user123",
			"role":     "user",
		},
	}
}

// GetDefaultRoles returns the default roles for the system.
func (sm *SecurityManager) GetDefaultRoles() map[string]interface{} {
	return map[string]interface{}{
		"admin": map[string]interface{}{
			"name":        "Admin",
			"description": "Full administrative access",
			"permissions": []string{"admin"},
		},
		"user": map[string]interface{}{
			"name":        "User",
			"description": "Standard user access",
			"permissions": []string{"read", "write"},
		},
		"viewer": map[string]interface{}{
			"name":        "Viewer",
			"description": "Read-only access",
			"permissions": []string{"read"},
		},
	}
}
