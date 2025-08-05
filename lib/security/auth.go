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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system.
type User struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Password string    `json:"-"` // Never expose password in JSON
	Role     string    `json:"role"`
	Active   bool      `json:"active"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

// Credentials represents login credentials.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenClaims represents JWT token claims.
type TokenClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Session represents a user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	User      *User     `json:"user"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// Authenticator handles user authentication.
type Authenticator struct {
	config AuthConfig
	logger *zap.Logger
	users  map[string]*User
}

// AuthConfig defines authentication configuration.
type AuthConfig struct {
	Enable      bool   `yaml:"enable"`
	Type        string `yaml:"type"` // "jwt", "ldap", "oauth2"
	JWTSecret   string `yaml:"jwt_secret"`
	TokenExpiry string `yaml:"token_expiry"`
	BCryptCost  int    `yaml:"bcrypt_cost"`
}

// NewAuthenticator creates a new authenticator.
func NewAuthenticator(config AuthConfig, logger *zap.Logger) *Authenticator {
	auth := &Authenticator{
		config: config,
		logger: logger,
		users:  make(map[string]*User),
	}

	// Initialize default admin user if authentication is enabled
	if config.Enable {
		auth.initializeDefaultUsers()
	}

	return auth
}

// initializeDefaultUsers creates default users for the system.
func (a *Authenticator) initializeDefaultUsers() {
	// Create default admin user
	adminPassword, _ := a.hashPassword("admin123")
	adminUser := &User{
		ID:       "admin",
		Username: "admin",
		Email:    "admin@krakenfs.local",
		Password: adminPassword,
		Role:     "admin",
		Active:   true,
		Created:  time.Now(),
		Updated:  time.Now(),
	}
	a.users["admin"] = adminUser

	// Create default user
	userPassword, _ := a.hashPassword("user123")
	user := &User{
		ID:       "user",
		Username: "user",
		Email:    "user@krakenfs.local",
		Password: userPassword,
		Role:     "user",
		Active:   true,
		Created:  time.Now(),
		Updated:  time.Now(),
	}
	a.users["user"] = user

	a.logger.Info("Initialized default users",
		zap.String("admin_username", "admin"),
		zap.String("user_username", "user"))
}

// Authenticate authenticates a user with credentials.
func (a *Authenticator) Authenticate(creds Credentials) (*User, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authentication is disabled")
	}

	user, exists := a.users[creds.Username]
	if !exists {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !user.Active {
		return nil, fmt.Errorf("user account is disabled")
	}

	if !a.checkPassword(creds.Password, user.Password) {
		return nil, fmt.Errorf("invalid credentials")
	}

	a.logger.Info("User authenticated successfully",
		zap.String("username", user.Username),
		zap.String("role", user.Role))

	return user, nil
}

// GenerateToken generates a JWT token for a user.
func (a *Authenticator) GenerateToken(user *User) (string, error) {
	if !a.config.Enable {
		return "", fmt.Errorf("authentication is disabled")
	}

	expiry, err := time.ParseDuration(a.config.TokenExpiry)
	if err != nil {
		expiry = 24 * time.Hour // Default to 24 hours
	}

	claims := TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "krakenfs",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(a.config.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign token: %s", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the user.
func (a *Authenticator) ValidateToken(tokenString string) (*User, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authentication is disabled")
	}

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.config.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse token: %s", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	user, exists := a.users[claims.UserID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	if !user.Active {
		return nil, fmt.Errorf("user account is disabled")
	}

	return user, nil
}

// CreateSession creates a new user session.
func (a *Authenticator) CreateSession(user *User, ipAddress, userAgent string) (*Session, error) {
	token, err := a.GenerateToken(user)
	if err != nil {
		return nil, err
	}

	expiry, err := time.ParseDuration(a.config.TokenExpiry)
	if err != nil {
		expiry = 24 * time.Hour
	}

	sessionID, err := a.generateSessionID()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		User:      user,
		Token:     token,
		ExpiresAt: time.Now().Add(expiry),
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	return session, nil
}

// hashPassword hashes a password using bcrypt.
func (a *Authenticator) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), a.config.BCryptCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// checkPassword checks if a password matches the hash.
func (a *Authenticator) checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// generateSessionID generates a random session ID.
func (a *Authenticator) generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GetUserByID returns a user by ID.
func (a *Authenticator) GetUserByID(userID string) (*User, error) {
	user, exists := a.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// GetUserByUsername returns a user by username.
func (a *Authenticator) GetUserByUsername(username string) (*User, error) {
	for _, user := range a.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// ListUsers returns all users.
func (a *Authenticator) ListUsers() []*User {
	users := make([]*User, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	return users
}

// CreateUser creates a new user.
func (a *Authenticator) CreateUser(username, email, password, role string) (*User, error) {
	if _, exists := a.users[username]; exists {
		return nil, fmt.Errorf("user already exists")
	}

	hashedPassword, err := a.hashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:       username,
		Username: username,
		Email:    email,
		Password: hashedPassword,
		Role:     role,
		Active:   true,
		Created:  time.Now(),
		Updated:  time.Now(),
	}

	a.users[username] = user
	a.logger.Info("Created new user", zap.String("username", username), zap.String("role", role))

	return user, nil
}

// UpdateUser updates an existing user.
func (a *Authenticator) UpdateUser(userID string, updates map[string]interface{}) (*User, error) {
	user, exists := a.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	// Update fields
	if password, ok := updates["password"].(string); ok {
		hashedPassword, err := a.hashPassword(password)
		if err != nil {
			return nil, err
		}
		user.Password = hashedPassword
	}

	if email, ok := updates["email"].(string); ok {
		user.Email = email
	}

	if role, ok := updates["role"].(string); ok {
		user.Role = role
	}

	if active, ok := updates["active"].(bool); ok {
		user.Active = active
	}

	user.Updated = time.Now()
	a.users[userID] = user

	a.logger.Info("Updated user", zap.String("user_id", userID))

	return user, nil
}

// DeleteUser deletes a user.
func (a *Authenticator) DeleteUser(userID string) error {
	if _, exists := a.users[userID]; !exists {
		return fmt.Errorf("user not found")
	}

	delete(a.users, userID)
	a.logger.Info("Deleted user", zap.String("user_id", userID))

	return nil
}
