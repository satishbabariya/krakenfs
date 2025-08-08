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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AuditEvent represents an audit event.
type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	UserID    string                 `json:"user_id"`
	Username  string                 `json:"username"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"` // "success", "failure", "denied"
	Details   map[string]interface{} `json:"details"`
	SessionID string                 `json:"session_id"`
	RequestID string                 `json:"request_id"`
}

// AuditLevel represents the severity level of an audit event.
type AuditLevel string

const (
	AuditLevelInfo     AuditLevel = "info"
	AuditLevelWarning  AuditLevel = "warning"
	AuditLevelError    AuditLevel = "error"
	AuditLevelCritical AuditLevel = "critical"
)

// EventType represents the type of audit event.
type EventType string

const (
	// Authentication events
	EventLogin          EventType = "login"
	EventLogout         EventType = "logout"
	EventLoginFailed    EventType = "login_failed"
	EventTokenRefresh   EventType = "token_refresh"
	EventTokenExpired   EventType = "token_expired"
	EventPasswordChange EventType = "password_change"
	EventPasswordReset  EventType = "password_reset"

	// Authorization events
	EventAccessGranted   EventType = "access_granted"
	EventAccessDenied    EventType = "access_denied"
	EventPermissionCheck EventType = "permission_check"

	// File system events
	EventFileRead   EventType = "file_read"
	EventFileWrite  EventType = "file_write"
	EventFileDelete EventType = "file_delete"
	EventFileCreate EventType = "file_create"
	EventFileModify EventType = "file_modify"
	EventDirList    EventType = "directory_list"
	EventDirCreate  EventType = "directory_create"
	EventDirDelete  EventType = "directory_delete"

	// User management events
	EventUserCreate  EventType = "user_create"
	EventUserUpdate  EventType = "user_update"
	EventUserDelete  EventType = "user_delete"
	EventUserDisable EventType = "user_disable"
	EventUserEnable  EventType = "user_enable"
	EventRoleAssign  EventType = "role_assign"
	EventRoleRemove  EventType = "role_remove"

	// System events
	EventConfigChange EventType = "config_change"
	EventSystemStart  EventType = "system_start"
	EventSystemStop   EventType = "system_stop"
	EventBackupStart  EventType = "backup_start"
	EventBackupEnd    EventType = "backup_end"
)

// Auditor handles audit logging.
type Auditor struct {
	config AuditConfig
	logger *zap.Logger
	file   *os.File
	mutex  sync.Mutex
}

// AuditConfig defines audit configuration.
type AuditConfig struct {
	Enable   bool   `yaml:"enable"`
	LogFile  string `yaml:"log_file"`
	LogLevel string `yaml:"log_level"`
	Format   string `yaml:"format"` // "json", "text"
}

// NewAuditor creates a new auditor.
func NewAuditor(config AuditConfig, logger *zap.Logger) (*Auditor, error) {
	auditor := &Auditor{
		config: config,
		logger: logger,
	}

	if config.Enable && config.LogFile != "" {
		// Create audit log file
		file, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open audit log file: %s", err)
		}
		auditor.file = file
	}

	return auditor, nil
}

// LogEvent logs an audit event.
func (a *Auditor) LogEvent(event *AuditEvent) error {
	if !a.config.Enable {
		return nil
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Log to structured logger
	a.logger.Info("Audit event",
		zap.String("event_type", event.EventType),
		zap.String("user_id", event.UserID),
		zap.String("username", event.Username),
		zap.String("ip_address", event.IPAddress),
		zap.String("resource", event.Resource),
		zap.String("action", event.Action),
		zap.String("result", event.Result),
		zap.String("session_id", event.SessionID),
		zap.String("request_id", event.RequestID),
		zap.Any("details", event.Details))

	// Log to file if configured
	if a.file != nil {
		if err := a.writeEventToFile(event); err != nil {
			return fmt.Errorf("write event to file: %s", err)
		}
	}

	return nil
}

// writeEventToFile writes an audit event to the log file.
func (a *Auditor) writeEventToFile(event *AuditEvent) error {
	var data []byte
	var err error

	if a.config.Format == "json" {
		data, err = json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal event: %s", err)
		}
		data = append(data, '\n')
	} else {
		// Text format
		data = []byte(fmt.Sprintf("[%s] %s: user=%s ip=%s resource=%s action=%s result=%s\n",
			event.Timestamp.Format(time.RFC3339),
			event.EventType,
			event.Username,
			event.IPAddress,
			event.Resource,
			event.Action,
			event.Result))
	}

	_, err = a.file.Write(data)
	return err
}

// LogLogin logs a successful login event.
func (a *Auditor) LogLogin(user *User, ipAddress, userAgent, sessionID string) error {
	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(EventLogin),
		UserID:    user.ID,
		Username:  user.Username,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Resource:  "auth",
		Action:    "login",
		Result:    "success",
		Details: map[string]interface{}{
			"role": user.Role,
		},
		SessionID: sessionID,
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogLoginFailed logs a failed login event.
func (a *Auditor) LogLoginFailed(username, ipAddress, userAgent, reason string) error {
	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(EventLoginFailed),
		Username:  username,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Resource:  "auth",
		Action:    "login",
		Result:    "failure",
		Details: map[string]interface{}{
			"reason": reason,
		},
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogLogout logs a logout event.
func (a *Auditor) LogLogout(user *User, ipAddress, sessionID string) error {
	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(EventLogout),
		UserID:    user.ID,
		Username:  user.Username,
		IPAddress: ipAddress,
		Resource:  "auth",
		Action:    "logout",
		Result:    "success",
		SessionID: sessionID,
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogAccessGranted logs an access granted event.
func (a *Auditor) LogAccessGranted(user *User, resource, action, ipAddress string) error {
	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(EventAccessGranted),
		UserID:    user.ID,
		Username:  user.Username,
		IPAddress: ipAddress,
		Resource:  resource,
		Action:    action,
		Result:    "success",
		Details: map[string]interface{}{
			"role": user.Role,
		},
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogAccessDenied logs an access denied event.
func (a *Auditor) LogAccessDenied(user *User, resource, action, ipAddress, reason string) error {
	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(EventAccessDenied),
		UserID:    user.ID,
		Username:  user.Username,
		IPAddress: ipAddress,
		Resource:  resource,
		Action:    action,
		Result:    "denied",
		Details: map[string]interface{}{
			"role":   user.Role,
			"reason": reason,
		},
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogFileAccess logs a file access event.
func (a *Auditor) LogFileAccess(user *User, filePath, action, ipAddress string, success bool) error {
	eventType := EventFileRead
	result := "success"

	switch action {
	case "read":
		eventType = EventFileRead
	case "write":
		eventType = EventFileWrite
	case "delete":
		eventType = EventFileDelete
	case "create":
		eventType = EventFileCreate
	case "modify":
		eventType = EventFileModify
	}

	if !success {
		result = "failure"
	}

	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(eventType),
		UserID:    user.ID,
		Username:  user.Username,
		IPAddress: ipAddress,
		Resource:  filePath,
		Action:    action,
		Result:    result,
		Details: map[string]interface{}{
			"role": user.Role,
		},
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogUserManagement logs a user management event.
func (a *Auditor) LogUserManagement(adminUser *User, targetUser *User, action, ipAddress string) error {
	var eventType EventType
	switch action {
	case "create":
		eventType = EventUserCreate
	case "update":
		eventType = EventUserUpdate
	case "delete":
		eventType = EventUserDelete
	case "disable":
		eventType = EventUserDisable
	case "enable":
		eventType = EventUserEnable
	default:
		eventType = EventUserUpdate
	}

	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(eventType),
		UserID:    adminUser.ID,
		Username:  adminUser.Username,
		IPAddress: ipAddress,
		Resource:  "users",
		Action:    action,
		Result:    "success",
		Details: map[string]interface{}{
			"admin_role":  adminUser.Role,
			"target_user": targetUser.Username,
			"target_role": targetUser.Role,
		},
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// LogSystemEvent logs a system event.
func (a *Auditor) LogSystemEvent(eventType EventType, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:        a.generateEventID(),
		Timestamp: time.Now(),
		EventType: string(eventType),
		Resource:  "system",
		Action:    "system_event",
		Result:    "success",
		Details:   details,
		RequestID: a.generateRequestID(),
	}

	return a.LogEvent(event)
}

// generateEventID generates a unique event ID.
func (a *Auditor) generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

// generateRequestID generates a unique request ID.
func (a *Auditor) generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// Close closes the auditor and its resources.
func (a *Auditor) Close() error {
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}

// GetClientIP extracts the client IP address from a request.
func GetClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
