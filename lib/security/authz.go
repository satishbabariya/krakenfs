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
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Permission represents a permission in the system.
type Permission struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Created     time.Time `json:"created"`
}

// Role represents a role in the system.
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Created     time.Time    `json:"created"`
	Updated     time.Time    `json:"updated"`
}

// AccessRequest represents an access request.
type AccessRequest struct {
	UserID   string                 `json:"user_id"`
	Resource string                 `json:"resource"`
	Action   string                 `json:"action"`
	Context  map[string]interface{} `json:"context"`
}

// AccessResponse represents an access response.
type AccessResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Authorizer handles authorization and access control.
type Authorizer struct {
	config      AuthzConfig
	logger      *zap.Logger
	roles       map[string]*Role
	permissions map[string]*Permission
}

// AuthzConfig defines authorization configuration.
type AuthzConfig struct {
	Enable bool       `yaml:"enable"`
	RBAC   RBACConfig `yaml:"rbac"`
}

// RBACConfig defines RBAC configuration.
type RBACConfig struct {
	Enable bool `yaml:"enable"`
}

// NewAuthorizer creates a new authorizer.
func NewAuthorizer(config AuthzConfig, logger *zap.Logger) *Authorizer {
	authz := &Authorizer{
		config:      config,
		logger:      logger,
		roles:       make(map[string]*Role),
		permissions: make(map[string]*Permission),
	}

	// Initialize default roles and permissions if authorization is enabled
	if config.Enable {
		authz.initializeDefaultPermissions()
		authz.initializeDefaultRoles()
	}

	return authz
}

// initializeDefaultPermissions creates default permissions for the system.
func (a *Authorizer) initializeDefaultPermissions() {
	permissions := []Permission{
		{
			ID:          "read",
			Name:        "Read",
			Description: "Read files and directories",
			Resource:    "*",
			Action:      "read",
			Created:     time.Now(),
		},
		{
			ID:          "write",
			Name:        "Write",
			Description: "Write files and directories",
			Resource:    "*",
			Action:      "write",
			Created:     time.Now(),
		},
		{
			ID:          "delete",
			Name:        "Delete",
			Description: "Delete files and directories",
			Resource:    "*",
			Action:      "delete",
			Created:     time.Now(),
		},
		{
			ID:          "admin",
			Name:        "Admin",
			Description: "Administrative access",
			Resource:    "*",
			Action:      "*",
			Created:     time.Now(),
		},
		{
			ID:          "user_manage",
			Name:        "User Management",
			Description: "Manage users",
			Resource:    "users",
			Action:      "*",
			Created:     time.Now(),
		},
		{
			ID:          "config_manage",
			Name:        "Configuration Management",
			Description: "Manage system configuration",
			Resource:    "config",
			Action:      "*",
			Created:     time.Now(),
		},
	}

	for _, perm := range permissions {
		a.permissions[perm.ID] = &perm
	}

	a.logger.Info("Initialized default permissions", zap.Int("count", len(permissions)))
}

// initializeDefaultRoles creates default roles for the system.
func (a *Authorizer) initializeDefaultRoles() {
	// Admin role with all permissions
	adminRole := &Role{
		ID:          "admin",
		Name:        "Admin",
		Description: "Full administrative access",
		Permissions: []Permission{*a.permissions["admin"]},
		Created:     time.Now(),
		Updated:     time.Now(),
	}

	// User role with read/write permissions
	userRole := &Role{
		ID:          "user",
		Name:        "User",
		Description: "Standard user access",
		Permissions: []Permission{
			*a.permissions["read"],
			*a.permissions["write"],
		},
		Created: time.Now(),
		Updated: time.Now(),
	}

	// Viewer role with read-only permissions
	viewerRole := &Role{
		ID:          "viewer",
		Name:        "Viewer",
		Description: "Read-only access",
		Permissions: []Permission{
			*a.permissions["read"],
		},
		Created: time.Now(),
		Updated: time.Now(),
	}

	a.roles["admin"] = adminRole
	a.roles["user"] = userRole
	a.roles["viewer"] = viewerRole

	a.logger.Info("Initialized default roles",
		zap.String("admin_role", "admin"),
		zap.String("user_role", "user"),
		zap.String("viewer_role", "viewer"))
}

// CanAccess checks if a user can perform an action on a resource.
func (a *Authorizer) CanAccess(user *User, resource, action string) bool {
	if !a.config.Enable {
		return true // If authorization is disabled, allow all access
	}

	role, exists := a.roles[user.Role]
	if !exists {
		a.logger.Warn("Role not found", zap.String("role", user.Role))
		return false
	}

	for _, permission := range role.Permissions {
		if a.matchesPermission(permission, resource, action) {
			a.logger.Debug("Access granted",
				zap.String("user_id", user.ID),
				zap.String("resource", resource),
				zap.String("action", action),
				zap.String("permission", permission.ID))
			return true
		}
	}

	a.logger.Debug("Access denied",
		zap.String("user_id", user.ID),
		zap.String("resource", resource),
		zap.String("action", action),
		zap.String("role", user.Role))

	return false
}

// CheckAccess checks access with detailed response.
func (a *Authorizer) CheckAccess(user *User, resource, action string) *AccessResponse {
	allowed := a.CanAccess(user, resource, action)

	response := &AccessResponse{
		Allowed: allowed,
	}

	if allowed {
		response.Reason = "Access granted"
	} else {
		response.Reason = fmt.Sprintf("User %s with role %s does not have permission to %s on %s",
			user.Username, user.Role, action, resource)
	}

	return response
}

// GetUserPermissions returns all permissions for a user.
func (a *Authorizer) GetUserPermissions(user *User) []Permission {
	if !a.config.Enable {
		return []Permission{} // Return empty if authorization is disabled
	}

	role, exists := a.roles[user.Role]
	if !exists {
		return []Permission{}
	}

	return role.Permissions
}

// CheckRole checks if a user has a specific role.
func (a *Authorizer) CheckRole(user *User, roleName string) bool {
	return user.Role == roleName
}

// matchesPermission checks if a permission matches the resource and action.
func (a *Authorizer) matchesPermission(permission Permission, resource, action string) bool {
	// Check if permission has wildcard resource
	if permission.Resource == "*" {
		// Check if permission has wildcard action
		if permission.Action == "*" {
			return true
		}
		// Check if action matches
		return permission.Action == action
	}

	// Check if resource matches
	if permission.Resource != resource {
		return false
	}

	// Check if permission has wildcard action
	if permission.Action == "*" {
		return true
	}

	// Check if action matches
	return permission.Action == action
}

// CreateRole creates a new role.
func (a *Authorizer) CreateRole(id, name, description string, permissionIDs []string) (*Role, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authorization is disabled")
	}

	if _, exists := a.roles[id]; exists {
		return nil, fmt.Errorf("role already exists")
	}

	permissions := make([]Permission, 0)
	for _, permID := range permissionIDs {
		if perm, exists := a.permissions[permID]; exists {
			permissions = append(permissions, *perm)
		} else {
			return nil, fmt.Errorf("permission not found: %s", permID)
		}
	}

	role := &Role{
		ID:          id,
		Name:        name,
		Description: description,
		Permissions: permissions,
		Created:     time.Now(),
		Updated:     time.Now(),
	}

	a.roles[id] = role
	a.logger.Info("Created new role", zap.String("role_id", id), zap.String("name", name))

	return role, nil
}

// UpdateRole updates an existing role.
func (a *Authorizer) UpdateRole(roleID string, updates map[string]interface{}) (*Role, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authorization is disabled")
	}

	role, exists := a.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role not found")
	}

	// Update fields
	if name, ok := updates["name"].(string); ok {
		role.Name = name
	}

	if description, ok := updates["description"].(string); ok {
		role.Description = description
	}

	if permissionIDs, ok := updates["permissions"].([]string); ok {
		permissions := make([]Permission, 0)
		for _, permID := range permissionIDs {
			if perm, exists := a.permissions[permID]; exists {
				permissions = append(permissions, *perm)
			} else {
				return nil, fmt.Errorf("permission not found: %s", permID)
			}
		}
		role.Permissions = permissions
	}

	role.Updated = time.Now()
	a.roles[roleID] = role

	a.logger.Info("Updated role", zap.String("role_id", roleID))

	return role, nil
}

// DeleteRole deletes a role.
func (a *Authorizer) DeleteRole(roleID string) error {
	if !a.config.Enable {
		return fmt.Errorf("authorization is disabled")
	}

	if _, exists := a.roles[roleID]; !exists {
		return fmt.Errorf("role not found")
	}

	delete(a.roles, roleID)
	a.logger.Info("Deleted role", zap.String("role_id", roleID))

	return nil
}

// GetRole returns a role by ID.
func (a *Authorizer) GetRole(roleID string) (*Role, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authorization is disabled")
	}

	role, exists := a.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role not found")
	}

	return role, nil
}

// ListRoles returns all roles.
func (a *Authorizer) ListRoles() []*Role {
	if !a.config.Enable {
		return []*Role{}
	}

	roles := make([]*Role, 0, len(a.roles))
	for _, role := range a.roles {
		roles = append(roles, role)
	}

	return roles
}

// CreatePermission creates a new permission.
func (a *Authorizer) CreatePermission(id, name, description, resource, action string) (*Permission, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authorization is disabled")
	}

	if _, exists := a.permissions[id]; exists {
		return nil, fmt.Errorf("permission already exists")
	}

	permission := &Permission{
		ID:          id,
		Name:        name,
		Description: description,
		Resource:    resource,
		Action:      action,
		Created:     time.Now(),
	}

	a.permissions[id] = permission
	a.logger.Info("Created new permission", zap.String("permission_id", id), zap.String("name", name))

	return permission, nil
}

// GetPermission returns a permission by ID.
func (a *Authorizer) GetPermission(permissionID string) (*Permission, error) {
	if !a.config.Enable {
		return nil, fmt.Errorf("authorization is disabled")
	}

	permission, exists := a.permissions[permissionID]
	if !exists {
		return nil, fmt.Errorf("permission not found")
	}

	return permission, nil
}

// ListPermissions returns all permissions.
func (a *Authorizer) ListPermissions() []*Permission {
	if !a.config.Enable {
		return []*Permission{}
	}

	permissions := make([]*Permission, 0, len(a.permissions))
	for _, permission := range a.permissions {
		permissions = append(permissions, permission)
	}

	return permissions
}

// ValidateResourcePath validates if a user can access a specific file path.
func (a *Authorizer) ValidateResourcePath(user *User, filePath string, action string) bool {
	// For now, we'll use a simple path-based validation
	// In a more sophisticated system, you might want to implement path-based ACLs

	// Check if user has wildcard permission
	if a.CanAccess(user, "*", action) {
		return true
	}

	// Check if user has specific file permission
	if a.CanAccess(user, filePath, action) {
		return true
	}

	// Check directory-based permissions
	pathParts := strings.Split(filePath, "/")
	for i := len(pathParts); i > 0; i-- {
		dirPath := strings.Join(pathParts[:i], "/")
		if dirPath == "" {
			dirPath = "/"
		}
		if a.CanAccess(user, dirPath, action) {
			return true
		}
	}

	return false
}
