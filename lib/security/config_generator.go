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
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// SecureConfigGenerator generates secure configuration files.
type SecureConfigGenerator struct {
	logger *zap.Logger
}

// NewSecureConfigGenerator creates a new secure configuration generator.
func NewSecureConfigGenerator(logger *zap.Logger) *SecureConfigGenerator {
	return &SecureConfigGenerator{
		logger: logger,
	}
}

// GenerateSecureConfig generates a secure configuration with random secrets.
func (scg *SecureConfigGenerator) GenerateSecureConfig(configPath string) error {
	// Generate secure JWT secret
	jwtSecret, err := scg.generateJWTSecret()
	if err != nil {
		return fmt.Errorf("generate JWT secret: %w", err)
	}

	// Generate secure admin password
	adminPassword := scg.generateSecurePassword(24)
	userPassword := scg.generateSecurePassword(16)

	// Create secure configuration
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"filesystem": map[string]interface{}{
			"watch_paths": []string{"/data", "/shared"},
			"exclude_patterns": []string{
				"*.tmp", "*.log", ".git", "node_modules", ".DS_Store",
			},
			"recursive":      true,
			"debounce_time": "100ms",
		},
		"sync": map[string]interface{}{
			"node_id": "node1",
			"cluster_nodes": []string{
				"node1:192.168.1.10",
				"node2:192.168.1.11",
			},
			"p2p_port":     6881,
			"tracker_port": 6882,
			"bandwidth": map[string]interface{}{
				"enable":               true,
				"egress_bits_per_sec":  1677721600, // 200MB/s
				"ingress_bits_per_sec": 2516582400, // 300MB/s
			},
			"conflict_resolution": map[string]interface{}{
				"strategy": "timestamp",
				"timeout":  "30s",
			},
			"tls": map[string]interface{}{
				"enable":               false,
				"cert_file":            "/etc/krakenfs/certs/node1.crt",
				"key_file":             "/etc/krakenfs/certs/node1.key",
				"ca_file":              "/etc/krakenfs/certs/ca.crt",
				"verify_peer":          false,
				"min_version":          "1.2",
				"max_version":          "1.3",
				"insecure_skip_verify": false,
			},
			"storage": map[string]interface{}{
				"path": "/var/lib/krakenfs/data",
			},
			"discovery": map[string]interface{}{
				"enable":       true,
				"service_name": "_krakenfs._tcp",
				"domain":       "local",
			},
		},
		"volume": map[string]interface{}{
			"root_path":   "/var/lib/krakenfs/volumes",
			"driver_name": "krakenfs",
		},
		"security": map[string]interface{}{
			"authentication": map[string]interface{}{
				"enable":       true,
				"type":         "jwt",
				"jwt_secret":   jwtSecret,
				"token_expiry": "24h",
				"bcrypt_cost":  12,
			},
			"authorization": map[string]interface{}{
				"enable": true,
				"rbac": map[string]interface{}{
					"enable": true,
				},
			},
			"audit": map[string]interface{}{
				"enable":    true,
				"log_file":  "/var/log/krakenfs/audit.log",
				"log_level": "info",
				"format":    "json",
			},
		},
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write configuration file
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer file.Close()

	// Write YAML header comment
	fmt.Fprintf(file, "# KrakenFS Secure Configuration\n")
	fmt.Fprintf(file, "# Generated with secure random secrets\n")
	fmt.Fprintf(file, "# \n")
	fmt.Fprintf(file, "# IMPORTANT SECURITY INFORMATION:\n")
	fmt.Fprintf(file, "# - JWT Secret: %s\n", jwtSecret[:16]+"...")
	fmt.Fprintf(file, "# - Admin Password: %s\n", adminPassword)
	fmt.Fprintf(file, "# - User Password: %s\n", userPassword)
	fmt.Fprintf(file, "# \n")
	fmt.Fprintf(file, "# Please store these credentials securely!\n")
	fmt.Fprintf(file, "# Change default passwords before production use.\n")
	fmt.Fprintf(file, "\n")

	encoder := yaml.NewEncoder(file)
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	scg.logger.Info("Generated secure configuration",
		zap.String("config_path", configPath),
		zap.String("admin_password", adminPassword),
		zap.String("user_password", userPassword))

	// Also create a separate credentials file
	credentialsPath := filepath.Join(filepath.Dir(configPath), "credentials.txt")
	if err := scg.writeCredentialsFile(credentialsPath, jwtSecret, adminPassword, userPassword); err != nil {
		scg.logger.Warn("Failed to create credentials file", zap.Error(err))
	}

	return nil
}

// generateJWTSecret generates a cryptographically secure JWT secret.
func (scg *SecureConfigGenerator) generateJWTSecret() (string, error) {
	// Generate 64 bytes of random data (512 bits)
	secretBytes := make([]byte, 64)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	// Encode as base64
	secret := base64.StdEncoding.EncodeToString(secretBytes)
	return secret, nil
}

// generateSecurePassword generates a cryptographically secure password.
func (scg *SecureConfigGenerator) generateSecurePassword(length int) string {
	// Generate enough random bytes
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		scg.logger.Error("Failed to generate secure password", zap.Error(err))
		return "insecure-fallback-password"
	}

	// Use a character set that's safe for passwords
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[int(bytes[i])%len(charset)]
	}

	return string(password)
}

// writeCredentialsFile writes credentials to a separate file for easy reference.
func (scg *SecureConfigGenerator) writeCredentialsFile(path, jwtSecret, adminPassword, userPassword string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Set restrictive permissions
	if err := file.Chmod(0600); err != nil {
		return err
	}

	fmt.Fprintf(file, "KrakenFS Credentials\n")
	fmt.Fprintf(file, "===================\n\n")
	fmt.Fprintf(file, "JWT Secret: %s\n\n", jwtSecret)
	fmt.Fprintf(file, "Default Users:\n")
	fmt.Fprintf(file, "  Admin:\n")
	fmt.Fprintf(file, "    Username: admin\n")
	fmt.Fprintf(file, "    Password: %s\n\n", adminPassword)
	fmt.Fprintf(file, "  User:\n")
	fmt.Fprintf(file, "    Username: user\n")
	fmt.Fprintf(file, "    Password: %s\n\n", userPassword)
	fmt.Fprintf(file, "IMPORTANT: Store these credentials securely and change defaults before production!\n")

	return nil
}

// ValidateConfigSecurity validates the security of an existing configuration.
func (scg *SecureConfigGenerator) ValidateConfigSecurity(configPath string) ([]string, error) {
	var warnings []string

	// Read configuration
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Check security section
	security, ok := config["security"].(map[interface{}]interface{})
	if !ok {
		warnings = append(warnings, "Security section missing or invalid")
		return warnings, nil
	}

	// Check authentication
	if auth, ok := security["authentication"].(map[interface{}]interface{}); ok {
		if jwtSecret, ok := auth["jwt_secret"].(string); ok {
			if len(jwtSecret) < 32 {
				warnings = append(warnings, "JWT secret is too short (minimum 32 characters)")
			}
			if jwtSecret == "REPLACE_WITH_A_STRONG_RANDOM_SECRET" || 
			   jwtSecret == "your-secret-key-change-in-production" {
				warnings = append(warnings, "JWT secret is using default placeholder value")
			}
		} else {
			warnings = append(warnings, "JWT secret is missing")
		}
	}

	// Check TLS configuration
	if sync, ok := config["sync"].(map[interface{}]interface{}); ok {
		if tls, ok := sync["tls"].(map[interface{}]interface{}); ok {
			if insecureSkip, ok := tls["insecure_skip_verify"].(bool); ok && insecureSkip {
				warnings = append(warnings, "TLS certificate verification is disabled (insecure)")
			}
		}
	}

	return warnings, nil
}