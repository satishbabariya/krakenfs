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
	"fmt"
	"net"
	"os"
	"strings"

	"go.uber.org/zap"
)

// IPResolver handles IP address resolution for cluster nodes.
type IPResolver struct {
	logger *zap.Logger
}

// NewIPResolver creates a new IP resolver.
func NewIPResolver(logger *zap.Logger) *IPResolver {
	return &IPResolver{
		logger: logger,
	}
}

// ResolveClusterNodes resolves IP addresses for cluster nodes.
// Supports formats:
// - "node1:192.168.1.10" (static IP)
// - "node1:auto" (auto-detect IP)
// - "node1:${NODE1_IP}" (environment variable)
// - "node1:hostname" (DNS resolution)
func (r *IPResolver) ResolveClusterNodes(clusterNodes []string) ([]string, error) {
	var resolvedNodes []string

	for _, node := range clusterNodes {
		resolved, err := r.resolveNode(node)
		if err != nil {
			r.logger.Warn("Failed to resolve node",
				zap.String("node", node),
				zap.Error(err))
			continue
		}
		resolvedNodes = append(resolvedNodes, resolved)
	}

	return resolvedNodes, nil
}

// resolveNode resolves a single node address.
func (r *IPResolver) resolveNode(node string) (string, error) {
	parts := strings.Split(node, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid node format: %s (expected 'nodeID:address')", node)
	}

	nodeID := parts[0]
	address := parts[1]

	// Handle different address types
	switch {
	case address == "auto":
		// Auto-detect local IP
		ip, err := r.getLocalIP()
		if err != nil {
			return "", fmt.Errorf("auto-detect IP for %s: %w", nodeID, err)
		}
		return fmt.Sprintf("%s:%s", nodeID, ip), nil

	case strings.HasPrefix(address, "${") && strings.HasSuffix(address, "}"):
		// Environment variable
		envVar := strings.TrimSuffix(strings.TrimPrefix(address, "${"), "}")
		ip := os.Getenv(envVar)
		if ip == "" {
			return "", fmt.Errorf("environment variable %s not set for node %s", envVar, nodeID)
		}
		return fmt.Sprintf("%s:%s", nodeID, ip), nil

	case net.ParseIP(address) != nil:
		// Already a valid IP address
		return node, nil

	default:
		// Try DNS resolution
		ip, err := r.resolveHostname(address)
		if err != nil {
			return "", fmt.Errorf("resolve hostname %s for node %s: %w", address, nodeID, err)
		}
		return fmt.Sprintf("%s:%s", nodeID, ip), nil
	}
}

// getLocalIP gets the local machine's primary IP address.
func (r *IPResolver) getLocalIP() (string, error) {
	// Try to get IP by connecting to a remote address (doesn't actually connect)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		// Fallback to interface enumeration
		return r.getLocalIPFromInterfaces()
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// getLocalIPFromInterfaces gets local IP by enumerating network interfaces.
func (r *IPResolver) getLocalIPFromInterfaces() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no suitable local IP address found")
}

// resolveHostname resolves a hostname to an IP address.
func (r *IPResolver) resolveHostname(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("lookup IP for hostname %s: %w", hostname, err)
	}

	for _, ip := range ips {
		if ip.To4() != nil { // Prefer IPv4
			return ip.String(), nil
		}
	}

	if len(ips) > 0 {
		return ips[0].String(), nil // Fallback to first IP (might be IPv6)
	}

	return "", fmt.Errorf("no IP addresses found for hostname %s", hostname)
}

// GetPreferredIP returns the preferred IP address for this node.
// It checks environment variables first, then auto-detects.
func (r *IPResolver) GetPreferredIP() (string, error) {
	// Check common environment variables
	envVars := []string{"KRAKENFS_IP", "NODE_IP", "POD_IP", "HOST_IP"}
	for _, envVar := range envVars {
		if ip := os.Getenv(envVar); ip != "" {
			if net.ParseIP(ip) != nil {
				r.logger.Info("Using IP from environment variable",
					zap.String("env_var", envVar),
					zap.String("ip", ip))
				return ip, nil
			}
		}
	}

	// Auto-detect
	return r.getLocalIP()
}

// ExpandEnvironmentVariables expands environment variables in cluster node addresses.
func (r *IPResolver) ExpandEnvironmentVariables(input string) string {
	return os.ExpandEnv(input)
}