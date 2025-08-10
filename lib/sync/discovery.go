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
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
	"go.uber.org/zap"
)

// DiscoveryService manages peer discovery using mDNS.
type DiscoveryService struct {
	nodeID     string
	serviceName string
	port       int
	logger     *zap.Logger
	server     *mdns.Server
	mutex      sync.RWMutex
	onPeerFound func(nodeID, address string, port int)
	stopChan   chan struct{}
}

// DiscoveryConfig defines discovery configuration.
type DiscoveryConfig struct {
	Enable      bool   `yaml:"enable"`
	ServiceName string `yaml:"service_name"`
	Domain      string `yaml:"domain"`
}

// NewDiscoveryService creates a new peer discovery service.
func NewDiscoveryService(nodeID string, port int, config DiscoveryConfig, logger *zap.Logger) *DiscoveryService {
	serviceName := config.ServiceName
	if serviceName == "" {
		serviceName = "_krakenfs._tcp"
	}

	return &DiscoveryService{
		nodeID:      nodeID,
		serviceName: serviceName,
		port:        port,
		logger:      logger,
		stopChan:    make(chan struct{}),
	}
}

// Start starts the discovery service.
func (ds *DiscoveryService) Start() error {
	// Start mDNS server for advertising this node
	if err := ds.startMDNSServer(); err != nil {
		return fmt.Errorf("start mDNS server: %w", err)
	}

	// Start mDNS client for discovering peers
	go ds.startMDNSClient()

	ds.logger.Info("Peer discovery service started",
		zap.String("node_id", ds.nodeID),
		zap.String("service_name", ds.serviceName),
		zap.Int("port", ds.port))

	return nil
}

// Stop stops the discovery service.
func (ds *DiscoveryService) Stop() {
	close(ds.stopChan)

	if ds.server != nil {
		ds.server.Shutdown()
	}

	ds.logger.Info("Peer discovery service stopped")
}

// SetPeerFoundCallback sets the callback function for when a new peer is found.
func (ds *DiscoveryService) SetPeerFoundCallback(callback func(nodeID, address string, port int)) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	ds.onPeerFound = callback
}

// startMDNSServer starts the mDNS server to advertise this node.
func (ds *DiscoveryService) startMDNSServer() error {
	// Get local IP addresses
	ips, err := getLocalIPs()
	if err != nil {
		return fmt.Errorf("get local IPs: %w", err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no local IP addresses found")
	}

	// Create mDNS service
	service, err := mdns.NewMDNSService(
		ds.nodeID,           // instance name
		ds.serviceName,      // service type
		"",                  // domain (empty for .local)
		"",                  // host name (empty for auto)
		ds.port,             // port
		ips,                 // IP addresses
		[]string{            // TXT records
			fmt.Sprintf("node_id=%s", ds.nodeID),
			"version=1.0",
		},
	)
	if err != nil {
		return fmt.Errorf("create mDNS service: %w", err)
	}

	// Create and start mDNS server
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return fmt.Errorf("create mDNS server: %w", err)
	}

	ds.server = server
	return nil
}

// startMDNSClient starts the mDNS client to discover peers.
func (ds *DiscoveryService) startMDNSClient() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Perform initial discovery
	ds.discoverPeers()

	for {
		select {
		case <-ticker.C:
			ds.discoverPeers()
		case <-ds.stopChan:
			return
		}
	}
}

// discoverPeers performs mDNS lookup to discover peers.
func (ds *DiscoveryService) discoverPeers() {
	ds.logger.Debug("Discovering peers via mDNS")

	// Create entries channel
	entriesCh := make(chan *mdns.ServiceEntry, 4)

	// Start mDNS lookup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		defer close(entriesCh)
		err := mdns.Lookup(ds.serviceName, entriesCh)
		if err != nil {
			ds.logger.Error("mDNS lookup failed", zap.Error(err))
		}
	}()

	// Process discovered entries
	for {
		select {
		case entry := <-entriesCh:
			if entry == nil {
				return // Channel closed
			}
			ds.handleDiscoveredPeer(entry)
		case <-ctx.Done():
			return // Timeout
		case <-ds.stopChan:
			return // Stopped
		}
	}
}

// handleDiscoveredPeer processes a discovered peer.
func (ds *DiscoveryService) handleDiscoveredPeer(entry *mdns.ServiceEntry) {
	// Extract node ID from TXT records
	nodeID := ds.extractNodeID(entry.InfoFields)
	if nodeID == "" {
		ds.logger.Warn("Discovered peer without node_id", 
			zap.String("name", entry.Name))
		return
	}

	// Skip self
	if nodeID == ds.nodeID {
		return
	}

	// Get IP address
	var ip string
	if entry.AddrV4 != nil {
		ip = entry.AddrV4.String()
	} else if entry.AddrV6 != nil {
		ip = entry.AddrV6.String()
	} else {
		ds.logger.Warn("Discovered peer without IP address",
			zap.String("node_id", nodeID))
		return
	}

	ds.logger.Debug("Discovered peer",
		zap.String("node_id", nodeID),
		zap.String("ip", ip),
		zap.Int("port", entry.Port))

	// Notify callback
	ds.mutex.RLock()
	callback := ds.onPeerFound
	ds.mutex.RUnlock()

	if callback != nil {
		callback(nodeID, ip, entry.Port)
	}
}

// extractNodeID extracts the node ID from TXT records.
func (ds *DiscoveryService) extractNodeID(txtRecords []string) string {
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "node_id=") {
			return strings.TrimPrefix(record, "node_id=")
		}
	}
	return ""
}

// getLocalIPs returns local IP addresses.
func getLocalIPs() ([]net.IP, error) {
	var ips []net.IP

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP)
			}
		}
	}

	return ips, nil
}

// PeerInfo represents information about a discovered peer.
type PeerInfo struct {
	NodeID  string    `json:"node_id"`
	Address string    `json:"address"`
	Port    int       `json:"port"`
	LastSeen time.Time `json:"last_seen"`
}

// String returns a string representation of the peer info.
func (pi *PeerInfo) String() string {
	return fmt.Sprintf("%s@%s:%d", pi.NodeID, pi.Address, pi.Port)
}