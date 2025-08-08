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
package network

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/uber/krakenfs/lib/sync"
)

// PeerInfo represents information about a peer in the network.
type PeerInfo struct {
	ID       string
	Addr     string
	Port     int
	LastSeen time.Time
}

// Discovery manages peer discovery in the P2P network.
type Discovery struct {
	nodeID       string
	peers        map[string]*PeerInfo
	clusterNodes []string
	tlsManager   *sync.TLSManager
}

// NewDiscovery creates a new peer discovery manager.
func NewDiscovery(nodeID string, clusterNodes []string) *Discovery {
	return &Discovery{
		nodeID:       nodeID,
		peers:        make(map[string]*PeerInfo),
		clusterNodes: clusterNodes,
	}
}

// SetTLSManager sets the TLS manager for secure connections.
func (d *Discovery) SetTLSManager(tlsManager *sync.TLSManager) {
	d.tlsManager = tlsManager
}

// DiscoverPeers discovers peers in the cluster.
func (d *Discovery) DiscoverPeers() ([]*PeerInfo, error) {
	var peers []*PeerInfo

	for _, nodeAddr := range d.clusterNodes {
		if nodeAddr == d.nodeID {
			continue // Skip self
		}

		// Parse node address (format: "node:ip")
		parts := strings.Split(nodeAddr, ":")
		if len(parts) != 2 {
			continue
		}

		nodeID := parts[0]
		addr := parts[1]

		// Try to connect to peer
		if peer, err := d.connectToPeer(nodeID, addr); err == nil {
			peers = append(peers, peer)
			d.peers[nodeID] = peer
		}
	}

	return peers, nil
}

// connectToPeer attempts to connect to a peer.
func (d *Discovery) connectToPeer(nodeID, addr string) (*PeerInfo, error) {
	// Parse address and port
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid address format: %s", addr)
	}

	host := parts[0]
	port := parts[1]

	// Connect to peer
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return nil, fmt.Errorf("connect to peer: %s", err)
	}

	// Wrap connection with TLS if enabled
	if d.tlsManager != nil {
		conn, err = d.tlsManager.WrapConnection(conn, true) // true = client mode
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("wrap connection with TLS: %s", err)
		}
	}

	// Close connection after testing
	conn.Close()

	// Create peer info
	peer := &PeerInfo{
		ID:       nodeID,
		Addr:     addr,
		Port:     6881, // Default P2P port
		LastSeen: time.Now(),
	}

	return peer, nil
}

// GetPeer returns a specific peer by ID.
func (d *Discovery) GetPeer(nodeID string) (*PeerInfo, error) {
	peer, exists := d.peers[nodeID]
	if !exists {
		return nil, fmt.Errorf("peer not found: %s", nodeID)
	}
	return peer, nil
}

// ListPeers returns all known peers.
func (d *Discovery) ListPeers() []*PeerInfo {
	peers := make([]*PeerInfo, 0, len(d.peers))
	for _, peer := range d.peers {
		peers = append(peers, peer)
	}
	return peers
}
