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
	"strings"
	"time"
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
}

// NewDiscovery creates a new peer discovery manager.
func NewDiscovery(nodeID string, clusterNodes []string) *Discovery {
	return &Discovery{
		nodeID:       nodeID,
		peers:        make(map[string]*PeerInfo),
		clusterNodes: clusterNodes,
	}
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
	// For now, just create a peer info without actual connection
	// TODO: Implement actual peer connection logic
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
