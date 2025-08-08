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
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/uber-go/tally"
	"go.uber.org/zap"

	"github.com/uber/krakenfs/lib/filesystem"
)

// Config defines sync engine configuration.
type Config struct {
	NodeID             string                   `yaml:"node_id"`
	ClusterNodes       []string                 `yaml:"cluster_nodes"`
	P2PPort            int                      `yaml:"p2p_port"`
	TrackerPort        int                      `yaml:"tracker_port"`
	Bandwidth          BandwidthConfig          `yaml:"bandwidth"`
	ConflictResolution ConflictResolutionConfig `yaml:"conflict_resolution"`
	TLS                TLSConfig                `yaml:"tls"`
}

// BandwidthConfig defines bandwidth limiting configuration.
type BandwidthConfig struct {
	Enable            bool  `yaml:"enable"`
	EgressBitsPerSec  int64 `yaml:"egress_bits_per_sec"`
	IngressBitsPerSec int64 `yaml:"ingress_bits_per_sec"`
}

// ConflictResolutionConfig defines conflict resolution configuration.
type ConflictResolutionConfig struct {
	Strategy string `yaml:"strategy"` // "timestamp", "manual", "last_write_wins"
	Timeout  string `yaml:"timeout"`
}

// TLSConfig defines TLS/SSL configuration for secure communication.
type TLSConfig struct {
	Enable             bool   `yaml:"enable"`
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	CAFile             string `yaml:"ca_file"`
	VerifyPeer         bool   `yaml:"verify_peer"`
	MinVersion         string `yaml:"min_version"` // "1.2", "1.3"
	MaxVersion         string `yaml:"max_version"` // "1.2", "1.3"
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Engine manages P2P file synchronization.
type Engine struct {
	config Config
	clock  clock.Clock
	stats  tally.Scope
	logger *zap.Logger

	// Network components
	listener  net.Listener
	peers     map[string]*Peer
	peerMutex sync.RWMutex

	// TLS components
	tlsManager *TLSManager

	// Event handling
	eventChan chan filesystem.FileChangeEvent
	stopChan  chan struct{}
	wg        sync.WaitGroup

	// File tracking
	fileTracker *FileTracker

	// Protocol and transfer components
	protocol         *Protocol
	fileTransfer     *FileTransfer
	conflictResolver *ConflictResolver
}

// Peer represents a connected peer in the P2P network.
type Peer struct {
	ID       string
	Addr     string
	Conn     net.Conn
	LastSeen time.Time
}

// FileTracker tracks file state across the cluster.
type FileTracker struct {
	files map[string]*FileState
	mutex sync.RWMutex
}

// FileState represents the state of a file in the cluster.
type FileState struct {
	Path     string
	Hash     string
	Size     int64
	Modified time.Time
	NodeID   string
	Version  int
}

// NewEngine creates a new sync engine.
func NewEngine(config Config, logger *zap.Logger) (*Engine, error) {
	// Create listener for P2P connections
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.P2PPort))
	if err != nil {
		return nil, fmt.Errorf("create listener: %s", err)
	}

	// Initialize TLS manager
	tlsManager := NewTLSManager(config.TLS, logger)

	// Generate self-signed certificate if TLS is enabled
	if config.TLS.Enable {
		if err := tlsManager.GenerateSelfSignedCert(config.NodeID); err != nil {
			return nil, fmt.Errorf("generate TLS certificate: %s", err)
		}

		// Wrap listener with TLS
		listener, err = tlsManager.WrapListener(listener)
		if err != nil {
			return nil, fmt.Errorf("wrap listener with TLS: %s", err)
		}
	}

	engine := &Engine{
		config:     config,
		clock:      clock.New(),
		logger:     logger,
		listener:   listener,
		peers:      make(map[string]*Peer),
		tlsManager: tlsManager,
		eventChan:  make(chan filesystem.FileChangeEvent, 100),
		stopChan:   make(chan struct{}),
		fileTracker: &FileTracker{
			files: make(map[string]*FileState),
		},
		protocol:         NewProtocol(config.NodeID, "1.0", logger),
		fileTransfer:     NewFileTransfer(DefaultChunkSize, logger),
		conflictResolver: NewConflictResolver(ConflictStrategy(config.ConflictResolution.Strategy), logger),
	}

	// Set TLS manager in protocol
	engine.protocol.SetTLSManager(tlsManager)

	return engine, nil
}

// Start starts the sync engine.
func (e *Engine) Start() error {
	e.logger.Info("Starting sync engine",
		zap.String("node_id", e.config.NodeID),
		zap.Int("p2p_port", e.config.P2PPort))

	// Start listening for peer connections
	e.wg.Add(1)
	go e.listenLoop()

	// Start event processing loop
	e.wg.Add(1)
	go e.eventLoop()

	// Start peer discovery
	e.wg.Add(1)
	go e.discoveryLoop()

	return nil
}

// Stop stops the sync engine.
func (e *Engine) Stop() {
	e.logger.Info("Stopping sync engine")
	close(e.stopChan)
	e.listener.Close()
	e.wg.Wait()
}

// ProcessEvent processes a file change event.
func (e *Engine) ProcessEvent(event filesystem.FileChangeEvent) {
	select {
	case e.eventChan <- event:
		e.logger.Debug("Queued file change event",
			zap.String("path", event.Path),
			zap.String("operation", event.Operation.String()))
	default:
		e.logger.Warn("Event channel full, dropping event",
			zap.String("path", event.Path))
	}
}

// listenLoop accepts incoming peer connections.
func (e *Engine) listenLoop() {
	defer e.wg.Done()

	e.logger.Info("Listening for peers", zap.String("addr", e.listener.Addr().String()))
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			select {
			case <-e.stopChan:
				return
			default:
				e.logger.Error("Error accepting connection", zap.Error(err))
				continue
			}
		}

		go e.handlePeerConnection(conn)
	}
}

// eventLoop processes file change events.
func (e *Engine) eventLoop() {
	defer e.wg.Done()

	for {
		select {
		case event := <-e.eventChan:
			e.handleFileEvent(event)
		case <-e.stopChan:
			return
		}
	}
}

// discoveryLoop periodically discovers and connects to peers.
func (e *Engine) discoveryLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.discoverPeers()
		case <-e.stopChan:
			return
		}
	}
}

// handlePeerConnection handles a new peer connection.
func (e *Engine) handlePeerConnection(conn net.Conn) {
	defer conn.Close()

	// Perform handshake
	peer, err := e.protocol.Handshake(conn)
	if err != nil {
		e.logger.Error("Handshake failed", zap.String("addr", conn.RemoteAddr().String()), zap.Error(err))
		return
	}

	// Add peer to our list
	e.peerMutex.Lock()
	e.peers[peer.ID] = peer
	e.peerMutex.Unlock()

	e.logger.Info("Peer connected successfully",
		zap.String("peer_id", peer.ID),
		zap.String("peer_addr", peer.Addr))

	// Start peer message handling
	go e.handlePeerMessages(peer)
}

// handleFileEvent processes a file change event.
func (e *Engine) handleFileEvent(event filesystem.FileChangeEvent) {
	e.logger.Info("Processing file event",
		zap.String("path", event.Path),
		zap.String("operation", event.Operation.String()),
		zap.String("node_id", event.NodeID))

	// Update local file tracker
	e.updateFileState(event)

	// Propagate to peers
	e.propagateToPeers(event)
}

// updateFileState updates the local file tracker.
func (e *Engine) updateFileState(event filesystem.FileChangeEvent) {
	e.fileTracker.mutex.Lock()
	defer e.fileTracker.mutex.Unlock()

	// TODO: Implement file state tracking
	e.logger.Debug("Updated file state", zap.String("path", event.Path))
}

// propagateToPeers propagates a file event to all connected peers.
func (e *Engine) propagateToPeers(event filesystem.FileChangeEvent) {
	e.peerMutex.RLock()
	defer e.peerMutex.RUnlock()

	for _, peer := range e.peers {
		// Send file event to peer
		if err := e.protocol.SendFileEvent(peer, event); err != nil {
			e.logger.Error("Failed to send file event to peer",
				zap.String("peer_id", peer.ID),
				zap.String("path", event.Path),
				zap.Error(err))
			continue
		}

		e.logger.Debug("Propagated file event to peer",
			zap.String("peer_id", peer.ID),
			zap.String("path", event.Path),
			zap.String("operation", event.Operation.String()))
	}
}

// handlePeerMessages handles incoming messages from a peer.
func (e *Engine) handlePeerMessages(peer *Peer) {
	defer func() {
		e.peerMutex.Lock()
		delete(e.peers, peer.ID)
		e.peerMutex.Unlock()
		peer.Conn.Close()
	}()

	for {
		// Receive file event
		event, err := e.protocol.ReceiveFileEvent(peer.Conn)
		if err != nil {
			e.logger.Error("Failed to receive file event from peer",
				zap.String("peer_id", peer.ID),
				zap.Error(err))
			return
		}

		// Process the event
		e.handleFileEvent(*event)
	}
}

// discoverPeers discovers and connects to peers in the cluster.
func (e *Engine) discoverPeers() {
	for _, nodeAddr := range e.config.ClusterNodes {
		if nodeAddr == e.config.NodeID {
			continue // Skip self
		}

		// TODO: Implement peer discovery logic
		e.logger.Debug("Discovering peer", zap.String("addr", nodeAddr))
	}
}
