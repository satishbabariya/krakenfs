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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
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
	Storage            StorageConfig            `yaml:"storage"`
	Discovery          DiscoveryConfig          `yaml:"discovery"`
	Recovery           RecoveryConfig           `yaml:"recovery"`
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

	// Storage
	storage *Storage

	// Discovery service
	discovery *DiscoveryService

	// Bandwidth limiter
	bandwidthLimiter *BandwidthLimiter

	// Recovery manager
	recoveryManager *RecoveryManager

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

	// Initialize storage
	storage, err := NewStorage(config.Storage, logger)
	if err != nil {
		return nil, fmt.Errorf("create storage: %s", err)
	}

	// Initialize TLS manager
	tlsManager := NewTLSManager(config.TLS, logger)

	// Generate self-signed certificate if TLS is enabled
	if config.TLS.Enable {
		if err := tlsManager.GenerateSelfSignedCert(config.NodeID); err != nil {
			storage.Close()
			return nil, fmt.Errorf("generate TLS certificate: %s", err)
		}

		// Wrap listener with TLS
		listener, err = tlsManager.WrapListener(listener)
		if err != nil {
			storage.Close()
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
		storage:    storage,
		fileTracker: &FileTracker{
			files: make(map[string]*FileState),
		},
		protocol:         NewProtocol(config.NodeID, "1.0", logger),
		fileTransfer:     NewFileTransfer(DefaultChunkSize, logger),
		conflictResolver: NewConflictResolver(ConflictStrategy(config.ConflictResolution.Strategy), logger),
	}

	// Set TLS manager in protocol
	engine.protocol.SetTLSManager(tlsManager)

	// Initialize discovery service if enabled
	if config.Discovery.Enable {
		discovery := NewDiscoveryService(config.NodeID, config.P2PPort, config.Discovery, logger)
		discovery.SetPeerFoundCallback(engine.onPeerDiscovered)
		engine.discovery = discovery
	}

	// Initialize bandwidth limiter
	bandwidthLimiter := NewBandwidthLimiter(config.Bandwidth, logger)
	engine.bandwidthLimiter = bandwidthLimiter

	// Initialize recovery manager
	recoveryManager := NewRecoveryManager(config.Recovery, logger)
	engine.recoveryManager = recoveryManager

	// Load existing file states from storage
	if err := engine.loadFileStates(); err != nil {
		storage.Close()
		return nil, fmt.Errorf("load file states: %s", err)
	}

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

	// Start mDNS discovery service if enabled
	if e.discovery != nil {
		if err := e.discovery.Start(); err != nil {
			e.logger.Error("Failed to start discovery service", zap.Error(err))
		}
	}

	return nil
}

// Stop stops the sync engine.
func (e *Engine) Stop() {
	e.logger.Info("Stopping sync engine")
	close(e.stopChan)
	e.listener.Close()
	e.wg.Wait()
	
	// Stop discovery service
	if e.discovery != nil {
		e.discovery.Stop()
	}

	// Close storage
	if e.storage != nil {
		if err := e.storage.Close(); err != nil {
			e.logger.Error("Error closing storage", zap.Error(err))
		}
	}
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

	// Apply bandwidth limiting
	conn = e.bandwidthLimiter.WrapConnection(conn)

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

	switch event.Operation {
	case filesystem.Remove:
		// Handle file deletion
		e.handleFileRemoval(event.Path)
	case filesystem.Create, filesystem.Write:
		// Handle file creation or modification
		e.handleFileChange(event)
	case filesystem.Rename:
		// Handle file rename (treat as delete + create)
		e.handleFileRename(event)
	default:
		e.logger.Debug("Ignoring file event", 
			zap.String("path", event.Path),
			zap.String("operation", event.Operation.String()))
	}
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
		// Receive any message from peer
		msg, err := e.protocol.receiveMessage(peer.Conn)
		if err != nil {
			e.logger.Error("Failed to receive message from peer",
				zap.String("peer_id", peer.ID),
				zap.Error(err))
			return
		}

		// Handle message based on type
		switch msg.Type {
		case FileEventMessage:
			e.handleFileEventMessage(peer, msg)
		case FileTransferRequest:
			e.handleFileTransferRequest(peer, msg)
		case FileTransferData:
			e.handleFileTransferData(peer, msg)
		case FileTransferComplete:
			e.handleFileTransferComplete(peer, msg)
		case HeartbeatMessage:
			e.handleHeartbeat(peer, msg)
		default:
			e.logger.Warn("Unknown message type from peer",
				zap.String("peer_id", peer.ID),
				zap.Uint8("message_type", uint8(msg.Type)))
		}
	}
}

// discoverPeers discovers and connects to peers in the cluster.
func (e *Engine) discoverPeers() {
	for _, nodeAddr := range e.config.ClusterNodes {
		// Parse node format: "node_id:ip_address:port" or "node_id:ip_address"
		parts := parseNodeAddr(nodeAddr)
		if len(parts) < 2 {
			e.logger.Warn("Invalid node address format", zap.String("addr", nodeAddr))
			continue
		}
		
		nodeID := parts[0]
		if nodeID == e.config.NodeID {
			continue // Skip self
		}

		// Check if we're already connected to this peer
		e.peerMutex.RLock()
		_, exists := e.peers[nodeID]
		e.peerMutex.RUnlock()
		
		if exists {
			continue // Already connected
		}

		// Try to connect to peer
		go e.connectToPeer(nodeID, parts[1], parts[2])
	}
}

// loadFileStates loads existing file states from storage.
func (e *Engine) loadFileStates() error {
	states, err := e.storage.ListFileStates()
	if err != nil {
		return fmt.Errorf("list file states: %w", err)
	}

	for _, state := range states {
		e.fileTracker.files[state.Path] = state
	}

	e.logger.Info("Loaded file states from storage", zap.Int("count", len(states)))
	return nil
}

// handleFileChange handles file creation or modification.
func (e *Engine) handleFileChange(event filesystem.FileChangeEvent) {
	// Calculate file hash and size
	hash, size, err := e.calculateFileHash(event.Path)
	if err != nil {
		e.logger.Error("Failed to calculate file hash",
			zap.String("path", event.Path),
			zap.Error(err))
		return
	}

	// Get existing state
	existingState := e.fileTracker.files[event.Path]
	
	// Create new state
	newState := &FileState{
		Path:     event.Path,
		Hash:     hash,
		Size:     size,
		Modified: event.Timestamp,
		NodeID:   event.NodeID,
		Version:  1,
	}

	if existingState != nil {
		newState.Version = existingState.Version + 1
		
		// Check if file actually changed
		if existingState.Hash == hash {
			e.logger.Debug("File hash unchanged, skipping update",
				zap.String("path", event.Path))
			return
		}
	}

	// Update in-memory tracker
	e.fileTracker.files[event.Path] = newState

	// Save to persistent storage
	if err := e.storage.SaveFileState(newState); err != nil {
		e.logger.Error("Failed to save file state",
			zap.String("path", event.Path),
			zap.Error(err))
	}

	e.logger.Debug("Updated file state",
		zap.String("path", event.Path),
		zap.String("hash", hash),
		zap.Int64("size", size),
		zap.Int("version", newState.Version))
}

// handleFileRemoval handles file deletion.
func (e *Engine) handleFileRemoval(path string) {
	// Remove from in-memory tracker
	delete(e.fileTracker.files, path)

	// Remove from persistent storage
	if err := e.storage.DeleteFileState(path); err != nil {
		e.logger.Error("Failed to delete file state",
			zap.String("path", path),
			zap.Error(err))
	}

	e.logger.Debug("Removed file state", zap.String("path", path))
}

// handleFileRename handles file rename operations.
func (e *Engine) handleFileRename(event filesystem.FileChangeEvent) {
	// For rename operations, we treat it as a delete of the old file
	// and creation of the new file. The filesystem watcher should 
	// generate separate events for this.
	e.handleFileChange(event)
}

// calculateFileHash calculates SHA256 hash and size of a file.
func (e *Engine) calculateFileHash(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("read file: %w", err)
	}

	hashString := hex.EncodeToString(hash.Sum(nil))
	return hashString, size, nil
}

// connectToPeer attempts to connect to a peer with retry logic.
func (e *Engine) connectToPeer(nodeID, host, port string) {
	addr := fmt.Sprintf("%s:%s", host, port)
	operationName := fmt.Sprintf("connect_to_peer_%s", nodeID)
	
	// Use recovery manager for connection attempts
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result := e.recoveryManager.ExecuteWithRetry(ctx, operationName, func() error {
		e.logger.Debug("Attempting to connect to peer",
			zap.String("node_id", nodeID),
			zap.String("addr", addr))

		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return ClassifyError(err)
		}

		// Handle the connection as an outgoing connection
		go e.handleOutgoingConnection(conn, nodeID)
		return nil
	})

	if !result.Success {
		e.logger.Error("Failed to connect to peer after all retries",
			zap.String("node_id", nodeID),
			zap.String("addr", addr),
			zap.Int("attempts", result.Attempts),
			zap.Duration("total_delay", result.TotalDelay),
			zap.Error(result.Error))
	}
}

// handleOutgoingConnection handles an outgoing connection to a peer.
func (e *Engine) handleOutgoingConnection(conn net.Conn, expectedNodeID string) {
	defer conn.Close()

	// Apply bandwidth limiting
	conn = e.bandwidthLimiter.WrapConnection(conn)

	// Wrap connection with TLS if enabled
	if e.tlsManager != nil {
		var err error
		conn, err = e.tlsManager.WrapConnection(conn, true) // true = client mode
		if err != nil {
			e.logger.Error("Failed to wrap outgoing connection with TLS",
				zap.String("expected_node_id", expectedNodeID),
				zap.Error(err))
			return
		}
	}

	// Perform handshake
	peer, err := e.protocol.Handshake(conn)
	if err != nil {
		e.logger.Error("Outgoing handshake failed",
			zap.String("expected_node_id", expectedNodeID),
			zap.Error(err))
		return
	}

	// Verify peer ID matches expected
	if peer.ID != expectedNodeID {
		e.logger.Warn("Peer ID mismatch",
			zap.String("expected", expectedNodeID),
			zap.String("actual", peer.ID))
		return
	}

	// Add peer to our list
	e.peerMutex.Lock()
	e.peers[peer.ID] = peer
	e.peerMutex.Unlock()

	// Save peer info to storage
	if err := e.storage.SavePeerInfo(peer); err != nil {
		e.logger.Error("Failed to save peer info",
			zap.String("peer_id", peer.ID),
			zap.Error(err))
	}

	e.logger.Info("Connected to peer successfully",
		zap.String("peer_id", peer.ID),
		zap.String("peer_addr", peer.Addr))

	// Start peer message handling
	e.handlePeerMessages(peer)
}

// parseNodeAddr parses node address in format "node_id:ip_address:port" or "node_id:ip_address".
func parseNodeAddr(addr string) []string {
	parts := make([]string, 3)
	
	// Split by colon
	segments := strings.Split(addr, ":")
	if len(segments) < 2 {
		return nil
	}
	
	parts[0] = segments[0] // node_id
	parts[1] = segments[1] // ip_address
	
	if len(segments) >= 3 {
		parts[2] = segments[2] // port
	} else {
		parts[2] = "6881" // default port
	}
	
	return parts
}

// onPeerDiscovered is called when a new peer is discovered via mDNS.
func (e *Engine) onPeerDiscovered(nodeID, address string, port int) {
	e.logger.Debug("Peer discovered via mDNS",
		zap.String("node_id", nodeID),
		zap.String("address", address),
		zap.Int("port", port))

	// Check if we're already connected to this peer
	e.peerMutex.RLock()
	_, exists := e.peers[nodeID]
	e.peerMutex.RUnlock()

	if exists {
		return // Already connected
	}

	// Try to connect to the discovered peer
	go e.connectToPeer(nodeID, address, strconv.Itoa(port))
}

// handleFileEventMessage handles file event messages from peers.
func (e *Engine) handleFileEventMessage(peer *Peer, msg *Message) {
	var fileEventMsg FileEventPayload
	if err := json.Unmarshal(msg.Payload, &fileEventMsg); err != nil {
		e.logger.Error("Failed to unmarshal file event",
			zap.String("peer_id", peer.ID),
			zap.Error(err))
		return
	}

	event := fileEventMsg.Event
	e.logger.Info("Received file event from peer",
		zap.String("peer_id", peer.ID),
		zap.String("path", event.Path),
		zap.String("operation", event.Operation.String()))

	// Check if we need to request the file
	if event.Operation == filesystem.Create || event.Operation == filesystem.Write {
		e.requestFileIfNeeded(peer, event)
	}

	// Process the event locally
	e.handleFileEvent(event)
}

// handleFileTransferRequest handles file transfer requests from peers.
func (e *Engine) handleFileTransferRequest(peer *Peer, msg *Message) {
	var req FileTransferRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		e.logger.Error("Failed to unmarshal file transfer request",
			zap.String("peer_id", peer.ID),
			zap.Error(err))
		return
	}

	e.logger.Info("Received file transfer request",
		zap.String("peer_id", peer.ID),
		zap.String("file_path", req.FilePath),
		zap.String("file_hash", req.FileHash))

	// Check if we have the file and it matches the hash
	if e.shouldSendFile(req) {
		go e.sendFileToRequestingPeer(peer, req)
	}
}

// handleFileTransferData handles file transfer data from peers.
func (e *Engine) handleFileTransferData(peer *Peer, msg *Message) {
	// This would be handled by an active file receiver
	// For now, just log it
	e.logger.Debug("Received file transfer data",
		zap.String("peer_id", peer.ID))
}

// handleFileTransferComplete handles file transfer completion from peers.
func (e *Engine) handleFileTransferComplete(peer *Peer, msg *Message) {
	var complete FileTransferCompletePayload
	if err := json.Unmarshal(msg.Payload, &complete); err != nil {
		e.logger.Error("Failed to unmarshal file transfer complete",
			zap.String("peer_id", peer.ID),
			zap.Error(err))
		return
	}

	e.logger.Info("File transfer completed",
		zap.String("peer_id", peer.ID),
		zap.String("file_hash", complete.FileHash),
		zap.Bool("success", complete.Success))
}

// handleHeartbeat handles heartbeat messages from peers.
func (e *Engine) handleHeartbeat(peer *Peer, msg *Message) {
	// Update peer's last seen time
	peer.LastSeen = time.Now()

	// Send heartbeat acknowledgment
	heartbeatAck := map[string]interface{}{
		"node_id":   e.config.NodeID,
		"timestamp": time.Now(),
	}

	if err := e.protocol.sendMessage(peer.Conn, HeartbeatAck, heartbeatAck); err != nil {
		e.logger.Error("Failed to send heartbeat ack",
			zap.String("peer_id", peer.ID),
			zap.Error(err))
	}
}

// requestFileIfNeeded checks if we need to request a file from a peer.
func (e *Engine) requestFileIfNeeded(peer *Peer, event filesystem.FileChangeEvent) {
	// Check if we have this file locally
	localState := e.fileTracker.files[event.Path]
	
	// If we don't have the file, or our version is older, request it
	shouldRequest := false
	if localState == nil {
		shouldRequest = true
		e.logger.Debug("File not found locally, requesting from peer",
			zap.String("path", event.Path),
			zap.String("peer_id", peer.ID))
	} else if event.Timestamp.After(localState.Modified) {
		shouldRequest = true
		e.logger.Debug("Local file is older, requesting from peer",
			zap.String("path", event.Path),
			zap.String("peer_id", peer.ID),
			zap.Time("local_modified", localState.Modified),
			zap.Time("remote_modified", event.Timestamp))
	}

	if shouldRequest {
		go e.requestFile(peer, event.Path)
	}
}

// requestFile requests a file from a peer.
func (e *Engine) requestFile(peer *Peer, filePath string) {
	req := FileTransferRequestPayload{
		FilePath:  filePath,
		Timestamp: time.Now(),
	}

	if err := e.protocol.sendMessage(peer.Conn, FileTransferRequest, req); err != nil {
		e.logger.Error("Failed to request file from peer",
			zap.String("peer_id", peer.ID),
			zap.String("file_path", filePath),
			zap.Error(err))
	}
}

// shouldSendFile checks if we should send a file to a requesting peer.
func (e *Engine) shouldSendFile(req FileTransferRequestPayload) bool {
	// Check if we have the file
	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		return false
	}

	// If a file hash is provided, verify it matches
	if req.FileHash != "" {
		hash, _, err := e.calculateFileHash(req.FilePath)
		if err != nil {
			e.logger.Error("Failed to calculate file hash",
				zap.String("file_path", req.FilePath),
				zap.Error(err))
			return false
		}
		return hash == req.FileHash
	}

	return true
}

// sendFileToRequestingPeer sends a file to a peer that requested it.
func (e *Engine) sendFileToRequestingPeer(peer *Peer, req FileTransferRequestPayload) {
	e.logger.Info("Sending file to peer",
		zap.String("peer_id", peer.ID),
		zap.String("file_path", req.FilePath))

	if err := e.fileTransfer.SendFile(peer, req.FilePath, e.protocol); err != nil {
		e.logger.Error("Failed to send file to peer",
			zap.String("peer_id", peer.ID),
			zap.String("file_path", req.FilePath),
			zap.Error(err))
	}
}
