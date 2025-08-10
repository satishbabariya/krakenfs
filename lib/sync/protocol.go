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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/uber/krakenfs/lib/filesystem"
	"go.uber.org/zap"
)

// MessageType represents the type of message in the protocol.
type MessageType uint8

const (
	// Handshake messages
	HandshakeRequest  MessageType = 0x01
	HandshakeResponse MessageType = 0x02

	// File event messages
	FileEventMessage MessageType = 0x10
	FileEventAck     MessageType = 0x11

	// File transfer messages
	FileTransferRequest  MessageType = 0x20
	FileTransferData     MessageType = 0x21
	FileTransferComplete MessageType = 0x22

	// Heartbeat messages
	HeartbeatMessage MessageType = 0x30
	HeartbeatAck     MessageType = 0x31
)

// Message represents a protocol message.
type Message struct {
	Type      MessageType `json:"type"`
	Length    uint32      `json:"length"`
	Payload   []byte      `json:"payload"`
	Timestamp time.Time   `json:"timestamp"`
}

// FileEventPayload represents a file change event message.
type FileEventPayload struct {
	Event filesystem.FileChangeEvent `json:"event"`
}

// HandshakeRequestPayload represents a handshake request.
type HandshakeRequestPayload struct {
	NodeID    string    `json:"node_id"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// HandshakeResponsePayload represents a handshake response.
type HandshakeResponsePayload struct {
	NodeID    string    `json:"node_id"`
	Version   string    `json:"version"`
	Accepted  bool      `json:"accepted"`
	Timestamp time.Time `json:"timestamp"`
}

// Protocol manages peer communication.
type Protocol struct {
	nodeID     string
	version    string
	logger     *zap.Logger
	tlsManager *TLSManager
}

// NewProtocol creates a new protocol instance.
func NewProtocol(nodeID, version string, logger *zap.Logger) *Protocol {
	return &Protocol{
		nodeID:  nodeID,
		version: version,
		logger:  logger,
	}
}

// SetTLSManager sets the TLS manager for secure connections.
func (p *Protocol) SetTLSManager(tlsManager *TLSManager) {
	p.tlsManager = tlsManager
}

// Handshake performs a handshake with a peer.
func (p *Protocol) Handshake(conn net.Conn) (*Peer, error) {
	// Wrap connection with TLS if enabled
	if p.tlsManager != nil {
		var err error
		conn, err = p.tlsManager.WrapConnection(conn, false) // false = server mode
		if err != nil {
			return nil, fmt.Errorf("wrap connection with TLS: %s", err)
		}
	}

	// Send handshake request
	req := HandshakeRequestPayload{
		NodeID:    p.nodeID,
		Version:   p.version,
		Timestamp: time.Now(),
	}

	if err := p.sendMessage(conn, HandshakeRequest, req); err != nil {
		return nil, fmt.Errorf("send handshake request: %s", err)
	}

	// Receive handshake response
	msg, err := p.receiveMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive handshake response: %s", err)
	}

	if msg.Type != HandshakeResponse {
		return nil, fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	var resp HandshakeResponsePayload
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal handshake response: %s", err)
	}

	if !resp.Accepted {
		return nil, fmt.Errorf("handshake rejected by peer")
	}

	peer := &Peer{
		ID:       resp.NodeID,
		Addr:     conn.RemoteAddr().String(),
		Conn:     conn,
		LastSeen: time.Now(),
	}

	p.logger.Info("Handshake successful",
		zap.String("peer_id", peer.ID),
		zap.String("peer_addr", peer.Addr))

	return peer, nil
}

// SendFileEvent sends a file change event to a peer.
func (p *Protocol) SendFileEvent(peer *Peer, event filesystem.FileChangeEvent) error {
	msg := FileEventPayload{
		Event: event,
	}

	return p.sendMessage(peer.Conn, FileEventMessage, msg)
}

// ReceiveFileEvent receives a file change event from a peer.
func (p *Protocol) ReceiveFileEvent(conn net.Conn) (*filesystem.FileChangeEvent, error) {
	msg, err := p.receiveMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive file event: %s", err)
	}

	if msg.Type != FileEventMessage {
		return nil, fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	var fileEventMsg FileEventPayload
	if err := json.Unmarshal(msg.Payload, &fileEventMsg); err != nil {
		return nil, fmt.Errorf("unmarshal file event: %s", err)
	}

	return &fileEventMsg.Event, nil
}

// SendHeartbeat sends a heartbeat to a peer.
func (p *Protocol) SendHeartbeat(peer *Peer) error {
	heartbeat := map[string]interface{}{
		"node_id":   p.nodeID,
		"timestamp": time.Now(),
	}

	return p.sendMessage(peer.Conn, HeartbeatMessage, heartbeat)
}

// sendMessage sends a message to a peer.
func (p *Protocol) sendMessage(conn net.Conn, msgType MessageType, payload interface{}) error {
	// Serialize payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %s", err)
	}

	// Create message
	msg := Message{
		Type:      msgType,
		Length:    uint32(len(payloadBytes)),
		Payload:   payloadBytes,
		Timestamp: time.Now(),
	}

	// Write message header (type + length)
	header := make([]byte, 5)
	header[0] = byte(msg.Type)
	binary.BigEndian.PutUint32(header[1:], msg.Length)

	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("write message header: %s", err)
	}

	// Write payload
	if _, err := conn.Write(msg.Payload); err != nil {
		return fmt.Errorf("write message payload: %s", err)
	}

	return nil
}

// receiveMessage receives a message from a peer.
func (p *Protocol) receiveMessage(conn net.Conn) (*Message, error) {
	// Read message header
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read message header: %s", err)
	}

	msgType := MessageType(header[0])
	msgLength := binary.BigEndian.Uint32(header[1:])

	// Read payload
	payload := make([]byte, msgLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("read message payload: %s", err)
	}

	msg := &Message{
		Type:      msgType,
		Length:    msgLength,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	return msg, nil
}
