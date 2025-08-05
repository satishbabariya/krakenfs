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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultChunkSize is the default size for file chunks (1MB)
	DefaultChunkSize = 1024 * 1024

	// MaxChunkSize is the maximum size for a single chunk
	MaxChunkSize = 10 * 1024 * 1024 // 10MB
)

// Chunk represents a file chunk for transfer.
type Chunk struct {
	FileHash    string `json:"file_hash"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Data        []byte `json:"data"`
	Checksum    string `json:"checksum"`
}

// FileTransferRequestPayload represents a request to transfer a file.
type FileTransferRequestPayload struct {
	FilePath    string    `json:"file_path"`
	FileHash    string    `json:"file_hash"`
	FileSize    int64     `json:"file_size"`
	TotalChunks int       `json:"total_chunks"`
	Timestamp   time.Time `json:"timestamp"`
}

// FileTransferDataPayload represents file transfer data.
type FileTransferDataPayload struct {
	FileHash   string `json:"file_hash"`
	ChunkIndex int    `json:"chunk_index"`
	Data       []byte `json:"data"`
	Checksum   string `json:"checksum"`
}

// FileTransferCompletePayload represents completion of file transfer.
type FileTransferCompletePayload struct {
	FileHash  string    `json:"file_hash"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// FileTransfer manages file transfer operations.
type FileTransfer struct {
	chunkSize int
	logger    *zap.Logger
}

// NewFileTransfer creates a new file transfer instance.
func NewFileTransfer(chunkSize int, logger *zap.Logger) *FileTransfer {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	return &FileTransfer{
		chunkSize: chunkSize,
		logger:    logger,
	}
}

// ChunkFile splits a file into chunks for transfer.
func (ft *FileTransfer) ChunkFile(filePath string) ([]Chunk, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %s", err)
	}
	defer file.Close()

	// Calculate file hash
	fileHash, err := ft.calculateFileHash(file)
	if err != nil {
		return nil, fmt.Errorf("calculate file hash: %s", err)
	}

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("seek file: %s", err)
	}

	// Read file in chunks
	var chunks []Chunk
	chunkIndex := 0
	buffer := make([]byte, ft.chunkSize)

	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read file chunk: %s", err)
		}

		// Create chunk
		chunkData := make([]byte, n)
		copy(chunkData, buffer[:n])

		chunk := Chunk{
			FileHash:    fileHash,
			ChunkIndex:  chunkIndex,
			TotalChunks: -1, // Will be set after all chunks are created
			Data:        chunkData,
			Checksum:    ft.calculateChunkChecksum(chunkData),
		}

		chunks = append(chunks, chunk)
		chunkIndex++
	}

	// Set total chunks count
	for i := range chunks {
		chunks[i].TotalChunks = len(chunks)
	}

	ft.logger.Info("File chunked for transfer",
		zap.String("file_path", filePath),
		zap.String("file_hash", fileHash),
		zap.Int("total_chunks", len(chunks)))

	return chunks, nil
}

// SendFile sends a file to a peer.
func (ft *FileTransfer) SendFile(peer *Peer, filePath string) error {
	// Chunk the file
	chunks, err := ft.ChunkFile(filePath)
	if err != nil {
		return fmt.Errorf("chunk file: %s", err)
	}

	// Send file transfer request
	req := FileTransferRequestPayload{
		FilePath:    filePath,
		FileHash:    chunks[0].FileHash,
		FileSize:    ft.getFileSize(filePath),
		TotalChunks: len(chunks),
		Timestamp:   time.Now(),
	}

	protocol := NewProtocol("", "1.0", ft.logger)
	if err := protocol.sendMessage(peer.Conn, FileTransferRequest, req); err != nil {
		return fmt.Errorf("send file transfer request: %s", err)
	}

	// Send chunks
	for _, chunk := range chunks {
		transferData := FileTransferDataPayload{
			FileHash:   chunk.FileHash,
			ChunkIndex: chunk.ChunkIndex,
			Data:       chunk.Data,
			Checksum:   chunk.Checksum,
		}

		if err := protocol.sendMessage(peer.Conn, FileTransferData, transferData); err != nil {
			return fmt.Errorf("send chunk %d: %s", chunk.ChunkIndex, err)
		}

		ft.logger.Debug("Sent chunk",
			zap.String("file_hash", chunk.FileHash),
			zap.Int("chunk_index", chunk.ChunkIndex),
			zap.Int("chunk_size", len(chunk.Data)))
	}

	// Send completion message
	complete := FileTransferCompletePayload{
		FileHash:  chunks[0].FileHash,
		Success:   true,
		Timestamp: time.Now(),
	}

	if err := protocol.sendMessage(peer.Conn, FileTransferComplete, complete); err != nil {
		return fmt.Errorf("send completion: %s", err)
	}

	ft.logger.Info("File transfer completed",
		zap.String("file_path", filePath),
		zap.String("file_hash", chunks[0].FileHash),
		zap.Int("total_chunks", len(chunks)))

	return nil
}

// ReceiveFile receives a file from a peer.
func (ft *FileTransfer) ReceiveFile(conn net.Conn, filePath string) error {
	protocol := NewProtocol("", "1.0", ft.logger)

	// Create temporary file
	tempPath := filePath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("create temp file: %s", err)
	}
	defer file.Close()

	// Receive file transfer request
	msg, err := protocol.receiveMessage(conn)
	if err != nil {
		return fmt.Errorf("receive file transfer request: %s", err)
	}

	if msg.Type != FileTransferRequest {
		return fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	var req FileTransferRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return fmt.Errorf("unmarshal file transfer request: %s", err)
	}

	ft.logger.Info("Receiving file",
		zap.String("file_path", filePath),
		zap.String("file_hash", req.FileHash),
		zap.Int("total_chunks", req.TotalChunks))

	// Receive chunks
	receivedChunks := make(map[int]Chunk)
	expectedChunks := req.TotalChunks

	for len(receivedChunks) < expectedChunks {
		msg, err := protocol.receiveMessage(conn)
		if err != nil {
			return fmt.Errorf("receive chunk: %s", err)
		}

		if msg.Type == FileTransferComplete {
			// Transfer completed
			break
		}

		if msg.Type != FileTransferData {
			return fmt.Errorf("unexpected message type: %d", msg.Type)
		}

		var transferData FileTransferDataPayload
		if err := json.Unmarshal(msg.Payload, &transferData); err != nil {
			return fmt.Errorf("unmarshal transfer data: %s", err)
		}

		// Verify checksum
		calculatedChecksum := ft.calculateChunkChecksum(transferData.Data)
		if calculatedChecksum != transferData.Checksum {
			return fmt.Errorf("checksum mismatch for chunk %d", transferData.ChunkIndex)
		}

		// Store chunk
		chunk := Chunk{
			FileHash:   transferData.FileHash,
			ChunkIndex: transferData.ChunkIndex,
			Data:       transferData.Data,
			Checksum:   transferData.Checksum,
		}
		receivedChunks[transferData.ChunkIndex] = chunk

		ft.logger.Debug("Received chunk",
			zap.String("file_hash", transferData.FileHash),
			zap.Int("chunk_index", transferData.ChunkIndex),
			zap.Int("chunk_size", len(transferData.Data)))
	}

	// Write chunks to file in order
	for i := 0; i < expectedChunks; i++ {
		chunk, exists := receivedChunks[i]
		if !exists {
			return fmt.Errorf("missing chunk %d", i)
		}

		if _, err := file.Write(chunk.Data); err != nil {
			return fmt.Errorf("write chunk %d: %s", i, err)
		}
	}

	// Close file and rename
	file.Close()
	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("rename temp file: %s", err)
	}

	ft.logger.Info("File received successfully",
		zap.String("file_path", filePath),
		zap.String("file_hash", req.FileHash))

	return nil
}

// calculateFileHash calculates the SHA256 hash of a file.
func (ft *FileTransfer) calculateFileHash(file *os.File) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// CalculateChunkChecksum calculates the SHA256 checksum of chunk data.
func (ft *FileTransfer) CalculateChunkChecksum(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// calculateChunkChecksum calculates the SHA256 checksum of chunk data.
func (ft *FileTransfer) calculateChunkChecksum(data []byte) string {
	return ft.CalculateChunkChecksum(data)
}

// getFileSize returns the size of a file.
func (ft *FileTransfer) getFileSize(filePath string) int64 {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return info.Size()
}
