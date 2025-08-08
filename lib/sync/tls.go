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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"go.uber.org/zap"
)

// TLSManager handles TLS certificate management and secure connections.
type TLSManager struct {
	config TLSConfig
	logger *zap.Logger
}

// NewTLSManager creates a new TLS manager.
func NewTLSManager(config TLSConfig, logger *zap.Logger) *TLSManager {
	return &TLSManager{
		config: config,
		logger: logger,
	}
}

// GenerateSelfSignedCert generates a self-signed certificate for testing.
func (tm *TLSManager) GenerateSelfSignedCert(nodeID string) error {
	if !tm.config.Enable {
		return nil
	}

	// Check if certificate already exists
	if _, err := os.Stat(tm.config.CertFile); err == nil {
		if _, err := os.Stat(tm.config.KeyFile); err == nil {
			tm.logger.Info("TLS certificates already exist",
				zap.String("cert_file", tm.config.CertFile),
				zap.String("key_file", tm.config.KeyFile))
			return nil
		}
	}

	tm.logger.Info("Generating self-signed TLS certificate",
		zap.String("node_id", nodeID))

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate private key: %s", err)
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"KrakenFS"},
			CommonName:   nodeID,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", nodeID},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate: %s", err)
	}

	// Write certificate file
	certOut, err := os.OpenFile(tm.config.CertFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create cert file: %s", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("encode certificate: %s", err)
	}

	// Write private key file with restrictive permissions (0600)
	keyOut, err := os.OpenFile(tm.config.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %s", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %s", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("encode private key: %s", err)
	}

	tm.logger.Info("TLS certificate generated successfully",
		zap.String("cert_file", tm.config.CertFile),
		zap.String("key_file", tm.config.KeyFile))

	return nil
}

// CreateTLSConfig creates a TLS configuration for secure connections.
func (tm *TLSManager) CreateTLSConfig() (*tls.Config, error) {
	if !tm.config.Enable {
		return nil, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(tm.config.CertFile, tm.config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %s", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	// Set minimum version if specified
	if tm.config.MinVersion != "" {
		switch tm.config.MinVersion {
		case "1.2":
			tlsConfig.MinVersion = tls.VersionTLS12
		case "1.3":
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}

	// Set maximum version if specified
	if tm.config.MaxVersion != "" {
		switch tm.config.MaxVersion {
		case "1.2":
			tlsConfig.MaxVersion = tls.VersionTLS12
		case "1.3":
			tlsConfig.MaxVersion = tls.VersionTLS13
		}
	}

	// Load CA certificate if specified
	if tm.config.CAFile != "" {
		caCert, err := os.ReadFile(tm.config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %s", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("append CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Configure peer verification
	if tm.config.VerifyPeer {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = tlsConfig.RootCAs
	} else {
		tlsConfig.InsecureSkipVerify = tm.config.InsecureSkipVerify
	}

	return tlsConfig, nil
}

// WrapListener wraps a TCP listener with TLS.
func (tm *TLSManager) WrapListener(listener net.Listener) (net.Listener, error) {
	if !tm.config.Enable {
		return listener, nil
	}

	tlsConfig, err := tm.CreateTLSConfig()
	if err != nil {
		return nil, err
	}

	return tls.NewListener(listener, tlsConfig), nil
}

// WrapConnection wraps a TCP connection with TLS.
func (tm *TLSManager) WrapConnection(conn net.Conn, isClient bool) (net.Conn, error) {
	if !tm.config.Enable {
		return conn, nil
	}

	tlsConfig, err := tm.CreateTLSConfig()
	if err != nil {
		return nil, err
	}

	if isClient {
		return tls.Client(conn, tlsConfig), nil
	}
	return tls.Server(conn, tlsConfig), nil
}
