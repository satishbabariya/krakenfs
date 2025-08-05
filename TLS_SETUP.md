# KrakenFS TLS/SSL Setup Guide

This guide explains how to configure TLS/SSL encryption for secure peer-to-peer communication in KrakenFS.

## Overview

KrakenFS now supports TLS/SSL encryption to secure all peer-to-peer communication, including:
- File transfer data
- File change events
- Handshake messages
- Heartbeat messages

## Configuration

### Basic TLS Configuration

Add the following section to your KrakenFS configuration:

```yaml
sync:
  tls:
    enable: true                    # Enable TLS encryption
    cert_file: "/path/to/cert.crt" # Certificate file path
    key_file: "/path/to/key.key"   # Private key file path
    ca_file: "/path/to/ca.crt"     # CA certificate file (optional)
    verify_peer: false             # Verify peer certificates
    min_version: "1.2"            # Minimum TLS version
    max_version: "1.3"            # Maximum TLS version
    insecure_skip_verify: false   # Skip verification (insecure)
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable TLS encryption |
| `cert_file` | string | - | Path to certificate file |
| `key_file` | string | - | Path to private key file |
| `ca_file` | string | - | Path to CA certificate file |
| `verify_peer` | bool | `false` | Verify peer certificates |
| `min_version` | string | `"1.2"` | Minimum TLS version (1.2, 1.3) |
| `max_version` | string | `"1.3"` | Maximum TLS version (1.2, 1.3) |
| `insecure_skip_verify` | bool | `false` | Skip certificate verification |

## Certificate Management

### Option 1: Self-Signed Certificates (Development/Testing)

KrakenFS can automatically generate self-signed certificates for testing:

1. **Enable TLS with auto-generation**:
   ```yaml
   sync:
     tls:
       enable: true
       cert_file: "/etc/krakenfs/certs/node1.crt"
       key_file: "/etc/krakenfs/certs/node1.key"
       verify_peer: false
       insecure_skip_verify: true
   ```

2. **Create certificate directory**:
   ```bash
   mkdir -p /etc/krakenfs/certs
   ```

3. **Start KrakenFS** - certificates will be generated automatically

### Option 2: CA-Signed Certificates (Production)

For production environments, use proper CA-signed certificates:

1. **Generate Certificate Signing Request (CSR)**:
   ```bash
   openssl req -new -newkey rsa:2048 -keyout node1.key -out node1.csr
   ```

2. **Sign with your CA**:
   ```bash
   openssl x509 -req -in node1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out node1.crt
   ```

3. **Configure KrakenFS**:
   ```yaml
   sync:
     tls:
       enable: true
       cert_file: "/etc/krakenfs/certs/node1.crt"
       key_file: "/etc/krakenfs/certs/node1.key"
       ca_file: "/etc/krakenfs/certs/ca.crt"
       verify_peer: true
       insecure_skip_verify: false
   ```

## Security Levels

### Level 1: Basic Encryption (Development)
```yaml
sync:
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/node1.crt"
    key_file: "/etc/krakenfs/certs/node1.key"
    verify_peer: false
    insecure_skip_verify: true
```

### Level 2: Certificate Verification (Staging)
```yaml
sync:
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/node1.crt"
    key_file: "/etc/krakenfs/certs/node1.key"
    ca_file: "/etc/krakenfs/certs/ca.crt"
    verify_peer: true
    insecure_skip_verify: false
```

### Level 3: Mutual Authentication (Production)
```yaml
sync:
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/node1.crt"
    key_file: "/etc/krakenfs/certs/node1.key"
    ca_file: "/etc/krakenfs/certs/ca.crt"
    verify_peer: true
    insecure_skip_verify: false
    min_version: "1.3"
    max_version: "1.3"
```

## Multi-Node Setup

### Step 1: Generate Certificates for Each Node

For each node in your cluster:

1. **Node 1**:
   ```bash
   mkdir -p /etc/krakenfs/certs/node1
   # Generate or copy certificates to /etc/krakenfs/certs/node1/
   ```

2. **Node 2**:
   ```bash
   mkdir -p /etc/krakenfs/certs/node2
   # Generate or copy certificates to /etc/krakenfs/certs/node2/
   ```

3. **Node 3**:
   ```bash
   mkdir -p /etc/krakenfs/certs/node3
   # Generate or copy certificates to /etc/krakenfs/certs/node3/
   ```

### Step 2: Configure Each Node

**Node 1 Configuration**:
```yaml
sync:
  node_id: "node1"
  cluster_nodes:
    - "node1:192.168.1.10"
    - "node2:192.168.1.11"
    - "node3:192.168.1.12"
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/node1/node1.crt"
    key_file: "/etc/krakenfs/certs/node1/node1.key"
    ca_file: "/etc/krakenfs/certs/ca.crt"
    verify_peer: true
```

**Node 2 Configuration**:
```yaml
sync:
  node_id: "node2"
  cluster_nodes:
    - "node1:192.168.1.10"
    - "node2:192.168.1.11"
    - "node3:192.168.1.12"
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/node2/node2.crt"
    key_file: "/etc/krakenfs/certs/node2/node2.key"
    ca_file: "/etc/krakenfs/certs/ca.crt"
    verify_peer: true
```

**Node 3 Configuration**:
```yaml
sync:
  node_id: "node3"
  cluster_nodes:
    - "node1:192.168.1.10"
    - "node2:192.168.1.11"
    - "node3:192.168.1.12"
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/node3/node3.crt"
    key_file: "/etc/krakenfs/certs/node3/node3.key"
    ca_file: "/etc/krakenfs/certs/ca.crt"
    verify_peer: true
```

## Troubleshooting

### Common Issues

1. **Certificate Not Found**:
   ```
   Error: load certificate: open /path/to/cert.crt: no such file or directory
   ```
   **Solution**: Ensure certificate files exist and paths are correct

2. **Private Key Permissions**:
   ```
   Error: load certificate: tls: failed to parse private key
   ```
   **Solution**: Check private key file permissions (should be 600)

3. **Certificate Verification Failed**:
   ```
   Error: handshake: tls: bad certificate
   ```
   **Solution**: Ensure all nodes use certificates signed by the same CA

4. **TLS Version Mismatch**:
   ```
   Error: handshake: tls: no cipher suite in common
   ```
   **Solution**: Check min_version and max_version settings

### Debugging

Enable debug logging to troubleshoot TLS issues:

```yaml
log:
  level: "debug"
```

### Certificate Validation

Test certificate validity:

```bash
# Check certificate
openssl x509 -in /etc/krakenfs/certs/node1.crt -text -noout

# Verify certificate chain
openssl verify -CAfile /etc/krakenfs/certs/ca.crt /etc/krakenfs/certs/node1.crt

# Test TLS connection
openssl s_client -connect node1:6881 -cert /etc/krakenfs/certs/node1.crt -key /etc/krakenfs/certs/node1.key -CAfile /etc/krakenfs/certs/ca.crt
```

## Security Best Practices

1. **Use Strong Certificates**: Use 2048-bit or stronger RSA keys
2. **Regular Certificate Rotation**: Rotate certificates before expiration
3. **Secure Storage**: Store private keys securely with appropriate permissions
4. **Network Segmentation**: Use firewalls to restrict access to P2P ports
5. **Monitoring**: Monitor certificate expiration and renewal
6. **Backup**: Regularly backup certificates and private keys

## Performance Considerations

- **CPU Overhead**: TLS encryption adds ~5-10% CPU overhead
- **Memory Usage**: TLS connections use additional memory for cipher suites
- **Network Latency**: TLS handshake adds initial connection latency
- **Bandwidth**: Encrypted data may be slightly larger due to padding

## Migration from Non-TLS

To migrate an existing cluster to TLS:

1. **Prepare Certificates**: Generate certificates for all nodes
2. **Update Configuration**: Add TLS configuration to all nodes
3. **Rolling Update**: Restart nodes one by one with TLS enabled
4. **Verify**: Check logs to ensure TLS connections are established
5. **Monitor**: Monitor performance and connection stability 