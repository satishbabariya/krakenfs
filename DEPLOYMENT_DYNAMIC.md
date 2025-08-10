# KrakenFS Dynamic IP Deployment Guide

This guide shows how to deploy KrakenFS without hardcoded IP addresses, making it suitable for cloud, container, and dynamic environments.

## 🚀 Why Dynamic IPs?

**Problems with Hardcoded IPs:**
- Not portable between environments
- Breaks in cloud/container deployments  
- Prevents auto-scaling
- Requires manual configuration changes

**Dynamic IP Solutions:**
- Auto-detection of local IP addresses
- Environment variable configuration
- DNS hostname resolution
- Container-friendly deployment

## 📋 IP Resolution Formats

KrakenFS supports multiple address resolution formats:

```yaml
sync:
  cluster_nodes:
    - "node1:auto"              # Auto-detect IP address
    - "node2:${NODE2_IP}"       # Environment variable
    - "node3:192.168.1.12"      # Static IP (legacy)
    - "node4:host.example.com"  # DNS hostname
```

## 🐳 Docker Deployment

### 1. Using Auto-Detection

```bash
# Node 1
docker run -d \
  --name krakenfs-node1 \
  -e NODE_ID=node1 \
  -e CLUSTER_NODES="node1:auto,node2:auto,node3:auto" \
  -v /data:/data \
  -p 6881:6881 \
  krakenfs:latest

# Node 2  
docker run -d \
  --name krakenfs-node2 \
  -e NODE_ID=node2 \
  -e CLUSTER_NODES="node1:auto,node2:auto,node3:auto" \
  -v /data:/data \
  -p 6881:6881 \
  krakenfs:latest
```

### 2. Using Environment Variables

```bash
# Set specific IPs via environment
export NODE1_IP=10.0.1.10
export NODE2_IP=10.0.1.11
export NODE3_IP=10.0.1.12

docker run -d \
  --name krakenfs-node1 \
  -e NODE_ID=node1 \
  -e NODE1_IP=${NODE1_IP} \
  -e NODE2_IP=${NODE2_IP} \
  -e NODE3_IP=${NODE3_IP} \
  -e CLUSTER_NODES="node1:${NODE1_IP},node2:${NODE2_IP},node3:${NODE3_IP}" \
  krakenfs:latest
```

### 3. Docker Compose with Dynamic IPs

```yaml
# docker-compose.yml
version: '3.8'

services:
  krakenfs-node1:
    image: krakenfs:latest
    environment:
      - NODE_ID=node1
      - CLUSTER_NODES=node1:auto,node2:auto,node3:auto
      - LOG_LEVEL=info
    volumes:
      - data1:/data
      - krakenfs-config:/etc/krakenfs
    networks:
      - krakenfs-network

  krakenfs-node2:
    image: krakenfs:latest
    environment:
      - NODE_ID=node2  
      - CLUSTER_NODES=node1:auto,node2:auto,node3:auto
      - LOG_LEVEL=info
    volumes:
      - data2:/data
      - krakenfs-config:/etc/krakenfs
    networks:
      - krakenfs-network

networks:
  krakenfs-network:
    driver: bridge

volumes:
  data1:
  data2:
  krakenfs-config:
```

## ☸️ Kubernetes Deployment

### 1. ConfigMap with Dynamic Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: krakenfs-config
data:
  config.yaml: |
    sync:
      node_id: "${NODE_ID}"
      cluster_nodes:
        - "${NODE_ID}:auto"
        - "krakenfs-0.krakenfs.default.svc.cluster.local:auto"
        - "krakenfs-1.krakenfs.default.svc.cluster.local:auto"
        - "krakenfs-2.krakenfs.default.svc.cluster.local:auto"
      discovery:
        enable: true
      storage:
        path: "/var/lib/krakenfs/data"
    # ... rest of config
```

### 2. StatefulSet with Auto IP Detection

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: krakenfs
spec:
  serviceName: krakenfs
  replicas: 3
  selector:
    matchLabels:
      app: krakenfs
  template:
    metadata:
      labels:
        app: krakenfs
    spec:
      containers:
      - name: krakenfs
        image: krakenfs:latest
        env:
        - name: NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: KRAKENFS_IP
          value: "auto"
        ports:
        - containerPort: 6881
          name: p2p
        - containerPort: 8080
          name: api
        volumeMounts:
        - name: data
          mountPath: /data
        - name: config
          mountPath: /etc/krakenfs
      volumes:
      - name: config
        configMap:
          name: krakenfs-config
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

## 🏗️ Manual Deployment

### 1. Generate Dynamic Configuration

```bash
# Generate secure config with auto IP detection
./krakenfs --generate-config /etc/krakenfs/config.yaml

# The generated config will use "auto" for IP detection
```

### 2. Set Environment Variables

```bash
# Option 1: Use auto-detection (recommended)
export KRAKENFS_IP=auto

# Option 2: Use specific environment variables
export NODE1_IP=$(hostname -I | awk '{print $1}')
export NODE2_IP=10.0.1.11
export NODE3_IP=10.0.1.12

# Option 3: Use hostname resolution
export CLUSTER_NODES="node1:$(hostname),node2:node2.local,node3:node3.local"
```

### 3. Run with Dynamic Configuration

```bash
# Start with auto IP detection
./krakenfs --config /etc/krakenfs/config.yaml
```

## 🔧 Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `NODE_ID` | Unique node identifier | `node1` |
| `KRAKENFS_IP` | Override IP detection | `auto` or `10.0.1.10` |
| `NODE_IP` | Kubernetes-style node IP | `10.0.1.10` |
| `POD_IP` | Kubernetes pod IP | `10.244.0.15` |
| `HOST_IP` | Docker host IP | `172.17.0.1` |
| `CLUSTER_NODES` | Comma-separated peer list | `node1:auto,node2:auto` |

## 🐛 Troubleshooting

### IP Detection Issues

```bash
# Check detected IP
./krakenfs --config config.yaml --log-level debug

# Look for log messages like:
# "Using IP from environment variable" 
# "Auto-detected IP address"
# "Resolved cluster nodes"
```

### Common Problems

1. **"No suitable local IP address found"**
   - Set `KRAKENFS_IP` environment variable
   - Use specific IP in configuration

2. **"Failed to resolve node"**
   - Check DNS resolution
   - Verify environment variables are set
   - Use static IPs as fallback

3. **Peers can't connect**
   - Ensure firewall allows P2P port (6881)
   - Check network connectivity between nodes
   - Verify resolved IPs are reachable

### Validation

```bash
# Validate configuration with dynamic IPs
./krakenfs --validate-config /etc/krakenfs/config.yaml

# Check peer connectivity
telnet <peer-ip> 6881
```

## 📊 Migration from Static IPs

### Step 1: Update Configuration

```bash
# Old configuration
cluster_nodes:
  - "node1:192.168.1.10"
  - "node2:192.168.1.11"

# New configuration  
cluster_nodes:
  - "node1:auto"
  - "node2:auto"
```

### Step 2: Gradual Migration

```bash
# Mixed mode during transition
cluster_nodes:
  - "node1:auto"           # Migrated node
  - "node2:192.168.1.11"   # Legacy node
  - "node3:auto"           # Migrated node
```

### Step 3: Verify and Complete

```bash
# Test connectivity
./krakenfs --validate-config config.yaml

# Deploy updated configuration
systemctl restart krakenfs
```

## 🏷️ Best Practices

1. **Always use `auto` for new deployments**
2. **Set environment variables for container deployments**
3. **Use DNS names for stable hostname-based deployments**
4. **Test IP resolution before production deployment**
5. **Monitor logs for IP resolution messages**
6. **Keep static IP fallbacks for critical environments**

This dynamic IP approach makes KrakenFS much more flexible and suitable for modern container and cloud deployments! 🚀