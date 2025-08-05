# KrakenFS Quick Start Guide

This guide will help you deploy KrakenFS across multiple VMs for P2P volume replication.

## Prerequisites

- Docker installed and running on all VMs
- Root access on all VMs
- Network connectivity between VMs (ports 6881, 6882)

## Step 1: Deploy on First VM

### 1.1 Clone and Build

```bash
# Clone the repository
git clone https://github.com/satishbabariya/krakenfs.git
cd krakenfs

# Make the deployment script executable
chmod +x scripts/deploy.sh
```

### 1.2 Deploy KrakenFS

```bash
# Deploy with default settings
sudo ./scripts/deploy.sh

# Or specify custom node ID and cluster nodes
sudo NODE_ID=vm1 CLUSTER_NODES=vm1:192.168.1.10,vm2:192.168.1.11 ./scripts/deploy.sh
```

### 1.3 Verify Installation

```bash
# Check if service is running
sudo systemctl status krakenfs

# Check Docker plugin
docker plugin ls | grep krakenfs

# View logs
sudo journalctl -u krakenfs -f
```

## Step 2: Deploy on Additional VMs

Repeat the deployment process on each VM, changing the NODE_ID:

```bash
# On VM2
sudo NODE_ID=vm2 CLUSTER_NODES=vm1:192.168.1.10,vm2:192.168.1.11 ./scripts/deploy.sh

# On VM3
sudo NODE_ID=vm3 CLUSTER_NODES=vm1:192.168.1.10,vm2:192.168.1.11,vm3:192.168.1.12 ./scripts/deploy.sh
```

## Step 3: Test Volume Replication

### 3.1 Create a Shared Volume

```bash
# Create a volume that will be replicated across all VMs
docker volume create --driver krakenfs my-shared-volume
```

### 3.2 Use the Volume in Containers

```bash
# On VM1 - Create a file
docker run --rm -v my-shared-volume:/data alpine sh -c "echo 'Hello from VM1' > /data/test.txt"

# On VM2 - Verify the file exists
docker run --rm -v my-shared-volume:/data alpine cat /data/test.txt

# On VM3 - Modify the file
docker run --rm -v my-shared-volume:/data alpine sh -c "echo 'Modified from VM3' >> /data/test.txt"
```

### 3.3 Verify Replication

```bash
# Check on all VMs that the file is synchronized
docker run --rm -v my-shared-volume:/data alpine cat /data/test.txt
```

## Step 4: Deploy Applications with Shared Volumes

### 4.1 Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  web-app:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - shared-content:/usr/share/nginx/html:rw
    restart: unless-stopped

  api-app:
    image: python:3.9-alpine
    ports:
      - "8081:8000"
    volumes:
      - shared-content:/app/data:rw
    working_dir: /app
    command: ["python", "-m", "http.server", "8000"]
    restart: unless-stopped

volumes:
  shared-content:
    driver: krakenfs
    driver_opts:
      node_id: ${NODE_ID:-vm1}
```

### 4.2 Deploy the Application

```bash
# Deploy on all VMs
docker-compose up -d

# Test file sharing
docker run --rm -v shared-content:/data alpine sh -c "echo 'Shared content' > /data/index.html"
```

## Step 5: Monitor and Troubleshoot

### 5.1 Check Service Status

```bash
# Check KrakenFS service
sudo systemctl status krakenfs

# Check Docker plugin
docker plugin ls

# View service logs
sudo journalctl -u krakenfs -f
```

### 5.2 Monitor Network Connectivity

```bash
# Check P2P ports
netstat -tlnp | grep -E '6881|6882'

# Test connectivity between VMs
telnet vm2 6881
```

### 5.3 View Volume Information

```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect my-shared-volume
```

## Configuration Options

### Environment Variables

- `NODE_ID`: Unique identifier for this VM
- `CLUSTER_NODES`: Comma-separated list of all VMs in format `node:ip`

### Configuration File

The deployment script creates `/etc/krakenfs/config.yaml`:

```yaml
log:
  level: "info"

filesystem:
  watch_paths:
    - "/var/lib/krakenfs/volumes"
  exclude_patterns:
    - "*.tmp"
    - "*.log"
  recursive: true

sync:
  node_id: "vm1"
  cluster_nodes:
    - "vm1:192.168.1.10"
    - "vm2:192.168.1.11"
  p2p_port: 6881
  bandwidth:
    enable: true
    egress_bits_per_sec: 1677721600
    ingress_bits_per_sec: 2516582400
  conflict_resolution:
    strategy: "timestamp"
    timeout: "30s"

volume:
  root_path: "/var/lib/krakenfs/volumes"
  driver_name: "krakenfs"
```

## Troubleshooting

### Common Issues

1. **Service not starting**
   ```bash
   sudo journalctl -u krakenfs -n 50
   ```

2. **Docker plugin not found**
   ```bash
   sudo systemctl restart docker
   ```

3. **Network connectivity issues**
   ```bash
   # Check firewall
   sudo ufw status
   
   # Open required ports
   sudo ufw allow 6881
   sudo ufw allow 6882
   ```

4. **Volume not syncing**
   ```bash
   # Check peer connections
   sudo journalctl -u krakenfs | grep "peer"
   
   # Restart service
   sudo systemctl restart krakenfs
   ```

### Performance Tuning

1. **Adjust bandwidth limits** in `/etc/krakenfs/config.yaml`
2. **Increase file watcher limits**:
   ```bash
   echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

## Advanced Usage

### Custom Volume Drivers

```bash
# Create volume with custom options
docker volume create --driver krakenfs --opt node_id=vm1 my-custom-volume
```

### Backup and Restore

```bash
# Backup volume data
sudo tar -czf backup.tar.gz /var/lib/krakenfs/volumes/

# Restore volume data
sudo tar -xzf backup.tar.gz -C /
```

### Scaling

To add more VMs to the cluster:

1. Deploy KrakenFS on the new VM
2. Update `CLUSTER_NODES` on all existing VMs
3. Restart the KrakenFS service on all VMs

## Support

For issues and questions:

1. Check the logs: `sudo journalctl -u krakenfs -f`
2. Review the configuration: `/etc/krakenfs/config.yaml`
3. Test network connectivity between VMs
4. Verify Docker plugin installation

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the [examples/](examples/) directory for more use cases
- Check the [architecture documentation](docs/ARCHITECTURE.md) for technical details 