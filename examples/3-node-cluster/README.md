# KrakenFS 3-Node Cluster Example

This example demonstrates a 3-node KrakenFS cluster with real-time file synchronization and a web-based file browser to visualize the synced data.

## Architecture

```
Node 1 (192.168.1.10)     Node 2 (192.168.1.11)     Node 3 (192.168.1.12)
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   KrakenFS      │◄─────►│   KrakenFS      │◄─────►│   KrakenFS      │
│   Filebrowser   │       │   Filebrowser   │       │   Filebrowser   │
│   Port: 8080    │       │   Port: 8081    │       │   Port: 8082    │
└─────────────────┘       └─────────────────┘       └─────────────────┘
        │                         │                         │
        └───────── Shared Data ───┴─────────────────────────┘
```

## Setup Instructions

### 1. Prepare Each Node

Copy the appropriate node folder to each server:

```bash
# On Node 1 (192.168.1.10)
cp -r examples/3-node-cluster/node1 /opt/krakenfs-node1
cd /opt/krakenfs-node1

# On Node 2 (192.168.1.11)  
cp -r examples/3-node-cluster/node2 /opt/krakenfs-node2
cd /opt/krakenfs-node2

# On Node 3 (192.168.1.12)
cp -r examples/3-node-cluster/node3 /opt/krakenfs-node3
cd /opt/krakenfs-node3
```

### 2. Update IP Addresses

Edit the `env-file` on each node to match your network:

```bash
# On each node, update the IP addresses in env-file
nano env-file
```

### 3. Create .env File

Copy the env-file to .env on each node:

```bash
# On each node
cp env-file .env
```

### 4. Build KrakenFS Image

On each node, build the KrakenFS image:

```bash
# Clone the repository and build
git clone https://github.com/uber/krakenfs.git
cd krakenfs
make images
```

### 5. Start the Services

On each node, start the services:

```bash
# On Node 1
cd /opt/krakenfs-node1
docker-compose up -d

# On Node 2  
cd /opt/krakenfs-node2
docker-compose up -d

# On Node 3
cd /opt/krakenfs-node3
docker-compose up -d
```

## Access Points

### Filebrowser Web Interfaces

- **Node 1**: http://192.168.1.10:8080 (admin/admin123)
- **Node 2**: http://192.168.1.11:8081 (admin/admin123)  
- **Node 3**: http://192.168.1.12:8082 (admin/admin123)

### KrakenFS Services

- **P2P Port**: 6881 (all nodes)
- **Tracker Port**: 6882 (all nodes)

## Testing File Synchronization

1. **Upload a file** through any Filebrowser interface
2. **Check all nodes** - the file should appear on all three nodes
3. **Modify the file** on any node
4. **Verify changes** propagate to all other nodes

## Monitoring

### Check Service Status

```bash
# On any node
docker-compose ps
```

### View Logs

```bash
# KrakenFS logs
docker-compose logs krakenfs

# Filebrowser logs  
docker-compose logs filebrowser
```

### Check Cluster Status

```bash
# View KrakenFS container logs to see P2P connections
docker logs krakenfs-node1
```

## Troubleshooting

### Common Issues

1. **Network Connectivity**: Ensure all nodes can reach each other on ports 6881-6882
2. **Firewall**: Open ports 6881, 6882, and the Filebrowser port (8080-8082)
3. **Permissions**: Ensure Docker has access to the data volumes

### Reset Cluster

```bash
# Stop all services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker volume rm node1_shared-data node2_shared-data node3_shared-data

# Restart services
docker-compose up -d
```

## Configuration Details

### Environment Variables

- `NODE_ID`: Unique identifier for each node
- `CLUSTER_NODES`: Comma-separated list of all nodes
- `KRAKENFS_PORT`: P2P communication port
- `KRAKENFS_PEER_PORT`: Tracker port
- `FILEBROWSER_PORT`: Web interface port (different per node)

### Data Directory

All nodes share the same `/data` directory which is synchronized in real-time across the cluster.

## Security Notes

- Change default Filebrowser credentials in production
- Use HTTPS for Filebrowser in production
- Consider network segmentation for the P2P ports
- Review and adjust bandwidth limits as needed 