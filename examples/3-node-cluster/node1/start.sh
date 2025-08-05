#!/bin/bash

# KrakenFS Node 1 Start Script

echo "Starting KrakenFS Node 1..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp env-file .env
    echo "Please edit .env file with your IP addresses before continuing"
    exit 1
fi

# Load environment variables
source .env

echo "Node ID: $NODE_ID"
echo "Cluster Nodes: $CLUSTER_NODES"
echo "Filebrowser Port: $FILEBROWSER_PORT"

# Start services
echo "Starting Docker Compose services..."
docker-compose up -d

echo "Node 1 started successfully!"
echo "Filebrowser available at: http://$(hostname -I | awk '{print $1}'):$FILEBROWSER_PORT"
echo "Username: admin, Password: admin123" 