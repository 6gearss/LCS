#!/bin/bash

# Configuration
SERVICE_NAME="lcs.service"

echo "=== Starting Update for $SERVICE_NAME ==="

# 1. Stop the service to release file locks (less relevant for Python, but good practice)
#    and ensure we restart with clean state.
echo "Stopping service..."
systemctl stop $SERVICE_NAME

# 2. Update the code
echo "Pulling latest changes from git..."
git pull
if [ $? -ne 0 ]; then
    echo "Git pull failed! Aborting update."
    exit 1
fi

# 3. Restart the service
echo "Restarting service..."
sudo systemctl start $SERVICE_NAME

# 4. Check status
echo "Current Status:"
systemctl status $SERVICE_NAME --no-pager

echo "=== Update Complete ==="
