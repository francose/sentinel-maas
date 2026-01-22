#!/bin/bash

# Define Version
VERSION="v1.0.0"
REPO="francose/sentinel-maas"

# Detect Architecture
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then
    BINARY="sentinel-amd64"
elif [ "$ARCH" == "arm64" ]; then
    BINARY="sentinel-arm64"
else
    echo "Error: Unsupported architecture $ARCH"
    exit 1
fi

URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY"

echo "Detected macOS ($ARCH)"
echo "Downloading Sentinel $VERSION..."

# Download to /usr/local/bin
sudo curl -L $URL -o /usr/local/bin/sentinel

# Make executable
sudo chmod +x /usr/local/bin/sentinel

echo "✅ Installed successfully! Run 'sudo sentinel' to start."