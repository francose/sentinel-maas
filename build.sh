#!/bin/bash

# 1. Clean previous builds
rm -rf dist
mkdir dist

echo "Building Sentinel..."

# 2. Build for Intel Mac (amd64)
echo "Compiling for Intel Mac..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o dist/sentinel-amd64

# 3. Build for Apple Silicon (M1/M2/M3)
echo "Compiling for Apple Silicon..."
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o dist/sentinel-arm64

# 4. Generate Checksums (Optional but Pro)
cd dist
shasum -a 256 * > checksums.txt

echo "Build complete! Check the 'dist/' folder."