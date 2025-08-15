#!/bin/bash
set -e

echo "Downloading pre-built jailer binaries from Firecracker releases..."

# Clean builds directory
rm -rf builds
mkdir -p builds

# Read versions from file
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSIONS_FILE="$SCRIPT_DIR/jailer_versions.txt"

while IFS= read -r VERSION; do
    if [[ -z "$VERSION" ]] || [[ "$VERSION" == \#* ]]; then
        continue
    fi
    
    echo "Downloading jailer version: $VERSION"
    
    # Download Firecracker release tarball
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download release
    wget -q "https://github.com/firecracker-microvm/firecracker/releases/download/${VERSION}/firecracker-${VERSION}-x86_64.tgz"
    tar -xzf "firecracker-${VERSION}-x86_64.tgz" 2>/dev/null || true
    
    # Find and extract commit hash from jailer binary name
    JAILER_BIN=$(find . -name "jailer-*-x86_64" -type f \! -name "*.debug" | head -1)
    if [ -n "$JAILER_BIN" ]; then
        # Extract commit hash from filename (e.g., jailer-v1.10.1-1fcdaec-x86_64 -> 1fcdaec)
        JAILER_NAME=$(basename "$JAILER_BIN")
        # Use more robust extraction: split by - and get the commit hash part
        COMMIT_HASH=$(echo "$JAILER_NAME" | cut -d'-' -f3)
        
        # Validate commit hash (should be 7 hex characters)
        if [[ "$COMMIT_HASH" =~ ^[a-f0-9]{7}$ ]]; then
            # Create version directory with commit hash (matching Firecracker convention)
            VERSION_WITH_COMMIT="${VERSION}_${COMMIT_HASH}"
            VERSION_DIR="builds/$VERSION_WITH_COMMIT"
        else
            echo "Warning: Could not extract valid commit hash from $JAILER_NAME, using version only"
            VERSION_DIR="builds/$VERSION"
        fi
        mkdir -p "$VERSION_DIR"
        
        cp "$JAILER_BIN" "$OLDPWD/$VERSION_DIR/jailer"
        chmod 755 "$OLDPWD/$VERSION_DIR/jailer"
        if [[ "$COMMIT_HASH" =~ ^[a-f0-9]{7}$ ]]; then
            echo "Downloaded jailer $VERSION_WITH_COMMIT"
        else
            echo "Downloaded jailer $VERSION"
        fi
    else
        echo "Warning: Jailer binary not found for $VERSION"
    fi
    
    # Cleanup
    cd "$OLDPWD"
    rm -rf "$TEMP_DIR"
done < "$VERSIONS_FILE"

echo "All jailer versions downloaded successfully"
