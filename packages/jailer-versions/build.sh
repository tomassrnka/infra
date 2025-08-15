#!/bin/bash
set -e

# Build jailer binaries for all specified versions
# Based on the pattern from fc-versions/build.sh

echo "Building jailer binaries..."

# Clean builds directory
rm -rf builds
mkdir -p builds

# Clone Firecracker repository (jailer is part of Firecracker)
REPO_DIR=$(mktemp -d)
git clone https://github.com/firecracker-microvm/firecracker.git "$REPO_DIR"
cd "$REPO_DIR"

# Read versions from file
VERSIONS_FILE="$(dirname "$0")/jailer_versions.txt"

while IFS= read -r VERSION; do
    if [[ -z "$VERSION" ]] || [[ "$VERSION" == \#* ]]; then
        continue
    fi
    
    echo "Building jailer version: $VERSION"
    
    # Checkout version
    git checkout "$VERSION"
    
    # Build jailer (part of Firecracker build)
    ./tools/devtool -y build --release
    
    # Create version directory
    VERSION_DIR="$(dirname "$0")/builds/$VERSION"
    mkdir -p "$VERSION_DIR"
    
    # Copy jailer binary
    cp build/cargo_target/x86_64-unknown-linux-musl/release/jailer "$VERSION_DIR/jailer"
    chmod 755 "$VERSION_DIR/jailer"
    
    echo "Built jailer $VERSION"
done < "$VERSIONS_FILE"

# Cleanup
cd ..
rm -rf "$REPO_DIR"

echo "All jailer versions built successfully"
echo "Binaries are in: $(dirname "$0")/builds/"