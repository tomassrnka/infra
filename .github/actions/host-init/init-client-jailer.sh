#!/bin/bash
set -e

# Download jailer versions to client servers
# This should be added to the existing client initialization script

echo "Downloading jailer versions..."

# Download jailer versions
jailer_versions_dir="/jailer-versions"
mkdir -p $jailer_versions_dir

# Download from project-specific bucket (for development/staging)
if [ -n "$GCP_PROJECT_ID" ]; then
    gsutil -m cp -r "gs://${GCP_PROJECT_ID}-jailer-versions/*" "${jailer_versions_dir}"
else
    # Production: download from public bucket
    gsutil -m cp -r "gs://e2b-prod-public-builds/jailers/*" "${jailer_versions_dir}"
fi

# Set proper permissions
chmod -R 755 $jailer_versions_dir

echo "Jailer versions downloaded successfully"

# Verify installation
ls -la $jailer_versions_dir/