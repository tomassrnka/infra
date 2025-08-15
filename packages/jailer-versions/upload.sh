#!/bin/bash
set -e

# Upload built jailer binaries to GCS bucket
# Based on the pattern from fc-versions/upload.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <GCP_PROJECT_ID>"
    exit 1
fi

GCP_PROJECT_ID=$1
BUCKET_NAME="${GCP_PROJECT_ID}-jailer-versions"

echo "Uploading jailer binaries to gs://${BUCKET_NAME}"

# Check if builds directory exists
if [ ! -d "builds" ]; then
    echo "Error: builds directory not found. Run build.sh first."
    exit 1
fi

# Upload to project-specific bucket
gsutil -h "Cache-Control:no-cache, max-age=0" cp -r "builds/*" "gs://${BUCKET_NAME}"

# For production, also upload to public bucket
if [ "$GCP_PROJECT_ID" == "e2b-prod" ]; then
    echo "Also uploading to public builds bucket..."
    gsutil -h "Cache-Control:no-cache, max-age=0" cp -r "builds/*" "gs://e2b-prod-public-builds/jailers/"
fi

echo "Upload complete"