#!/bin/bash
# Upload witness keys to a GCS bucket.
#
# Usage:
#   bazel run //deploy/witness:upload_keys -- <bucket-name> <witness-key-path> <origins-file-path>
#
# Example:
#   bazel run //deploy/witness:upload_keys -- my-project-git-ratchet-witness ./witness-key ./origins
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <bucket-name> <witness-key-path> <origins-file-path>" >&2
    echo "" >&2
    echo "Uploads the witness private key and trusted origins file to GCS." >&2
    echo "Run 'gcloud auth login' first if not already authenticated." >&2
    exit 1
fi

BUCKET="$1"
KEY_PATH="$2"
ORIGINS_PATH="$3"

# bazel run sets CWD to the runfiles tree, not the workspace root.
# Resolve relative paths against the workspace root so callers can
# pass paths like "deploy/witness/witness-key" as documented.
if [[ "${KEY_PATH}" != /* ]]; then
    KEY_PATH="${BUILD_WORKSPACE_DIRECTORY}/${KEY_PATH}"
fi
if [[ "${ORIGINS_PATH}" != /* ]]; then
    ORIGINS_PATH="${BUILD_WORKSPACE_DIRECTORY}/${ORIGINS_PATH}"
fi

echo "Uploading witness key to gs://${BUCKET}/witness-key ..."
gcloud storage cp "${KEY_PATH}" "gs://${BUCKET}/witness-key"

echo "Uploading origins file to gs://${BUCKET}/origins ..."
gcloud storage cp "${ORIGINS_PATH}" "gs://${BUCKET}/origins"

echo "Done. Keys uploaded to gs://${BUCKET}/"
