#!/bin/bash
#
# sync-mirror.sh - Sync upstream APT mirror and create snapshot
#
# This script updates the staging mirror from upstream repositories
# and creates a timestamped snapshot for processing.
#

set -euo pipefail

# Configuration
MIRROR_NAME="${MIRROR_NAME:-ubuntu-jammy}"
SNAPSHOT_PREFIX="${SNAPSHOT_PREFIX:-staging}"
LOG_DIR="${LOG_DIR:-/opt/apt-mirror-system/logs}"
SNAPSHOTS_DIR="${SNAPSHOTS_DIR:-/opt/apt-mirror-system/snapshots}"
MAX_RETRIES="${MAX_RETRIES:-4}"
RETRY_DELAY="${RETRY_DELAY:-2}"

# Set script name for logging and source shared utilities
SCRIPT_NAME="sync-mirror"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# Ensure snapshots directory exists
mkdir -p "${SNAPSHOTS_DIR}"

# Validate aptly is available
if ! command -v aptly >/dev/null 2>&1; then
    log_error "aptly command not found. Please install aptly."
    exit 1
fi

# Update mirror from upstream
log "Starting mirror update for ${MIRROR_NAME}"

if ! retry_command aptly mirror update "${MIRROR_NAME}"; then
    log_error "Failed to update mirror ${MIRROR_NAME}"
    exit 1
fi

log "Mirror update completed successfully"

# Create snapshot
SNAPSHOT_NAME="${SNAPSHOT_PREFIX}-${DATE_SUFFIX}"

log "Creating snapshot ${SNAPSHOT_NAME} from mirror ${MIRROR_NAME}"

if ! retry_command aptly snapshot create "${SNAPSHOT_NAME}" from mirror "${MIRROR_NAME}"; then
    log_error "Failed to create snapshot ${SNAPSHOT_NAME}"
    exit 1
fi

log "Snapshot ${SNAPSHOT_NAME} created successfully"

# Save snapshot metadata (no retry - snapshot just created, should succeed)
SNAPSHOT_FILE="${SNAPSHOTS_DIR}/${SNAPSHOT_NAME}.txt"

if aptly snapshot show -with-packages "${SNAPSHOT_NAME}" > "${SNAPSHOT_FILE}"; then
    log "Snapshot metadata saved to ${SNAPSHOT_FILE}"
else
    log_error "Failed to save snapshot metadata"
fi

# Output snapshot name for pipeline
echo "${SNAPSHOT_NAME}"

log "Sync complete: ${SNAPSHOT_NAME}"
exit 0
