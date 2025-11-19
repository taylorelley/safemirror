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

# Logging
TIMESTAMP=$(date +%Y-%m-%dT%H:%M:%S)
DATE_SUFFIX=$(date +%Y%m%d)
LOG_FILE="${LOG_DIR}/sync-${DATE_SUFFIX}.log"

mkdir -p "${LOG_DIR}" "${SNAPSHOTS_DIR}"

log() {
    echo "${TIMESTAMP} [INFO] [sync-mirror] $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "${TIMESTAMP} [ERROR] [sync-mirror] $*" | tee -a "${LOG_FILE}" >&2
}

retry_command() {
    local cmd="$*"
    local attempt=1
    local delay="${RETRY_DELAY}"

    while [ ${attempt} -le ${MAX_RETRIES} ]; do
        log "Attempt ${attempt}/${MAX_RETRIES}: ${cmd}"

        if eval "${cmd}"; then
            log "Command succeeded: ${cmd}"
            return 0
        fi

        if [ ${attempt} -lt ${MAX_RETRIES} ]; then
            log "Command failed, retrying in ${delay}s..."
            sleep "${delay}"
            delay=$((delay * 2))
        fi

        attempt=$((attempt + 1))
    done

    log_error "Command failed after ${MAX_RETRIES} attempts: ${cmd}"
    return 1
}

# Update mirror from upstream
log "Starting mirror update for ${MIRROR_NAME}"

if ! retry_command "aptly mirror update ${MIRROR_NAME}"; then
    log_error "Failed to update mirror ${MIRROR_NAME}"
    exit 1
fi

log "Mirror update completed successfully"

# Create snapshot
SNAPSHOT_NAME="${SNAPSHOT_PREFIX}-${DATE_SUFFIX}"

log "Creating snapshot ${SNAPSHOT_NAME} from mirror ${MIRROR_NAME}"

if ! retry_command "aptly snapshot create ${SNAPSHOT_NAME} from mirror ${MIRROR_NAME}"; then
    log_error "Failed to create snapshot ${SNAPSHOT_NAME}"
    exit 1
fi

log "Snapshot ${SNAPSHOT_NAME} created successfully"

# Save snapshot metadata
SNAPSHOT_FILE="${SNAPSHOTS_DIR}/${SNAPSHOT_NAME}.txt"

if retry_command "aptly snapshot show -with-packages '${SNAPSHOT_NAME}' > '${SNAPSHOT_FILE}'"; then
    log "Snapshot metadata saved to ${SNAPSHOT_FILE}"
else
    log_error "Failed to save snapshot metadata"
fi

# Output snapshot name for pipeline
echo "${SNAPSHOT_NAME}"

log "Sync complete: ${SNAPSHOT_NAME}"
exit 0
