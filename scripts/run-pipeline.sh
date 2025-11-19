#!/bin/bash
#
# run-pipeline.sh - Main orchestrator for safe-apt pipeline
#
# This script orchestrates the complete pipeline:
# 1. Sync upstream mirror
# 2. Detect changed packages
# 3. Scan packages
# 4. Build approved list
# 5. Publish approved mirror
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-/opt/apt-mirror-system}"
LOG_DIR="${LOG_DIR:-${BASE_DIR}/logs}"
SCANS_DIR="${SCANS_DIR:-${BASE_DIR}/scans}"
APPROVALS_DIR="${APPROVALS_DIR:-${BASE_DIR}/approvals}"
SNAPSHOTS_DIR="${SNAPSHOTS_DIR:-${BASE_DIR}/snapshots}"
MIRROR_NAME="${MIRROR_NAME:-ubuntu-jammy}"
DISTRIBUTION="${DISTRIBUTION:-jammy}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
APTLY_POOL="${APTLY_POOL:-/var/lib/aptly/pool}"

# Set script name for logging and source shared utilities
SCRIPT_NAME="run-pipeline"
source "${SCRIPT_DIR}/lib/common.sh"

# Cleanup on exit
cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Pipeline failed, check ${LOG_FILE} for details"
    fi
}
trap cleanup EXIT

log "========================================="
log "Starting safe-apt pipeline"
log "========================================="

# Step 1: Sync mirror and create snapshot
log "Step 1: Syncing mirror ${MIRROR_NAME}"

# Run sync-mirror.sh and capture output to temp file
SYNC_TEMP=$(mktemp)
if bash "${SCRIPT_DIR}/sync-mirror.sh" > "${SYNC_TEMP}" 2>&1; then
    # Sync succeeded, append output to log and extract snapshot name
    cat "${SYNC_TEMP}" >> "${LOG_FILE}"
    NEW_SNAPSHOT=$(tail -n 1 "${SYNC_TEMP}")
    rm -f "${SYNC_TEMP}"

    if [ -z "${NEW_SNAPSHOT}" ]; then
        log_error "Sync succeeded but no snapshot name returned"
        exit 1
    fi

    log "New snapshot created: ${NEW_SNAPSHOT}"
else
    # Sync failed, log error output and exit
    log_error "Mirror sync failed:"
    cat "${SYNC_TEMP}" | tee -a "${LOG_FILE}" >&2
    rm -f "${SYNC_TEMP}"
    exit 1
fi

# Step 2: Detect changes from previous snapshot
log "Step 2: Detecting changed packages"

# Find previous snapshot
PREVIOUS_SNAPSHOT=$(aptly snapshot list -raw | grep "^staging-" | grep -v "${NEW_SNAPSHOT}" | sort -r | head -n 1 || echo "")

if [ -z "${PREVIOUS_SNAPSHOT}" ]; then
    log "No previous snapshot found, this is the first run"
    log "Will scan all packages in snapshot"

    # Get all packages from new snapshot
    CHANGES_FILE="${SNAPSHOTS_DIR}/all-packages-${NEW_SNAPSHOT}.txt"
    aptly snapshot show -with-packages "${NEW_SNAPSHOT}" | grep '_' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "${CHANGES_FILE}" || true
else
    log "Comparing ${PREVIOUS_SNAPSHOT} -> ${NEW_SNAPSHOT}"

    bash "${SCRIPT_DIR}/detect-changes.sh" "${PREVIOUS_SNAPSHOT}" "${NEW_SNAPSHOT}" 2>&1 | tee -a "${LOG_FILE}" > /dev/null

    CHANGES_FILE="${SNAPSHOTS_DIR}/changes-${PREVIOUS_SNAPSHOT}-to-${NEW_SNAPSHOT}.txt"
fi

if [ ! -f "${CHANGES_FILE}" ]; then
    log_error "Changes file not found: ${CHANGES_FILE}"
    exit 1
fi

PACKAGE_COUNT=$(wc -l < "${CHANGES_FILE}")
log "Found ${PACKAGE_COUNT} packages to scan"

# Step 3: Scan changed packages
log "Step 3: Scanning packages for vulnerabilities"

if [ ${PACKAGE_COUNT} -eq 0 ]; then
    log "No packages to scan, skipping scan step"
else
    SCANNED=0
    FAILED=0

    # Read package list and scan each one
    while IFS= read -r package_key; do
        # Trim leading and trailing whitespace
        package_key=$(echo "${package_key}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip empty lines
        if [ -z "${package_key}" ]; then
            continue
        fi

        # Extract package information
        package_name="${package_key%%_*}"

        log "Scanning package: ${package_key}"

        # Find .deb file in aptly pool
        # Aptly pool structure: pool/main/p/package/package_version_arch.deb
        first_letter="${package_name:0:1}"
        pool_path=""

        # Search for the .deb file
        # Note: This is a simplified search, actual aptly pool structure may vary
        for prefix in "main" "restricted" "universe" "multiverse"; do
            search_path="${APTLY_POOL}/${prefix}/${first_letter}/${package_name}"

            if [ -d "${search_path}" ]; then
                deb_file=$(find "${search_path}" -name "${package_key}.deb" -print -quit 2>/dev/null || echo "")

                if [ -n "${deb_file}" ]; then
                    pool_path="${deb_file}"
                    break
                fi
            fi
        done

        if [ -z "${pool_path}" ] || [ ! -f "${pool_path}" ]; then
            log_error "Package file not found in pool: ${package_key}"
            FAILED=$((FAILED + 1))
            continue
        fi

        # Run scanner using Python module
        if ${PYTHON_BIN} -m src.scanner.scan_packages "${pool_path}" >> "${LOG_FILE}" 2>&1; then
            SCANNED=$((SCANNED + 1))
            log "Successfully scanned: ${package_key}"
        else
            FAILED=$((FAILED + 1))
            log_error "Failed to scan: ${package_key}"
        fi

    done < "${CHANGES_FILE}"

    log "Scan complete: ${SCANNED} successful, ${FAILED} failed"
fi

# Step 4: Build approved package list
log "Step 4: Building approved package list"

# Get all packages from new snapshot
ALL_PACKAGES_FILE="${SNAPSHOTS_DIR}/all-packages-${NEW_SNAPSHOT}.txt"
aptly snapshot show -with-packages "${NEW_SNAPSHOT}" | grep '_' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "${ALL_PACKAGES_FILE}" || true

# Run approval list builder
APPROVED_LIST="${APPROVALS_DIR}/approved.txt"

if ${PYTHON_BIN} -m src.publisher \
    --package-list "${ALL_PACKAGES_FILE}" \
    --output "${APPROVED_LIST}" >> "${LOG_FILE}" 2>&1; then
    log "Approved list built successfully"
else
    log_error "Failed to build approved list"
    exit 1
fi

APPROVED_COUNT=$(wc -l < "${APPROVED_LIST}" 2>/dev/null || echo "0")
log "Approved packages: ${APPROVED_COUNT}"

# Step 5: Publish approved mirror
log "Step 5: Publishing approved mirror"

if bash "${SCRIPT_DIR}/publish-approved.sh" "${NEW_SNAPSHOT}" "${APPROVED_LIST}" 2>&1 | tee -a "${LOG_FILE}"; then
    log "Publication successful"
else
    log_error "Publication failed"
    exit 1
fi

# Pipeline complete
log "========================================="
log "Pipeline completed successfully"
log "New snapshot: ${NEW_SNAPSHOT}"
log "Approved packages: ${APPROVED_COUNT}"
log "========================================="

exit 0
