#!/bin/bash
#
# publish-approved.sh - Filter and publish approved packages
#
# This script creates a filtered snapshot containing only approved
# packages and publishes it for client consumption.
#

set -euo pipefail

# Configuration
SOURCE_SNAPSHOT="${1:-}"
APPROVED_LIST="${2:-/opt/apt-mirror-system/approvals/approved.txt}"
DISTRIBUTION="${DISTRIBUTION:-jammy}"
GPG_KEY_ID="${GPG_KEY_ID:-}"
LOG_DIR="${LOG_DIR:-/opt/apt-mirror-system/logs}"
MAX_RETRIES="${MAX_RETRIES:-4}"
RETRY_DELAY="${RETRY_DELAY:-2}"

# Set script name for logging and source shared utilities
SCRIPT_NAME="publish-approved"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# Validate arguments
if [ -z "${SOURCE_SNAPSHOT}" ]; then
    log_error "Usage: $0 <source-snapshot> [approved-list]"
    exit 1
fi

if [ ! -f "${APPROVED_LIST}" ]; then
    log_error "Approved list not found: ${APPROVED_LIST}"
    exit 1
fi

log "Publishing approved packages from ${SOURCE_SNAPSHOT}"

# Create filtered snapshot name
APPROVED_SNAPSHOT="approved-${DATE_SUFFIX}"

log "Creating filtered snapshot ${APPROVED_SNAPSHOT}"

# Use aptly snapshot filter to create approved-only snapshot
# Note: aptly filter uses package queries, we need to convert our approved list
FILTER_QUERY=""

# Read approved packages and build filter query
# Format: Name (package1) | Name (package2) | ...
PACKAGE_COUNT=$(wc -l < "${APPROVED_LIST}")
log "Filtering ${PACKAGE_COUNT} approved packages"

# For large package lists, use include-file directly if supported
# Otherwise, build a query string (limited by command line length)
# Using 50 as threshold to safely avoid hitting shell command-line limits
if [ "${PACKAGE_COUNT}" -gt 50 ]; then
    # Use temporary filter file approach
    TEMP_FILTER=$(mktemp)

    # Convert approved.txt format to aptly filter format
    # approved.txt: package_version_arch
    # Need to extract just package names for Name() query
    while IFS= read -r line; do
        # Extract package name (before first underscore)
        pkg_name="${line%%_*}"
        echo "Name (${pkg_name})" >> "${TEMP_FILTER}"
    done < "${APPROVED_LIST}"

    # Join with OR
    FILTER_QUERY=$(paste -sd '|' "${TEMP_FILTER}")
    rm -f "${TEMP_FILTER}"
else
    # Build filter query directly for smaller lists
    while IFS= read -r line; do
        pkg_name="${line%%_*}"
        if [ -z "${FILTER_QUERY}" ]; then
            FILTER_QUERY="Name (${pkg_name})"
        else
            FILTER_QUERY="${FILTER_QUERY} | Name (${pkg_name})"
        fi
    done < "${APPROVED_LIST}"
fi

# Create filtered snapshot (FILTER_QUERY safely passed as parameter)
if ! retry_command aptly snapshot filter "${SOURCE_SNAPSHOT}" "${APPROVED_SNAPSHOT}" "${FILTER_QUERY}"; then
    log_error "Failed to create filtered snapshot"
    exit 1
fi

log "Filtered snapshot ${APPROVED_SNAPSHOT} created successfully"

# Check if publication exists
PUBLISH_EXISTS=false
if aptly publish list | grep -q "${DISTRIBUTION}"; then
    PUBLISH_EXISTS=true
    log "Existing publication found for ${DISTRIBUTION}, will switch"
else
    log "No existing publication found, will create new one"
fi

# Publish or switch to new snapshot
if [ "${PUBLISH_EXISTS}" = true ]; then
    # Switch existing publication to new snapshot
    if [ -n "${GPG_KEY_ID}" ]; then
        if ! retry_command aptly publish switch -gpg-key="${GPG_KEY_ID}" "${DISTRIBUTION}" "${APPROVED_SNAPSHOT}"; then
            log_error "Failed to switch publication to ${APPROVED_SNAPSHOT}"
            exit 1
        fi
    else
        if ! retry_command aptly publish switch "${DISTRIBUTION}" "${APPROVED_SNAPSHOT}"; then
            log_error "Failed to switch publication to ${APPROVED_SNAPSHOT}"
            exit 1
        fi
    fi

    log "Publication switched to ${APPROVED_SNAPSHOT}"
else
    # Create new publication
    if [ -n "${GPG_KEY_ID}" ]; then
        if ! retry_command aptly publish snapshot -gpg-key="${GPG_KEY_ID}" "${APPROVED_SNAPSHOT}" "${DISTRIBUTION}"; then
            log_error "Failed to publish snapshot ${APPROVED_SNAPSHOT}"
            exit 1
        fi
    else
        if ! retry_command aptly publish snapshot -skip-signing "${APPROVED_SNAPSHOT}" "${DISTRIBUTION}"; then
            log_error "Failed to publish snapshot ${APPROVED_SNAPSHOT}"
            exit 1
        fi
    fi

    log "Publication created for ${APPROVED_SNAPSHOT}"
fi

# Verify publication
if aptly publish show "${DISTRIBUTION}" > /dev/null 2>&1; then
    log "Publication verified successfully"
else
    log_error "Publication verification failed"
    exit 1
fi

log "Publish complete: ${APPROVED_SNAPSHOT} -> ${DISTRIBUTION}"
echo "${APPROVED_SNAPSHOT}"

exit 0
