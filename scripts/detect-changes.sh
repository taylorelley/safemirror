#!/bin/bash
#
# detect-changes.sh - Detect changed packages between snapshots
#
# This script compares two aptly snapshots and outputs a list of
# packages that have been added or modified.
#

set -euo pipefail

# Configuration
LOG_DIR="${LOG_DIR:-/opt/apt-mirror-system/logs}"
SNAPSHOTS_DIR="${SNAPSHOTS_DIR:-/opt/apt-mirror-system/snapshots}"

# Arguments
OLD_SNAPSHOT="${1:-}"
NEW_SNAPSHOT="${2:-}"

# Set script name for logging and source shared utilities
SCRIPT_NAME="detect-changes"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# Ensure snapshots directory exists
mkdir -p "${SNAPSHOTS_DIR}"

# Validate arguments
if [ -z "${OLD_SNAPSHOT}" ] || [ -z "${NEW_SNAPSHOT}" ]; then
    log_error "Usage: $0 <old-snapshot> <new-snapshot>"
    exit 1
fi

log "Detecting changes between ${OLD_SNAPSHOT} and ${NEW_SNAPSHOT}"

# Check if snapshots exist
if ! aptly snapshot show "${OLD_SNAPSHOT}" > /dev/null 2>&1; then
    log_error "Old snapshot not found: ${OLD_SNAPSHOT}"
    exit 1
fi

if ! aptly snapshot show "${NEW_SNAPSHOT}" > /dev/null 2>&1; then
    log_error "New snapshot not found: ${NEW_SNAPSHOT}"
    exit 1
fi

# Get package diff
DIFF_OUTPUT=$(aptly snapshot diff "${OLD_SNAPSHOT}" "${NEW_SNAPSHOT}" 2>&1)
DIFF_EXIT=$?

# Check for real errors (exit code > 1 typically indicates infrastructure failure)
# aptly returns 0 for success, may return 1 for differences found
if [ ${DIFF_EXIT} -gt 1 ]; then
    log_error "aptly snapshot diff failed with exit code ${DIFF_EXIT}"
    log_error "Output: ${DIFF_OUTPUT}"
    exit 1
fi

# Parse diff output
# aptly snapshot diff format:
#   Arch 'amd64' (added 2, removed 1, left 1234, changed 3)
#   +package-name_1.0.0_amd64
#   -old-package_0.9.0_amd64
#   !updated-package_2.0.0_amd64 -> !updated-package_2.0.1_amd64

CHANGES_FILE="${SNAPSHOTS_DIR}/changes-${OLD_SNAPSHOT}-to-${NEW_SNAPSHOT}.txt"

# Extract added and changed packages (lines starting with + or !)
# For lines with ->, extract the new package (right side)
{
    echo "${DIFF_OUTPUT}" | grep -E '^\+|^!' || true
} | while IFS= read -r line; do
    # Remove leading +/! marker
    clean_line="${line#[+!]}"

    # Check if line contains ->
    if [[ "${clean_line}" =~ "->" ]]; then
        # Extract right side (new package) after ->
        echo "${clean_line}" | sed 's/.*-> *//' | sed 's/^!//'
    else
        # No ->, just output the cleaned line
        echo "${clean_line}"
    fi
done > "${CHANGES_FILE}"

CHANGE_COUNT=$(wc -l < "${CHANGES_FILE}")

if [ "${CHANGE_COUNT}" -eq 0 ]; then
    log "No package changes detected"
    echo ""  # Empty output for pipeline
else
    log "Detected ${CHANGE_COUNT} changed packages"
    log "Changes saved to ${CHANGES_FILE}"

    # Output package list for pipeline
    cat "${CHANGES_FILE}"
fi

exit 0
