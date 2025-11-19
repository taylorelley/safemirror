#!/bin/bash
#
# common.sh - Shared utility functions for safe-apt scripts
#
# Security: Uses array-based command execution to prevent command injection.
# All commands are executed via "${cmd[@]}" without eval, ensuring shell
# metacharacters are treated as data, not code.
#
# Usage:
#   SCRIPT_NAME="my-script"
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#
# Required: SCRIPT_NAME must be set before sourcing this file
# Optional: LOG_DIR, MAX_RETRIES, RETRY_DELAY
#

# Validate that SCRIPT_NAME is set
: "${SCRIPT_NAME:?SCRIPT_NAME must be set before sourcing common.sh}"

# Configuration with defaults
: "${LOG_DIR:=/opt/apt-mirror-system/logs}"
: "${MAX_RETRIES:=4}"
: "${RETRY_DELAY:=2}"

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

# Initialize logging session
TIMESTAMP=$(date +%Y-%m-%dT%H:%M:%S)
DATE_SUFFIX=$(date +%Y%m%d)
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-${DATE_SUFFIX}.log"

#
# log() - Write informational message to log file only
#
# Messages are written to log file without polluting stdout.
# This allows scripts to output specific data to stdout (like snapshot names)
# while keeping operational logs separate.
#
# Args:
#   $* - Message to log
#
log() {
    echo "${TIMESTAMP} [INFO] [${SCRIPT_NAME}] $*" >> "${LOG_FILE}"
}

#
# log_error() - Write error message to log file and stderr
#
# Error messages are written to both the log file and stderr for visibility.
#
# Args:
#   $* - Error message to log
#
log_error() {
    echo "${TIMESTAMP} [ERROR] [${SCRIPT_NAME}] $*" | tee -a "${LOG_FILE}" >&2
}

#
# retry_command() - Execute command with exponential backoff retry logic
#
# SECURITY: Uses array-based execution (no eval) to prevent command injection.
# Commands are executed via "${cmd[@]}" so shell metacharacters in arguments
# are treated as literal data, not interpreted as code.
#
# Args:
#   $@ - Command and arguments to execute (passed as separate parameters)
#
# Returns:
#   0 - Command succeeded within retry limit
#   1 - Command failed after all retries exhausted
#
# Example:
#   retry_command aptly mirror update ubuntu-jammy
#   retry_command cp "${source}" "${dest}"
#
retry_command() {
    local -a cmd=("$@")  # Capture command as array
    local attempt=1
    local delay="${RETRY_DELAY}"
    local cmd_display="${*}"  # For logging display only, not execution

    while [ ${attempt} -le ${MAX_RETRIES} ]; do
        log "Attempt ${attempt}/${MAX_RETRIES}: ${cmd_display}"

        # Safe execution - no eval, shell metacharacters treated as data
        if "${cmd[@]}"; then
            log "Command succeeded: ${cmd_display}"
            return 0
        fi

        if [ ${attempt} -lt ${MAX_RETRIES} ]; then
            log "Command failed, retrying in ${delay}s..."
            sleep "${delay}"
            delay=$((delay * 2))  # Exponential backoff
        fi

        attempt=$((attempt + 1))
    done

    log_error "Command failed after ${MAX_RETRIES} attempts: ${cmd_display}"
    return 1
}
