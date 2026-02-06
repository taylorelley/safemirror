#!/bin/bash
set -euo pipefail

# scripts/migrate.sh — Run Alembic migrations inside the API container.
#
# Usage:
#   ./scripts/migrate.sh                  # upgrade to head
#   ./scripts/migrate.sh upgrade head     # explicit upgrade
#   ./scripts/migrate.sh downgrade -1     # rollback one revision
#   ./scripts/migrate.sh current          # show current revision
#   ./scripts/migrate.sh history          # show revision history
#   ./scripts/migrate.sh heads            # show head revisions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
SERVICE="api"

cd "${PROJECT_ROOT}"

# Default action: upgrade to head
ACTION="${1:-upgrade}"
shift 2>/dev/null || true
ARGS="${*:-}"

if [ "${ACTION}" = "upgrade" ] && [ -z "${ARGS}" ]; then
    ARGS="head"
fi

echo "Running: alembic ${ACTION} ${ARGS}"
docker compose exec "${SERVICE}" alembic "${ACTION}" ${ARGS}
