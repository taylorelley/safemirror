#!/bin/bash
set -euo pipefail

# scripts/dev.sh — Start the full SafeMirror dev stack with hot-reload.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

cd "${PROJECT_ROOT}"

# Ensure .env exists
if [ ! -f .env ]; then
    echo "Creating .env from .env.example ..."
    cp .env.example .env
fi

# Install frontend deps if missing
if [ ! -d frontend/node_modules ]; then
    echo "Installing frontend dependencies ..."
    (cd frontend && npm install)
fi

# Build and start everything
echo "Starting SafeMirror dev stack ..."
docker compose up --build "$@"
