#!/bin/bash
# ====================================
# SafeMirror Enterprise - Upgrade Script
# ====================================
# Usage: ./scripts/upgrade.sh [version]
# Example: ./scripts/upgrade.sh 0.3.0
# ====================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${PROJECT_DIR}/backups"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.prod.yml"
VERSION="${1:-latest}"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "Compose file not found: $COMPOSE_FILE"
        exit 1
    fi
}

get_current_version() {
    docker compose -f "$COMPOSE_FILE" exec -T api cat /app/enterprise/__init__.py 2>/dev/null | \
        grep -oP '__version__\s*=\s*"\K[^"]+' || echo "unknown"
}

backup_database() {
    log_info "Creating database backup..."
    
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="${BACKUP_DIR}/safemirror-$(date +%Y%m%d-%H%M%S).sql.gz"
    
    docker compose -f "$COMPOSE_FILE" exec -T db \
        pg_dump -U safemirror safemirror | gzip > "$BACKUP_FILE"
    
    if [ $? -eq 0 ]; then
        log_info "Backup created: $BACKUP_FILE"
    else
        log_error "Backup failed!"
        exit 1
    fi
}

pull_images() {
    log_info "Pulling new images (version: $VERSION)..."
    
    if [ "$VERSION" != "latest" ]; then
        export VERSION
    fi
    
    docker compose -f "$COMPOSE_FILE" pull
}

stop_services() {
    log_info "Stopping services..."
    docker compose -f "$COMPOSE_FILE" stop api worker beat frontend
}

run_migrations() {
    log_info "Running database migrations..."
    docker compose -f "$COMPOSE_FILE" run --rm api alembic upgrade head
}

start_services() {
    log_info "Starting services..."
    docker compose -f "$COMPOSE_FILE" up -d
}

health_check() {
    log_info "Performing health check..."
    
    MAX_ATTEMPTS=30
    ATTEMPT=0
    
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        if curl -sf http://localhost/health > /dev/null 2>&1; then
            log_info "Health check passed!"
            return 0
        fi
        
        ATTEMPT=$((ATTEMPT + 1))
        log_warn "Waiting for API... ($ATTEMPT/$MAX_ATTEMPTS)"
        sleep 2
    done
    
    log_error "Health check failed after $MAX_ATTEMPTS attempts"
    return 1
}

cleanup_old_images() {
    log_info "Cleaning up old images..."
    docker image prune -f
}

# Main execution
main() {
    echo "======================================"
    echo "SafeMirror Enterprise Upgrade"
    echo "======================================"
    
    cd "$PROJECT_DIR"
    
    check_prerequisites
    
    CURRENT_VERSION=$(get_current_version)
    log_info "Current version: $CURRENT_VERSION"
    log_info "Target version: $VERSION"
    
    # Confirm upgrade
    read -p "Proceed with upgrade? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Upgrade cancelled"
        exit 0
    fi
    
    # Upgrade steps
    backup_database
    pull_images
    stop_services
    run_migrations
    start_services
    
    # Verify
    if health_check; then
        cleanup_old_images
        log_info "======================================"
        log_info "Upgrade completed successfully!"
        log_info "New version: $(get_current_version)"
        log_info "======================================"
    else
        log_error "Upgrade may have failed. Check logs."
        log_warn "To rollback, restore from: $BACKUP_FILE"
        exit 1
    fi
}

main "$@"
