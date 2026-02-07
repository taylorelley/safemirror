#!/bin/bash
# ====================================
# SafeMirror Enterprise - Migration Script
# ====================================
# Usage: 
#   ./scripts/migrate.sh              # Run pending migrations
#   ./scripts/migrate.sh upgrade head # Upgrade to head
#   ./scripts/migrate.sh downgrade -1 # Rollback one migration
#   ./scripts/migrate.sh history      # Show migration history
#   ./scripts/migrate.sh current      # Show current revision
# ====================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.prod.yml"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running in Docker or locally
detect_environment() {
    if [ -f "$COMPOSE_FILE" ] && docker compose -f "$COMPOSE_FILE" ps --quiet api 2>/dev/null | head -1 | grep -q .; then
        echo "docker"
    elif [ -f "${PROJECT_DIR}/alembic.ini" ]; then
        echo "local"
    else
        echo "unknown"
    fi
}

run_alembic() {
    ENV=$(detect_environment)
    
    case $ENV in
        docker)
            docker compose -f "$COMPOSE_FILE" exec -T api alembic "$@"
            ;;
        local)
            cd "$PROJECT_DIR"
            alembic "$@"
            ;;
        *)
            log_error "Cannot detect environment. Make sure Docker is running or alembic is installed."
            exit 1
            ;;
    esac
}

show_help() {
    echo "SafeMirror Migration Script"
    echo ""
    echo "Usage: $0 [command] [args]"
    echo ""
    echo "Commands:"
    echo "  (none)          Run pending migrations (upgrade head)"
    echo "  upgrade [rev]   Upgrade to revision (default: head)"
    echo "  downgrade [rev] Downgrade to revision (e.g., -1, base)"
    echo "  current         Show current revision"
    echo "  history         Show migration history"
    echo "  heads           Show current heads"
    echo "  branches        Show branch points"
    echo "  stamp [rev]     Set revision without running migrations"
    echo "  generate [msg]  Generate new migration (auto or manual)"
    echo ""
    echo "Examples:"
    echo "  $0                      # Apply all pending migrations"
    echo "  $0 downgrade -1         # Rollback one migration"
    echo "  $0 downgrade base       # Rollback all migrations"
    echo "  $0 history              # Show migration history"
    echo "  $0 generate \"add users\" # Create new migration"
}

# Main execution
main() {
    COMMAND="${1:-upgrade}"
    
    case $COMMAND in
        -h|--help|help)
            show_help
            exit 0
            ;;
        upgrade)
            REVISION="${2:-head}"
            log_info "Upgrading to: $REVISION"
            run_alembic upgrade "$REVISION"
            log_info "Migration complete"
            ;;
        downgrade)
            REVISION="${2:--1}"
            log_warn "Downgrading to: $REVISION"
            read -p "Are you sure? This may cause data loss. (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                run_alembic downgrade "$REVISION"
                log_info "Downgrade complete"
            else
                log_warn "Downgrade cancelled"
            fi
            ;;
        current)
            log_info "Current revision:"
            run_alembic current
            ;;
        history)
            log_info "Migration history:"
            run_alembic history --verbose
            ;;
        heads)
            run_alembic heads
            ;;
        branches)
            run_alembic branches
            ;;
        stamp)
            REVISION="${2:-head}"
            log_warn "Stamping database at: $REVISION (no migrations run)"
            run_alembic stamp "$REVISION"
            ;;
        generate)
            MESSAGE="${2:-new_migration}"
            log_info "Generating migration: $MESSAGE"
            run_alembic revision --autogenerate -m "$MESSAGE"
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
