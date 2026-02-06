# Development Guide

## Prerequisites

- Docker & Docker Compose v2
- Node.js 22+ (for local frontend work outside Docker)

## Quick Start

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Start the full stack (builds images, starts all services)
./scripts/dev.sh
```

This brings up:

| Service    | URL                      | Hot-reload |
|------------|--------------------------|------------|
| API        | http://localhost:8000    | Yes — uvicorn `--reload` watches `enterprise/` and `src/` |
| Frontend   | http://localhost:3000    | Yes — Next.js Turbopack HMR |
| PostgreSQL | localhost:5432           | n/a |
| Redis      | localhost:6379           | n/a |
| Worker     | (background)             | Yes — `watchfiles` restarts Celery on Python changes |

## Hot-Reload Details

### FastAPI (api service)

Uvicorn runs with `--reload --reload-dir enterprise --reload-dir src`, so only
Python changes in the mounted `enterprise/` and `src/` directories trigger a
restart. Edits to tests, scripts, or docs are ignored.

### Next.js (frontend service)

Next.js runs in dev mode with Turbopack (`next dev --turbopack`). The `src/` and
`public/` directories are bind-mounted so file changes on the host propagate
instantly. `WATCHPACK_POLLING=true` is set to ensure reliable change detection
inside Docker.

### Celery (worker service)

The worker uses [`watchfiles`](https://watchfiles.helpmanual.io/) to monitor
`enterprise/` and `src/` for Python file changes. When a change is detected, the
Celery worker process is restarted automatically.

## Environment Variables

All variables are defined in `.env.example`. Copy it to `.env` and override as
needed. Key variables:

| Variable              | Default                          | Purpose |
|-----------------------|----------------------------------|---------|
| `DB_PASSWORD`         | `devpass`                        | PostgreSQL password |
| `DATABASE_URL`        | `postgresql://...@db:5432/...`   | Full DB connection string |
| `REDIS_URL`           | `redis://redis:6379/0`           | Redis broker/cache |
| `SECRET_KEY`          | `dev-secret-key-change-in-prod`  | JWT signing key |
| `DEBUG`               | `true`                           | Enables Swagger UI at `/docs` |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000`          | API URL used by frontend |

## Database Migrations

Migrations are managed by [Alembic](https://alembic.sqlalchemy.org/) and live in
`enterprise/migrations/versions/`. A convenience wrapper is provided at
`scripts/migrate.sh`.

### Running Migrations

```bash
# Apply all pending migrations (default action)
./scripts/migrate.sh

# Explicit upgrade to latest
./scripts/migrate.sh upgrade head

# Rollback the last migration
./scripts/migrate.sh downgrade -1

# Show current revision
./scripts/migrate.sh current

# Show migration history
./scripts/migrate.sh history
```

Or run Alembic directly inside the container:

```bash
docker compose exec api alembic upgrade head
docker compose exec api alembic downgrade -1
```

### Creating a New Migration

1. Edit or add models in `enterprise/db/models/`.
2. Generate a migration (autogenerate compares models to the database):
   ```bash
   docker compose exec api alembic revision --autogenerate -m "describe change"
   ```
3. Review the generated file in `enterprise/migrations/versions/` and adjust if
   needed — autogenerate does not detect all changes (e.g. renamed columns).
4. Apply: `./scripts/migrate.sh upgrade head`
5. Verify: `./scripts/migrate.sh current`

### Writing Migrations by Hand

For non-trivial schema changes, write the migration manually:

```bash
docker compose exec api alembic revision -m "describe change"
```

Then fill in the `upgrade()` and `downgrade()` functions in the generated file.
Always ensure `downgrade()` fully reverses `upgrade()`.

### Resetting the Database

```bash
# Drop all data and volumes, then re-apply migrations
docker compose down -v
./scripts/dev.sh
# In another terminal, once services are healthy:
./scripts/migrate.sh
```

### Migration Conventions

- One migration per logical change.
- Use `server_default` instead of Python-side `default` for columns so that raw
  SQL inserts and `\copy` also get correct defaults.
- Name constraints explicitly using the naming convention defined in
  `enterprise/db/base.py` (e.g. `pk_<table>`, `fk_<table>_<col>_<ref_table>`,
  `uq_<table>_<col>`).
- Drop tables in reverse dependency order in `downgrade()`.
- Test both upgrade and downgrade before merging.

## Testing

### Running Tests

```bash
# Run all unit tests (no database required)
pytest tests/unit/

# Run all tests including database tests (requires PostgreSQL)
pytest

# Run only database tests
pytest -m db

# Run integration tests (migrations + DB fixtures)
pytest -m integration

# Skip database tests
pytest -m "not db"

# Run with coverage
pytest --cov=enterprise --cov=src --cov-report=term-missing
```

Inside Docker:

```bash
docker compose exec api pytest
docker compose exec api pytest -m db
```

### Test Database Setup

Database tests need a reachable PostgreSQL instance. The fixture system tries
connections in this order:

1. `TEST_DATABASE_URL` env var (default: `safemirror_test` database)
2. `DATABASE_URL` env var (falls back to the dev `safemirror` database)
3. Skips if neither is reachable

To use a dedicated test database (recommended):

```bash
# Create the test database once
docker compose exec db psql -U safemirror -c "CREATE DATABASE safemirror_test;"

# Or set the env var to point at your test instance
export TEST_DATABASE_URL="postgresql://safemirror:devpass@localhost:5432/safemirror_test"
```

### Available Fixtures

All database fixtures are defined in `tests/conftest.py`.

| Fixture             | Scope    | Description |
|---------------------|----------|-------------|
| `db_engine`         | session  | SQLAlchemy engine; creates tables once, drops at end |
| `db_session`        | function | Transactional session — **auto-rolls back** after each test |
| `db_session_module` | module   | Shared session for a module; truncates tables at teardown |
| `org_factory`       | function | Creates `Organization` records with sensible defaults |
| `role_factory`      | function | Creates `Role` records (auto-creates org if not given) |
| `user_factory`      | function | Creates `User` records (auto-creates org + role if not given) |
| `policy_factory`    | function | Creates `Policy` records |
| `scan_factory`      | function | Creates `Scan` records (auto-creates org + user if not given) |
| `audit_log_factory` | function | Creates `AuditLog` records |

### Writing a Database Test

```python
import pytest

pytestmark = pytest.mark.db  # registers the test as needing a database


def test_create_user(user_factory, db_session):
    """Factory creates a user with all required relationships."""
    user = user_factory(name="Alice", email="alice@test.com")
    assert user.id is not None
    assert user.organization is not None

    # session rolls back automatically — nothing to clean up


def test_custom_relationships(org_factory, role_factory, user_factory):
    """Pass explicit org/role to control relationships."""
    org = org_factory(name="Acme")
    role = role_factory(org=org, name="admin", permissions=["read", "write"])
    user = user_factory(org=org, role=role)
    assert user.organization.name == "Acme"
    assert user.role.name == "admin"
```

### Factory Functions

The factory functions in `tests/factories.py` can also be called directly if
you prefer not to use the fixture wrappers:

```python
from tests.factories import create_organization, create_user

def test_direct_factory(db_session):
    org = create_organization(db_session, name="Direct")
    user = create_user(db_session, org=org, email="d@test.com")
    assert user.organization.name == "Direct"
```

Every factory auto-generates unique values (names, slugs, emails) so tests
never collide even when defaults are used.

### Test Markers

| Marker        | Meaning |
|---------------|---------|
| `db`          | Requires a PostgreSQL database |
| `integration` | Integration test (may be slower) |
| `slow`        | Long-running test |
| `benchmark`   | Performance benchmark |

## Common Commands

```bash
# Start all services
./scripts/dev.sh

# Start only backend services (no frontend)
docker compose up api db redis worker

# Rebuild after dependency changes
docker compose up --build

# Run backend tests
docker compose exec api pytest

# Run DB migrations
./scripts/migrate.sh

# View logs for a single service
docker compose logs -f api

# Stop everything
docker compose down

# Stop and remove volumes (reset database)
docker compose down -v
```

## Project Layout

```
.env.example          # Environment template (commit this)
.env                  # Local overrides (git-ignored)
docker-compose.yml    # Dev stack definition
Dockerfile            # Backend image
frontend/
  Dockerfile          # Frontend image
  src/app/            # Next.js App Router pages
  next.config.ts      # Proxy rewrites to API
enterprise/           # FastAPI backend
  migrations/         # Alembic migrations
    versions/         # Individual migration scripts
scripts/
  dev.sh              # One-command dev startup
  migrate.sh          # Migration wrapper
src/                  # Core scanning library
```
