# Phase 1: Foundation Plan

## Directory Structure

```
enterprise/
├── api/                     # FastAPI application
│   ├── __init__.py
│   ├── main.py              # App entry point
│   ├── deps.py              # Dependencies (DB session, current user)
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py          # Login, register, logout, password reset
│   │   ├── users.py         # User CRUD
│   │   ├── orgs.py          # Organization management
│   │   ├── scans.py         # Scan endpoints
│   │   └── policies.py      # Security policy management
│   └── schemas/
│       ├── __init__.py
│       ├── auth.py
│       ├── user.py
│       ├── org.py
│       ├── scan.py
│       └── policy.py
├── core/
│   ├── __init__.py
│   ├── config.py            # Settings (env vars)
│   ├── security.py          # Password hashing, JWT tokens
│   └── auth.py              # Auth logic
├── db/
│   ├── __init__.py
│   ├── base.py              # SQLAlchemy declarative base
│   ├── session.py           # Database session factory
│   └── models/
│       ├── __init__.py
│       ├── user.py
│       ├── org.py
│       ├── role.py
│       ├── policy.py
│       ├── scan.py
│       └── audit.py
├── migrations/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
└── workers/
    ├── __init__.py
    └── scan_tasks.py        # Celery tasks for background scanning
```

## Docker Compose Services

```yaml
services:
  api:
    build: .
    ports: ["8000:8000"]
    depends_on: [db, redis]
    
  db:
    image: postgres:15-alpine
    volumes: [postgres_data:/var/lib/postgresql/data]
    environment:
      POSTGRES_DB: safemirror
      POSTGRES_USER: safemirror
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      
  redis:
    image: redis:7-alpine
    
  worker:
    build: .
    command: celery -A enterprise.workers worker -l info
    depends_on: [db, redis]
```

## Database Schema

### users
- id: UUID (PK)
- email: VARCHAR(255) UNIQUE NOT NULL
- password_hash: VARCHAR(255) NOT NULL
- name: VARCHAR(255)
- org_id: UUID (FK -> organizations)
- role_id: UUID (FK -> roles)
- is_active: BOOLEAN DEFAULT true
- created_at: TIMESTAMP
- updated_at: TIMESTAMP
- last_login: TIMESTAMP

### organizations
- id: UUID (PK)
- name: VARCHAR(255) NOT NULL
- slug: VARCHAR(100) UNIQUE NOT NULL
- settings: JSONB DEFAULT {}
- created_at: TIMESTAMP
- updated_at: TIMESTAMP

### roles
- id: UUID (PK)
- org_id: UUID (FK -> organizations)
- name: VARCHAR(100) NOT NULL
- permissions: JSONB NOT NULL
- is_system: BOOLEAN DEFAULT false
- created_at: TIMESTAMP

### policies
- id: UUID (PK)
- org_id: UUID (FK -> organizations)
- name: VARCHAR(255) NOT NULL
- description: TEXT
- rules: JSONB NOT NULL
- enabled: BOOLEAN DEFAULT true
- created_at: TIMESTAMP
- updated_at: TIMESTAMP

### scans
- id: UUID (PK)
- org_id: UUID (FK -> organizations)
- user_id: UUID (FK -> users)
- package_type: VARCHAR(50) NOT NULL (deb, rpm, apk, pypi, npm)
- package_name: VARCHAR(255) NOT NULL
- package_version: VARCHAR(100)
- status: VARCHAR(50) NOT NULL (pending, running, completed, failed)
- results: JSONB
- policy_id: UUID (FK -> policies, nullable)
- created_at: TIMESTAMP
- started_at: TIMESTAMP
- completed_at: TIMESTAMP

### audit_logs
- id: UUID (PK)
- org_id: UUID (FK -> organizations)
- user_id: UUID (FK -> users)
- action: VARCHAR(100) NOT NULL
- resource_type: VARCHAR(100) NOT NULL
- resource_id: UUID
- details: JSONB
- ip_address: INET
- created_at: TIMESTAMP

## Default Roles

1. **admin** - Full access to everything
2. **security_engineer** - Manage policies, view all scans, approve exceptions
3. **developer** - Submit scans, view own results
4. **viewer** - Read-only access

## Migration Strategy

1. Initialize Alembic with SQLAlchemy models
2. Create initial migration with all tables
3. Add default roles in migration
4. Add indexes for common queries (org_id, status, created_at)

## Phase 1 Tasks Order

1. Create enterprise/ directory structure
2. Set up Docker Compose
3. Create SQLAlchemy models
4. Initialize Alembic and create first migration
5. Implement user registration and login
6. Add JWT authentication
7. Create API router structure
8. Add password reset flow
9. Write auth middleware
10. Set up pytest fixtures
