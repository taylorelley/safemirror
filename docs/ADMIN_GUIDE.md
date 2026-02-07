# SafeMirror Enterprise - Administrator Guide

This guide covers installation, configuration, and administration of SafeMirror Enterprise.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [User Management](#user-management)
5. [Role-Based Access Control](#role-based-access-control)
6. [Backup and Restore](#backup-and-restore)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)
10. [Security Hardening](#security-hardening)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Disk | 50 GB SSD | 200+ GB SSD |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

- Docker 24.0+ and Docker Compose 2.20+
- OR Kubernetes 1.28+ with Helm 3.14+
- PostgreSQL 14+ (if external)
- Redis 7+ (if external)

### Network Ports

| Port | Service | Notes |
|------|---------|-------|
| 80 | HTTP | Redirect to HTTPS |
| 443 | HTTPS | Main application |
| 5432 | PostgreSQL | Internal only |
| 6379 | Redis | Internal only |
| 8000 | API | Internal only |
| 3000 | Frontend | Internal only |

---

## Installation

### Docker Compose Installation

1. **Clone and prepare**:
```bash
git clone https://github.com/safemirror/safemirror.git
cd safemirror
cp .env.prod.example .env.prod
```

2. **Configure secrets**:
```bash
# Generate secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
echo "SECRET_KEY=$SECRET_KEY" >> .env.prod

# Set database password
echo "POSTGRES_PASSWORD=$(openssl rand -base64 24)" >> .env.prod
```

3. **Build and start**:
```bash
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

4. **Run migrations**:
```bash
docker compose -f docker-compose.prod.yml exec api alembic upgrade head
```

5. **Seed default data**:
```bash
docker compose -f docker-compose.prod.yml exec api python -m enterprise.db.seed
```

### Kubernetes Installation

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed Kubernetes deployment instructions.

```bash
# Quick start
helm install safemirror ./helm/safemirror \
  --set config.secretKey="$(openssl rand -base64 48)" \
  --set postgresql.auth.password="$(openssl rand -base64 24)" \
  --set ingress.hosts[0].host=safemirror.example.com
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing key (required) | - |
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `DEBUG` | Enable debug mode | `false` |
| `CORS_ORIGINS` | Allowed CORS origins | `[]` |
| `SMTP_HOST` | SMTP server for emails | - |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username | - |
| `SMTP_PASSWORD` | SMTP password | - |
| `SMTP_FROM_EMAIL` | From email address | `noreply@safemirror.local` |

### SMTP Configuration

For email notifications and password resets:

```bash
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=safemirror@example.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_EMAIL=noreply@safemirror.example.com
SMTP_USE_TLS=true
```

### SSO Configuration

SafeMirror supports SAML 2.0 and OIDC:

```bash
# Via admin UI: Settings > SSO Configuration
# Or via API:
curl -X POST https://safemirror.example.com/api/sso/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "okta",
    "metadata_url": "https://company.okta.com/app/.../sso/saml/metadata",
    "enabled": true
  }'
```

---

## User Management

### Creating the First Admin

After initial installation:

```bash
# Via API
curl -X POST https://safemirror.example.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "name": "Admin User",
    "org_name": "My Organization"
  }'
```

### Managing Users

#### List Users
```bash
curl -X GET https://safemirror.example.com/api/users \
  -H "Authorization: Bearer $TOKEN"
```

#### Create User
```bash
curl -X POST https://safemirror.example.com/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "name": "New User",
    "role_id": "ROLE_UUID",
    "password": "TempPassword123!"
  }'
```

#### Deactivate User
```bash
curl -X PATCH https://safemirror.example.com/api/users/{user_id} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_active": false}'
```

---

## Role-Based Access Control

### Default Roles

| Role | Description | Key Permissions |
|------|-------------|-----------------|
| Admin | Full system access | `*:*` |
| Security Lead | Security team lead | Approvals, policies, reports |
| Security Analyst | Security reviewer | View, approve, reports |
| Developer | Development team | View packages, request approvals |
| Viewer | Read-only access | View only |

### Permissions

Permissions follow the format: `resource:action`

| Resource | Actions |
|----------|---------|
| `users` | `create`, `read`, `update`, `delete`, `list` |
| `roles` | `create`, `read`, `update`, `delete`, `list`, `assign` |
| `mirrors` | `create`, `read`, `update`, `delete`, `list`, `sync` |
| `packages` | `read`, `list`, `scan` |
| `approvals` | `create`, `read`, `update`, `delete`, `list`, `approve`, `reject` |
| `policies` | `create`, `read`, `update`, `delete`, `list` |
| `audit` | `read`, `list`, `export` |

### Creating Custom Roles

```bash
curl -X POST https://safemirror.example.com/api/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Package Manager",
    "permissions": [
      "packages:read",
      "packages:list",
      "packages:scan",
      "approvals:create",
      "approvals:read"
    ]
  }'
```

---

## Backup and Restore

### Database Backup

#### Automated Backups
```bash
# Add to crontab
0 2 * * * docker compose -f docker-compose.prod.yml exec -T db pg_dump -U safemirror safemirror | gzip > /backups/safemirror-$(date +\%Y\%m\%d).sql.gz
```

#### Manual Backup
```bash
# Full database backup
docker compose -f docker-compose.prod.yml exec db pg_dump -U safemirror -F c safemirror > backup.dump

# Compressed backup
docker compose -f docker-compose.prod.yml exec db pg_dump -U safemirror safemirror | gzip > backup.sql.gz
```

### Database Restore

```bash
# Stop application
docker compose -f docker-compose.prod.yml stop api worker beat

# Restore
docker compose -f docker-compose.prod.yml exec -T db pg_restore -U safemirror -d safemirror -c backup.dump

# Or from SQL
gunzip -c backup.sql.gz | docker compose -f docker-compose.prod.yml exec -T db psql -U safemirror safemirror

# Restart application
docker compose -f docker-compose.prod.yml up -d
```

### Backup Retention

```bash
# Clean old backups (keep last 30 days)
find /backups -name "safemirror-*.sql.gz" -mtime +30 -delete
```

---

## Monitoring

### Health Checks

```bash
# API health
curl https://safemirror.example.com/health

# Expected response:
# {"status": "healthy", "version": "0.2.0"}
```

### Logs

```bash
# All services
docker compose -f docker-compose.prod.yml logs -f

# Specific service
docker compose -f docker-compose.prod.yml logs -f api

# Last 100 lines
docker compose -f docker-compose.prod.yml logs --tail=100 api
```

### Metrics (Prometheus)

Add to values.yaml for Kubernetes:
```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    namespace: monitoring
```

### Alerting

Recommended alerts:
- API health check failures
- Database connection errors
- Redis connection errors
- High memory usage (>80%)
- High CPU usage (>70%)
- Failed login attempts (>10/min)
- Certificate expiry (<30 days)

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed
```bash
# Check database is running
docker compose -f docker-compose.prod.yml ps db

# Check logs
docker compose -f docker-compose.prod.yml logs db

# Test connection
docker compose -f docker-compose.prod.yml exec db psql -U safemirror -c "SELECT 1"
```

#### 2. API Not Starting
```bash
# Check logs
docker compose -f docker-compose.prod.yml logs api

# Common causes:
# - Missing SECRET_KEY
# - Invalid DATABASE_URL
# - Port already in use
```

#### 3. Frontend Not Loading
```bash
# Check frontend logs
docker compose -f docker-compose.prod.yml logs frontend

# Check nginx logs
docker compose -f docker-compose.prod.yml logs nginx

# Verify API is accessible from frontend
docker compose -f docker-compose.prod.yml exec frontend wget -O- http://api:8000/health
```

#### 4. Worker Tasks Not Processing
```bash
# Check worker logs
docker compose -f docker-compose.prod.yml logs worker

# Check Redis connection
docker compose -f docker-compose.prod.yml exec redis redis-cli ping
```

### Debug Mode

**WARNING**: Never enable in production with real data!

```bash
# Temporarily enable debug
docker compose -f docker-compose.prod.yml exec api DEBUG=true uvicorn enterprise.api.main:app
```

---

## Performance Tuning

### API Server

```yaml
# In docker-compose.prod.yml
api:
  command: uvicorn enterprise.api.main:app --host 0.0.0.0 --port 8000 --workers 8
  deploy:
    resources:
      limits:
        cpus: "4"
        memory: 4G
```

### Database

```sql
-- PostgreSQL tuning (for 16GB RAM server)
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET work_mem = '256MB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
SELECT pg_reload_conf();
```

### Redis

```conf
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
```

---

## Security Hardening

### Checklist

- [ ] Change default SECRET_KEY
- [ ] Set DEBUG=false
- [ ] Configure HTTPS/TLS
- [ ] Set specific CORS origins
- [ ] Enable rate limiting
- [ ] Configure firewall rules
- [ ] Set up intrusion detection
- [ ] Enable audit logging
- [ ] Regular security updates
- [ ] Implement backup encryption

### Firewall Rules

```bash
# Allow only necessary ports
ufw default deny incoming
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (redirect)
ufw allow 443/tcp  # HTTPS
ufw enable
```

### Audit Log Review

```bash
# Export audit logs
curl -X GET "https://safemirror.example.com/api/audit?limit=1000&format=json" \
  -H "Authorization: Bearer $TOKEN" > audit-export.json

# Review failed logins
curl -X GET "https://safemirror.example.com/api/audit?action=login&status=failed" \
  -H "Authorization: Bearer $TOKEN"
```

---

*For support, contact support@safemirror.io or visit https://docs.safemirror.io*
