# SafeMirror Deployment Validation Checklist

Use this checklist to validate a fresh installation of SafeMirror Enterprise.

## Prerequisites Check

- [ ] Docker 24.0+ installed
- [ ] Docker Compose 2.20+ installed
- [ ] At least 4GB RAM available
- [ ] At least 20GB disk space
- [ ] Port 80/443 available

## Installation Steps

### 1. Clone and Configure

```bash
git clone https://github.com/safemirror/safemirror.git
cd safemirror
cp .env.prod.example .env.prod

# Generate secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
POSTGRES_PASSWORD=$(openssl rand -base64 24)

# Update .env.prod with generated values
sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env.prod
sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env.prod
```

**Validation:**
- [ ] .env.prod file exists with SECRET_KEY set
- [ ] POSTGRES_PASSWORD is set
- [ ] No unsafe default values

### 2. Build Images

```bash
docker compose -f docker-compose.prod.yml build
```

**Validation:**
- [ ] Build completes without errors
- [ ] safemirror/api image created
- [ ] safemirror/frontend image created

### 3. Start Services

```bash
docker compose -f docker-compose.prod.yml up -d
```

**Validation:**
- [ ] All containers start: `docker compose ps`
- [ ] No containers in "Restarting" state
- [ ] Logs show no errors: `docker compose logs`

### 4. Run Migrations

```bash
docker compose -f docker-compose.prod.yml exec api alembic upgrade head
```

**Validation:**
- [ ] Migrations complete successfully
- [ ] Database tables created

### 5. Seed Default Data (Optional)

```bash
docker compose -f docker-compose.prod.yml exec api python -m enterprise.db.seed
```

**Validation:**
- [ ] Default roles created
- [ ] No errors in output

## Health Checks

### API Health

```bash
curl http://localhost/health
```

**Expected:**
```json
{"status": "healthy", "version": "0.2.0"}
```

- [ ] Returns 200 OK
- [ ] Status is "healthy"

### Readiness Check

```bash
curl http://localhost/health/ready
```

- [ ] Returns 200 OK
- [ ] Database check passes
- [ ] Redis check passes

### Frontend

```bash
curl -I http://localhost/
```

- [ ] Returns 200 OK
- [ ] HTML content returned

## Functional Tests

### 1. User Registration

```bash
curl -X POST http://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d {email: test@example.com, password: Test123!, name: Test User, org_name: Test Org}
```

- [ ] Returns 201 Created
- [ ] User object returned

### 2. Login

```bash
curl -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@example.com&password=Test123!"
```

- [ ] Returns 200 OK
- [ ] access_token in response

### 3. Authenticated Request

```bash
TOKEN="<token from login>"
curl -X GET http://localhost/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

- [ ] Returns 200 OK
- [ ] User info returned

### 4. Rate Limiting

```bash
# Make 10 rapid requests
for i in {1..10}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost/api/auth/login \
    -X POST -d "username=x&password=x"
done
```

- [ ] Rate limit headers present
- [ ] 429 returned after limit exceeded

## Security Checks

### Security Headers

```bash
curl -I http://localhost/
```

- [ ] X-Content-Type-Options: nosniff
- [ ] X-Frame-Options: DENY
- [ ] X-XSS-Protection: 1; mode=block

### No Sensitive Data Exposure

- [ ] /docs not accessible (404)
- [ ] /redoc not accessible (404)
- [ ] Stack traces not exposed

## Cleanup

```bash
# Stop and remove containers
docker compose -f docker-compose.prod.yml down -v
```

## Results

| Check | Status | Notes |
|-------|--------|-------|
| Prerequisites | ☐ | |
| Build | ☐ | |
| Services Start | ☐ | |
| Migrations | ☐ | |
| Health Checks | ☐ | |
| Registration | ☐ | |
| Login | ☐ | |
| Auth Request | ☐ | |
| Rate Limiting | ☐ | |
| Security Headers | ☐ | |

**Validated By:** ___________________  
**Date:** ___________________  
**Environment:** ___________________

---

## Issues Found

Document any issues encountered during validation:

1. 
2. 
3. 

## Documentation Gaps

Note any missing or unclear documentation:

1. 
2. 
3. 
