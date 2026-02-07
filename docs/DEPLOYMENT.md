# SafeMirror Enterprise - Deployment Guide

This guide covers deploying SafeMirror Enterprise in various environments.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Cloud Deployments](#cloud-deployments)
5. [Environment Variables](#environment-variables)
6. [Database Setup](#database-setup)
7. [Post-Deployment](#post-deployment)

---

## Quick Start

### Docker (Fastest)

```bash
# Clone repository
git clone https://github.com/safemirror/safemirror.git
cd safemirror

# Configure environment
cp .env.prod.example .env.prod
# Edit .env.prod with your values

# Start services
docker compose -f docker-compose.prod.yml up -d

# Run migrations
docker compose -f docker-compose.prod.yml exec api alembic upgrade head

# Access at http://localhost
```

### Kubernetes (Helm)

```bash
# Add Bitnami repo for dependencies
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install SafeMirror
helm install safemirror ./helm/safemirror \
  --set config.secretKey="$(openssl rand -base64 48)" \
  --set postgresql.auth.password="$(openssl rand -base64 24)"
```

---

## Docker Deployment

### Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- 4+ GB RAM available
- 20+ GB disk space

### Step-by-Step

#### 1. Prepare Configuration

```bash
# Create environment file
cp .env.prod.example .env.prod

# Generate secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env.prod

# Generate database password
DB_PASS=$(openssl rand -base64 24)
sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$DB_PASS/" .env.prod
```

#### 2. Build Images

```bash
# Build all images
docker compose -f docker-compose.prod.yml build

# Or pull pre-built (if available)
docker compose -f docker-compose.prod.yml pull
```

#### 3. Start Services

```bash
# Start all services
docker compose -f docker-compose.prod.yml up -d

# Check status
docker compose -f docker-compose.prod.yml ps

# View logs
docker compose -f docker-compose.prod.yml logs -f
```

#### 4. Initialize Database

```bash
# Run migrations
docker compose -f docker-compose.prod.yml exec api alembic upgrade head

# Seed default data (optional)
docker compose -f docker-compose.prod.yml exec api python -m enterprise.db.seed
```

#### 5. Verify Deployment

```bash
# Check API health
curl http://localhost/health

# Expected: {"status": "healthy", "version": "0.2.0"}
```

### SSL/TLS Setup

See [TLS_SETUP.md](TLS_SETUP.md) for detailed instructions.

Quick setup:
```bash
# Generate self-signed cert for testing
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/privkey.pem -out certs/fullchain.pem \
  -subj "/CN=localhost"

# Edit nginx/conf.d/safemirror.conf to enable SSL
# Restart nginx
docker compose -f docker-compose.prod.yml restart nginx
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.28+
- Helm 3.14+
- kubectl configured
- Storage class for PVCs
- Ingress controller (nginx-ingress recommended)

### Step-by-Step

#### 1. Add Helm Repositories

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
```

#### 2. Create Namespace

```bash
kubectl create namespace safemirror
```

#### 3. Create Secrets

```bash
# Generate secrets
kubectl create secret generic safemirror-secrets \
  --namespace safemirror \
  --from-literal=secret-key="$(openssl rand -base64 48)" \
  --from-literal=database-password="$(openssl rand -base64 24)" \
  --from-literal=redis-password="$(openssl rand -base64 16)"
```

#### 4. Create values-prod.yaml

```yaml
# values-prod.yaml
secrets:
  create: false
  existingSecret: safemirror-secrets

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: safemirror.example.com
      paths:
        - path: /api
          pathType: Prefix
          service: api
        - path: /
          pathType: Prefix
          service: frontend
  tls:
    - secretName: safemirror-tls
      hosts:
        - safemirror.example.com

postgresql:
  enabled: true
  auth:
    existingSecret: safemirror-secrets
    secretKeys:
      adminPasswordKey: database-password
      userPasswordKey: database-password
  primary:
    persistence:
      size: 50Gi

redis:
  enabled: true
  auth:
    enabled: true
    existingSecret: safemirror-secrets
    existingSecretPasswordKey: redis-password
```

#### 5. Install Chart

```bash
helm install safemirror ./helm/safemirror \
  --namespace safemirror \
  -f values-prod.yaml
```

#### 6. Verify Deployment

```bash
# Check pods
kubectl get pods -n safemirror

# Check ingress
kubectl get ingress -n safemirror

# View logs
kubectl logs -n safemirror -l app.kubernetes.io/component=api
```

### Scaling

```bash
# Scale API replicas
kubectl scale deployment safemirror-api -n safemirror --replicas=5

# Or via HPA (already configured)
kubectl get hpa -n safemirror
```

---

## Cloud Deployments

### AWS (EKS)

#### Prerequisites
- EKS cluster
- AWS Load Balancer Controller
- EBS CSI driver

#### RDS Setup
```bash
# Create RDS PostgreSQL instance
aws rds create-db-instance \
  --db-instance-identifier safemirror-db \
  --db-instance-class db.r6g.large \
  --engine postgres \
  --engine-version 16 \
  --master-username safemirror \
  --master-user-password "YOUR_PASSWORD" \
  --allocated-storage 100

# Get endpoint
aws rds describe-db-instances \
  --db-instance-identifier safemirror-db \
  --query 'DBInstances[0].Endpoint.Address'
```

#### ElastiCache Setup
```bash
aws elasticache create-replication-group \
  --replication-group-id safemirror-redis \
  --replication-group-description "SafeMirror Redis" \
  --engine redis \
  --cache-node-type cache.r6g.large \
  --num-cache-clusters 2
```

#### Helm Values for AWS
```yaml
# values-aws.yaml
postgresql:
  enabled: false

externalDatabase:
  host: safemirror-db.xxxxx.us-east-1.rds.amazonaws.com
  port: 5432
  database: safemirror
  username: safemirror
  existingSecret: safemirror-secrets
  existingSecretPasswordKey: database-password

redis:
  enabled: false

externalRedis:
  host: safemirror-redis.xxxxx.cache.amazonaws.com
  port: 6379

ingress:
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:...
```

### GCP (GKE)

#### Cloud SQL Setup
```bash
gcloud sql instances create safemirror-db \
  --database-version=POSTGRES_16 \
  --tier=db-custom-4-16384 \
  --region=us-central1

gcloud sql users set-password postgres \
  --instance=safemirror-db \
  --password=YOUR_PASSWORD
```

#### Memorystore Setup
```bash
gcloud redis instances create safemirror-redis \
  --size=2 \
  --region=us-central1 \
  --redis-version=redis_7_0
```

#### Helm Values for GCP
```yaml
# values-gcp.yaml
postgresql:
  enabled: false

externalDatabase:
  host: /cloudsql/PROJECT:REGION:safemirror-db
  port: 5432
  database: safemirror
  username: postgres

# Add Cloud SQL proxy sidecar to deployments
```

### Azure (AKS)

#### Azure Database for PostgreSQL
```bash
az postgres flexible-server create \
  --resource-group safemirror-rg \
  --name safemirror-db \
  --admin-user safemirror \
  --admin-password "YOUR_PASSWORD" \
  --sku-name Standard_D4s_v3 \
  --tier GeneralPurpose \
  --version 16
```

#### Azure Cache for Redis
```bash
az redis create \
  --resource-group safemirror-rg \
  --name safemirror-redis \
  --sku Standard \
  --vm-size c1
```

---

## Environment Variables

### Required Variables

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing key (64+ chars) |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode |
| `APP_NAME` | `SafeMirror Enterprise` | Application name |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | JWT token expiry |
| `CORS_ORIGINS` | `[]` | Allowed CORS origins |
| `SMTP_HOST` | - | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | - | SMTP username |
| `SMTP_PASSWORD` | - | SMTP password |
| `SMTP_FROM_EMAIL` | `noreply@safemirror.local` | From address |

---

## Database Setup

### External PostgreSQL

Requirements:
- PostgreSQL 14+
- Database created for SafeMirror
- User with full privileges on database

```sql
-- Create database and user
CREATE USER safemirror WITH PASSWORD 'your_password';
CREATE DATABASE safemirror OWNER safemirror;
GRANT ALL PRIVILEGES ON DATABASE safemirror TO safemirror;
```

### Running Migrations

```bash
# Docker
docker compose -f docker-compose.prod.yml exec api alembic upgrade head

# Kubernetes
kubectl exec -it deployment/safemirror-api -n safemirror -- alembic upgrade head
```

### Database Backup

```bash
# Docker
docker compose -f docker-compose.prod.yml exec db \
  pg_dump -U safemirror -F c safemirror > backup.dump

# Kubernetes
kubectl exec -it statefulset/safemirror-postgresql -n safemirror -- \
  pg_dump -U safemirror -F c safemirror > backup.dump
```

---

## Post-Deployment

### 1. Create First Admin

```bash
curl -X POST https://safemirror.example.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "name": "Admin",
    "org_name": "My Organization"
  }'
```

### 2. Configure SSO (Optional)

Navigate to Settings > SSO in the UI or use the API.

### 3. Set Up Monitoring

- Enable Prometheus metrics
- Configure alerts for health checks
- Set up log aggregation

### 4. Security Checklist

- [ ] TLS/HTTPS enabled
- [ ] Strong SECRET_KEY set
- [ ] DEBUG=false
- [ ] Firewall configured
- [ ] Backups scheduled
- [ ] Monitoring enabled

---

*For detailed administration, see [ADMIN_GUIDE.md](ADMIN_GUIDE.md)*
