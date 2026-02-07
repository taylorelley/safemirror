# SafeMirror Secrets Management

This document describes how to securely manage secrets in SafeMirror Enterprise.

## Overview

SafeMirror supports multiple sources for secrets:

1. **Environment Variables** - Standard approach, works everywhere
2. **Docker Secrets** - For Docker Swarm/Compose deployments
3. **Kubernetes Secrets** - Mounted as env vars
4. **HashiCorp Vault** - Enterprise-grade secrets management

## Required Secrets

| Secret | Description | Required |
|--------|-------------|----------|
| `SECRET_KEY` | JWT signing key | Yes |
| `POSTGRES_PASSWORD` | Database password | Yes (or DATABASE_URL) |
| `DATABASE_URL` | Full database connection string | Alternative to POSTGRES_PASSWORD |
| `REDIS_PASSWORD` | Redis password | No (but recommended) |
| `SMTP_PASSWORD` | Email server password | No |

## Environment Variables

The simplest approach - set secrets as environment variables:

```bash
# .env.prod (do NOT commit this file!)
SECRET_KEY=your-64-character-random-string
POSTGRES_PASSWORD=your-database-password
REDIS_PASSWORD=your-redis-password
```

### Generating a Secure Secret Key

```bash
# Python
python3 -c "import secrets; print(secrets.token_urlsafe(64))"

# OpenSSL
openssl rand -base64 48

# /dev/urandom
head -c 48 /dev/urandom | base64
```

## Docker Secrets

For Docker Swarm or Docker Compose with secrets support:

### Creating Secrets

```bash
# Create secret from string
echo "your-secret-key" | docker secret create safemirror_secret_key -

# Create from file
docker secret create safemirror_db_password ./db_password.txt

# List secrets
docker secret ls
```

### docker-compose.yml Configuration

```yaml
version: "3.8"

services:
  api:
    image: safemirror/api
    secrets:
      - safemirror_secret_key
      - safemirror_db_password
    environment:
      - SECRET_KEY_FILE=/run/secrets/safemirror_secret_key
      - POSTGRES_PASSWORD_FILE=/run/secrets/safemirror_db_password

secrets:
  safemirror_secret_key:
    external: true
  safemirror_db_password:
    external: true
```

### Reading from Files

SafeMirror automatically reads secrets from `/run/secrets/`:

```
/run/secrets/SECRET_KEY -> sets SECRET_KEY env var
/run/secrets/POSTGRES_PASSWORD -> sets POSTGRES_PASSWORD env var
```

## Kubernetes Secrets

### Creating Secrets

```bash
# Create from literal values
kubectl create secret generic safemirror-secrets \
  --namespace safemirror \
  --from-literal=secret-key="$(openssl rand -base64 48)" \
  --from-literal=database-password="$(openssl rand -base64 24)"

# Create from file
kubectl create secret generic safemirror-secrets \
  --namespace safemirror \
  --from-file=secret-key=./secret-key.txt \
  --from-file=database-password=./db-password.txt
```

### Using in Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: safemirror-secrets
                  key: secret-key
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: safemirror-secrets
                  key: database-password
```

### Sealed Secrets (GitOps)

For storing secrets in Git safely:

```bash
# Install kubeseal
brew install kubeseal

# Create SealedSecret
kubectl create secret generic safemirror-secrets \
  --from-literal=secret-key="$(openssl rand -base64 48)" \
  --dry-run=client -o yaml | kubeseal --format yaml > sealed-secrets.yaml

# Apply (can be committed to Git)
kubectl apply -f sealed-secrets.yaml
```

## HashiCorp Vault

For enterprise deployments with Vault:

### Configuration

```bash
# Set Vault environment
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=your-vault-token
```

### Storing Secrets

```bash
# Write secrets to Vault
vault kv put secret/safemirror \
  SECRET_KEY="your-jwt-secret" \
  POSTGRES_PASSWORD="your-db-password" \
  REDIS_PASSWORD="your-redis-password"

# Read secrets
vault kv get secret/safemirror
```

### Application Configuration

```bash
# Set in environment
VAULT_URL=https://vault.example.com
VAULT_TOKEN=s.xxxxxxxxxx
```

SafeMirror will automatically load secrets from `secret/safemirror` path.

### Vault Agent Sidecar (Kubernetes)

For automatic secret injection:

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "safemirror"
        vault.hashicorp.com/agent-inject-secret-config: "secret/safemirror"
```

## Security Best Practices

### Do's

- ✅ Use strong, randomly generated secrets
- ✅ Rotate secrets regularly (at least annually)
- ✅ Use different secrets per environment
- ✅ Store secrets in dedicated secret management tools
- ✅ Limit access to secrets on a need-to-know basis
- ✅ Audit secret access

### Don'ts

- ❌ Never commit secrets to Git
- ❌ Never log secrets (SafeMirror redacts automatically)
- ❌ Never share secrets via email/chat
- ❌ Never use default/example secrets in production
- ❌ Never store secrets in code or config files

### Validation on Startup

SafeMirror validates secrets on startup:

```python
# In your startup script or __init__.py
from enterprise.core.secrets import validate_secrets

# Will raise RuntimeError if secrets are invalid
validate_secrets(production_mode=True)
```

## Secret Rotation

### Manual Rotation

1. Generate new secret value
2. Update in secret store (Vault, K8s, etc.)
3. Restart application pods/containers
4. Verify application health
5. Revoke old secret if applicable

### Automated Rotation

For Vault with database secrets engine:

```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL
vault write database/config/safemirror \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@db:5432/safemirror" \
  allowed_roles="safemirror-role"

# Create role with TTL
vault write database/roles/safemirror-role \
  db_name=safemirror \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}};" \
  default_ttl="1h" \
  max_ttl="24h"
```

## Troubleshooting

### Missing Secrets Error

```
RuntimeError: Secret validation failed:
  - Missing required secret: SECRET_KEY
```

**Solution**: Set the SECRET_KEY environment variable or add to .env.prod file.

### Unsafe Default Warning

```
WARNING: Secret SECRET_KEY has an unsafe default value
```

**Solution**: Replace the default value with a randomly generated secret.

### Vault Connection Failed

```
WARNING: Failed to load from Vault: Connection refused
```

**Solution**: Verify VAULT_URL and VAULT_TOKEN are correct and Vault is accessible.

---

*For more information, see the [Admin Guide](ADMIN_GUIDE.md).*
