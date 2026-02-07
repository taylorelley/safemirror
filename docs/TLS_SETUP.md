# TLS/SSL Configuration Guide

This guide covers TLS/SSL setup for SafeMirror Enterprise in various deployment scenarios.

## Table of Contents

1. [Quick Start (Self-Signed)](#quick-start-self-signed)
2. [Let's Encrypt with Docker](#lets-encrypt-with-docker)
3. [Let's Encrypt with Kubernetes](#lets-encrypt-with-kubernetes)
4. [Nginx Reverse Proxy](#nginx-reverse-proxy)
5. [Certificate Rotation](#certificate-rotation)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start (Self-Signed)

For development or testing, you can use self-signed certificates.

### Generate Self-Signed Certificate

```bash
# Create certs directory
mkdir -p certs

# Generate private key and certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/privkey.pem \
  -out certs/fullchain.pem \
  -subj "/CN=safemirror.local" \
  -addext "subjectAltName=DNS:safemirror.local,DNS:localhost,IP:127.0.0.1"

# Set permissions
chmod 600 certs/privkey.pem
chmod 644 certs/fullchain.pem
```

### Enable TLS in docker-compose.prod.yml

Uncomment the TLS sections in `nginx/conf.d/safemirror.conf`:

```nginx
# Uncomment these lines:
listen 443 ssl http2;
listen [::]:443 ssl http2;

ssl_certificate /etc/nginx/certs/fullchain.pem;
ssl_certificate_key /etc/nginx/certs/privkey.pem;
```

---

## Let's Encrypt with Docker

### Using Certbot

1. **Install Certbot**:
```bash
apt-get install certbot
```

2. **Obtain Certificate** (standalone mode):
```bash
# Stop nginx temporarily
docker compose -f docker-compose.prod.yml stop nginx

# Get certificate
certbot certonly --standalone \
  -d safemirror.example.com \
  --email admin@example.com \
  --agree-tos \
  --non-interactive

# Copy certificates
cp /etc/letsencrypt/live/safemirror.example.com/fullchain.pem certs/
cp /etc/letsencrypt/live/safemirror.example.com/privkey.pem certs/

# Restart nginx
docker compose -f docker-compose.prod.yml up -d nginx
```

3. **Auto-Renewal**:
```bash
# Add to crontab
0 3 * * * certbot renew --quiet && docker compose -f docker-compose.prod.yml exec nginx nginx -s reload
```

### Using acme.sh

```bash
# Install acme.sh
curl https://get.acme.sh | sh

# Issue certificate
~/.acme.sh/acme.sh --issue -d safemirror.example.com \
  --webroot /var/www/html \
  --key-file certs/privkey.pem \
  --fullchain-file certs/fullchain.pem \
  --reloadcmd "docker compose -f docker-compose.prod.yml exec nginx nginx -s reload"
```

---

## Let's Encrypt with Kubernetes

### Using cert-manager

1. **Install cert-manager**:
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
```

2. **Create ClusterIssuer**:
```yaml
# cluster-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
```

```bash
kubectl apply -f cluster-issuer.yaml
```

3. **Update Helm values**:
```yaml
# values-prod.yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
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
```

4. **Install with TLS**:
```bash
helm install safemirror ./helm/safemirror \
  -f values-prod.yaml \
  --set config.secretKey="$(openssl rand -base64 48)" \
  --set postgresql.auth.password="$(openssl rand -base64 24)"
```

---

## Nginx Reverse Proxy

### Full TLS Configuration

```nginx
# /etc/nginx/conf.d/safemirror-tls.conf
server {
    listen 80;
    listen [::]:80;
    server_name safemirror.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name safemirror.example.com;

    # SSL Certificate
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # SSL Session
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/certs/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Proxy settings...
    location /api/ {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Testing SSL Configuration

```bash
# Test SSL configuration
openssl s_client -connect safemirror.example.com:443 -servername safemirror.example.com

# Check certificate expiry
echo | openssl s_client -connect safemirror.example.com:443 2>/dev/null | openssl x509 -noout -dates

# Test SSL grade (external)
# Visit: https://www.ssllabs.com/ssltest/
```

---

## Certificate Rotation

### Automated Rotation with Certbot

```bash
# /etc/cron.d/certbot-renew
0 3 1,15 * * root certbot renew --quiet --post-hook "docker compose -f /opt/safemirror/docker-compose.prod.yml exec nginx nginx -s reload"
```

### Manual Rotation

```bash
# 1. Backup current certificates
cp certs/fullchain.pem certs/fullchain.pem.bak
cp certs/privkey.pem certs/privkey.pem.bak

# 2. Replace certificates
cp /path/to/new/fullchain.pem certs/
cp /path/to/new/privkey.pem certs/

# 3. Reload nginx
docker compose -f docker-compose.prod.yml exec nginx nginx -s reload

# 4. Verify
curl -I https://safemirror.example.com/health
```

### Kubernetes Secret Rotation

```bash
# Update TLS secret
kubectl create secret tls safemirror-tls \
  --cert=fullchain.pem \
  --key=privkey.pem \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart ingress controller to pick up new cert
kubectl rollout restart deployment ingress-nginx-controller -n ingress-nginx
```

---

## Troubleshooting

### Common Issues

**1. Certificate Not Trusted**
```bash
# Check certificate chain
openssl verify -CAfile chain.pem fullchain.pem
```

**2. Certificate Mismatch**
```bash
# Compare certificate and key
openssl x509 -noout -modulus -in fullchain.pem | md5sum
openssl rsa -noout -modulus -in privkey.pem | md5sum
# Both should match
```

**3. Mixed Content Warnings**
- Ensure all API calls use HTTPS
- Update `NEXT_PUBLIC_API_URL` to use https://

**4. Certificate Expiry**
```bash
# Check expiry
openssl x509 -enddate -noout -in certs/fullchain.pem
```

**5. Permission Issues**
```bash
# Fix permissions
chmod 600 certs/privkey.pem
chmod 644 certs/fullchain.pem
chown root:root certs/*
```

---

## Security Best Practices

1. **Use TLS 1.2+**: Disable TLS 1.0 and 1.1
2. **Strong Ciphers**: Use AEAD ciphers (GCM, CHACHA20-POLY1305)
3. **HSTS**: Enable with long max-age (1+ year)
4. **OCSP Stapling**: Improve performance and privacy
5. **Certificate Transparency**: Use CT-enabled certificates
6. **Monitor Expiry**: Set up alerts for certificate expiration
7. **Automate Renewal**: Use certbot or cert-manager

---

*For production deployments, always use certificates from trusted CAs like Let's Encrypt.*
