# safe-apt Deployment Guide

This guide provides detailed instructions for deploying safe-apt in production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Initial Setup](#initial-setup)
6. [Security Hardening](#security-hardening)
7. [Monitoring](#monitoring)
8. [Maintenance](#maintenance)
9. [Troubleshooting](#troubleshooting)
10. [Disaster Recovery](#disaster-recovery)

## Prerequisites

### Hardware Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8GB
- Disk: 200GB SSD
- Network: 100 Mbps

**Recommended:**
- CPU: 8+ cores (for parallel scanning)
- RAM: 16GB+
- Disk: 500GB+ SSD (varies by mirror size)
- Network: 1 Gbps

### Software Requirements

- **Operating System**: Ubuntu 20.04+ or Debian 11+
- **Root Access**: Required for installation
- **Network Access**: Outbound to upstream repositories

## System Requirements

### Disk Space Planning

Calculate required disk space:

```text
Total = Mirror Size + Snapshots + Scans + Logs
```

**Example for Ubuntu Jammy:**
- Mirror (all components): ~250GB
- Snapshots (7 days): ~1.75TB
- Scans (30 days): ~500MB
- Logs: ~100MB

**Recommendation**: Start with 500GB, monitor, and expand as needed.

### Network Requirements

**Outbound:**
- Upstream APT repositories (HTTP/HTTPS)
- CVE database updates (HTTPS)

**Inbound:**
- Client connections (HTTPS only)
- Management access (SSH)

## Installation

### 1. Update System

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y curl wget gnupg ca-certificates
```

### 2. Install Aptly

```bash
# Add Aptly repository
wget -qO - https://www.aptly.info/pubkey.txt | sudo apt-key add -
echo "deb http://repo.aptly.info/ squeeze main" | sudo tee /etc/apt/sources.list.d/aptly.list

# Install
sudo apt-get update
sudo apt-get install -y aptly
```

### 3. Install Trivy

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# Verify installation
trivy --version
```

### 4. Install Nginx

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

### 5. Install Python Dependencies

```bash
sudo apt-get install -y python3 python3-pip
```

### 6. Clone and Setup safe-apt

```bash
cd /opt
sudo git clone https://github.com/taylorelley/safe-apt.git
cd safe-apt
sudo ./scripts/setup.sh
```

## Configuration

### 1. Edit Configuration File

```bash
sudo nano /opt/apt-mirror-system/config.yaml
```

**Key Settings:**

```yaml
# Mirror configuration
mirrors:
  - name: ubuntu-jammy
    archive_url: http://archive.ubuntu.com/ubuntu
    distribution: jammy
    components: [main, restricted, universe, multiverse]
    architectures: [amd64]

# Security policy
policy:
  min_cvss_score: 7.0
  block_severities: [CRITICAL, HIGH]

# Scanner settings
scanner:
  type: trivy
  timeout: 300
  workers: 4

# Publishing
publishing:
  distribution: jammy
  gpg_key_id: YOUR_KEY_ID  # Add after GPG setup
```

### 2. Configure Aptly

Edit `~/.aptly.conf`:

```json
{
  "rootDir": "/var/lib/aptly",
  "downloadConcurrency": 8,
  "architectures": ["amd64"],
  "dependencyFollowSuggests": false,
  "dependencyFollowRecommends": false,
  "gpgDisableSign": false,
  "gpgDisableVerify": false,
  "downloadSourcePackages": false,
  "skipContentsPublishing": false
}
```

## Initial Setup

### 1. Generate GPG Key

```bash
# Generate key
sudo gpg --full-generate-key

# Select:
# - RSA and RSA
# - 4096 bits
# - Does not expire (or set expiration)
# - Real name: APT Mirror
# - Email: apt@your-domain.com

# List keys to get Key ID
sudo gpg --list-keys
# Look for line like: pub   rsa4096 2025-11-19 [SC]
#                           ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234

# Export public key
sudo gpg --armor --export YOUR_KEY_ID > /var/lib/aptly/public/apt-mirror.gpg
```

### 2. Create Aptly Mirror

```bash
# Create mirror
sudo aptly mirror create ubuntu-jammy \
    http://archive.ubuntu.com/ubuntu \
    jammy main restricted universe multiverse

# Initial sync (this takes time!)
sudo aptly mirror update ubuntu-jammy
```

### 3. Configure SSL Certificate

#### Option A: Let's Encrypt (Recommended)

```bash
# Obtain certificate
sudo certbot --nginx -d apt.yourdomain.com

# Auto-renewal is configured by default
```

#### Option B: Self-Signed (Testing Only)

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/apt-mirror.key \
    -out /etc/ssl/certs/apt-mirror.crt
```

### 4. Configure Nginx

```bash
# Edit configuration
sudo nano /etc/nginx/sites-available/apt-mirror

# Update server_name
server_name apt.yourdomain.com;

# If using self-signed cert, update paths
ssl_certificate /etc/ssl/certs/apt-mirror.crt;
ssl_certificate_key /etc/ssl/private/apt-mirror.key;

# Enable site
sudo ln -s /etc/nginx/sites-available/apt-mirror /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. First Pipeline Run

```bash
# Run pipeline manually
sudo /opt/apt-mirror-system/scripts/run-pipeline.sh

# Monitor progress
tail -f /opt/apt-mirror-system/logs/pipeline-*.log
```

## Security Hardening

### 1. Firewall Configuration

```bash
# Enable UFW
sudo ufw enable

# Allow SSH (change port if needed)
sudo ufw allow 22/tcp

# Allow HTTPS only (no HTTP in production)
sudo ufw allow 443/tcp

# Verify rules
sudo ufw status
```

### 2. SSH Hardening

```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Recommended settings:
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no

# Restart SSH
sudo systemctl restart sshd
```

### 3. File Permissions

```bash
# Restrict config file
sudo chmod 600 /opt/apt-mirror-system/config.yaml

# Restrict GPG keys
sudo chmod 700 ~/.gnupg

# Restrict scripts
sudo chown root:root /opt/apt-mirror-system/scripts/*
sudo chmod 750 /opt/apt-mirror-system/scripts/*
```

### 4. AppArmor/SELinux

Consider enabling AppArmor or SELinux profiles for:
- nginx
- aptly
- Python processes

### 5. Audit Logging

Enable system audit logging:

```bash
sudo apt-get install -y auditd
sudo systemctl enable auditd
sudo systemctl start auditd
```

## Monitoring

### 1. Log Monitoring

**Centralized Logging:**

```bash
# Install rsyslog or journald forwarding
# Configure to send to central log server

# Example: Forward to remote syslog
echo "*.* @logserver.yourdomain.com:514" | sudo tee -a /etc/rsyslog.conf
sudo systemctl restart rsyslog
```

**Log Rotation:**

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/safe-apt

# Add:
/opt/apt-mirror-system/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
```

### 2. Disk Space Monitoring

```bash
# Create monitoring script
sudo nano /opt/apt-mirror-system/scripts/check-disk.sh
```

```bash
#!/bin/bash
THRESHOLD=90
USAGE=$(df -h /var/lib/aptly | tail -1 | awk '{print $5}' | sed 's/%//')

if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "ALERT: Disk usage at ${USAGE}%"
    # Send notification
fi
```

### 3. Service Health Checks

```bash
# Add to cron
echo "*/5 * * * * root /opt/apt-mirror-system/scripts/check-health.sh" | sudo tee -a /etc/cron.d/safe-apt-monitoring
```

### 4. Metrics Collection

Consider integrating with:
- **Prometheus**: Metrics collection
- **Grafana**: Visualization
- **Nagios/Zabbix**: Alerting

## Maintenance

### Daily Tasks

Automated by cron:
- Pipeline sync and scan (2:00 AM)
- Nightly rescan (3:00 AM)

### Weekly Tasks

```bash
# Review logs
sudo grep ERROR /opt/apt-mirror-system/logs/*.log

# Check disk usage
df -h /var/lib/aptly

# Review blocked packages
sudo tail -100 /opt/apt-mirror-system/logs/scanner.log | grep BLOCKED
```

### Monthly Tasks

```bash
# Update scanner database manually
sudo trivy image --download-db-only

# Clean old snapshots
sudo aptly snapshot list | grep staging- | sort | head -n -7 | xargs -I {} sudo aptly snapshot drop {}

# Clean old scans
find /opt/apt-mirror-system/scans -name "*.json" -mtime +30 -delete

# Review security policy effectiveness
# Count approved vs blocked packages
jq -r '.status' /opt/apt-mirror-system/scans/*.json 2>/dev/null | sort | uniq -c

# Or review recent scan statistics
grep -E "BLOCKED|APPROVED" /opt/apt-mirror-system/logs/scanner.log | tail -100
```

### Updates

```bash
# Update safe-apt
cd /opt/safe-apt
sudo git pull
sudo pip3 install -r requirements.txt

# Update Trivy
sudo trivy --download-db-only

# Update system packages
sudo apt-get update
sudo apt-get upgrade -y
```

## Troubleshooting

### Pipeline Fails

**Check logs:**
```bash
tail -100 /opt/apt-mirror-system/logs/pipeline-*.log
```

**Common issues:**
1. **Upstream unavailable**: Wait and retry, or use alternate mirror
2. **Disk full**: Clean old snapshots or expand disk
3. **Scanner timeout**: Increase timeout in config.yaml
4. **GPG signing failed**: Check GPG key and passphrase

### No Packages Approved

**Diagnose:**
```bash
# Check scan results
ls -l /opt/apt-mirror-system/scans/

# Review policy
cat /opt/apt-mirror-system/config.yaml | grep -A 5 policy

# Check specific scan
cat /opt/apt-mirror-system/scans/package-name_*.json | jq .
```

**Solutions:**
1. Adjust CVSS threshold
2. Remove HIGH from blocked_severities
3. Add allowed_cves for false positives

### Clients Can't Connect

**Check nginx:**
```bash
sudo systemctl status nginx
sudo nginx -t
tail -50 /var/log/nginx/error.log
```

**Check SSL:**
```bash
sudo certbot certificates
curl -I https://apt.yourdomain.com/health
```

**Check publication:**
```bash
aptly publish list
ls -l /var/lib/aptly/public/dists/
```

## Disaster Recovery

### Backup Strategy

**What to backup:**
1. Configuration: `/opt/apt-mirror-system/config.yaml`
2. GPG keys: `~/.gnupg/`
3. Aptly database: `/var/lib/aptly/db/`
4. Approved lists: `/opt/apt-mirror-system/approvals/`
5. Recent scans: `/opt/apt-mirror-system/scans/`

**Backup script:**

```bash
#!/bin/bash
BACKUP_DIR="/backup/safe-apt/$(date +%Y%m%d)"
mkdir -p "${BACKUP_DIR}"

# Config
cp /opt/apt-mirror-system/config.yaml "${BACKUP_DIR}/"

# GPG keys
tar czf "${BACKUP_DIR}/gnupg.tar.gz" ~/.gnupg/

# Aptly database
tar czf "${BACKUP_DIR}/aptly-db.tar.gz" /var/lib/aptly/db/

# Approvals and recent scans
tar czf "${BACKUP_DIR}/data.tar.gz" /opt/apt-mirror-system/approvals/ /opt/apt-mirror-system/scans/

# Keep 30 days
find /backup/safe-apt/ -type d -mtime +30 -exec rm -rf {} +
```

### Recovery Procedure

1. **Install fresh system** following installation steps
2. **Restore configuration**: Copy config.yaml
3. **Restore GPG keys**: Extract gnupg.tar.gz to ~/.gnupg
4. **Restore Aptly database**: Extract aptly-db.tar.gz
5. **Restore data**: Extract data.tar.gz
6. **Rebuild mirror**: Run sync if needed
7. **Test**: Verify publication works

### High Availability

For HA deployment:

1. **Primary/Secondary Setup**:
   - Two identical servers
   - Shared storage (NFS/GlusterFS) for /var/lib/aptly
   - Keepalived for VIP failover

2. **Load Balancing**:
   - Multiple read-only mirrors
   - HAProxy or nginx load balancer
   - Single primary for syncing/scanning

## Performance Tuning

### Aptly Optimization

```json
{
  "downloadConcurrency": 16,
  "skipContentsPublishing": true
}
```

### Scanner Optimization

```yaml
scanner:
  workers: 8  # Increase for more CPU cores
  timeout: 600  # Increase for large packages
```

### Nginx Optimization

```nginx
# Enable caching
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=apt_cache:10m max_size=10g;
```

## Compliance and Auditing

### Audit Log Review

```bash
# Review all blocked packages
grep BLOCKED /opt/apt-mirror-system/logs/*.log

# Check policy changes
git log --follow /opt/apt-mirror-system/config.yaml

# Scan result summary
jq -r '.status' /opt/apt-mirror-system/scans/*.json | sort | uniq -c
```

### Compliance Reporting

Generate monthly reports:

```bash
# Packages scanned
ls -1 /opt/apt-mirror-system/scans/*.json | wc -l

# Blocked vs approved
jq -r '.status' /opt/apt-mirror-system/scans/*.json | sort | uniq -c

# Critical CVEs found
jq -r '.vulnerabilities[] | select(.severity=="CRITICAL") | .cve_id' /opt/apt-mirror-system/scans/*.json | sort | uniq
```

## Additional Resources

- [Aptly Documentation](https://www.aptly.info/doc/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Nginx Hardening Guide](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/)
- [Ubuntu Security Guide](https://ubuntu.com/security/certifications/docs/2204)

## Support

For issues and questions:
- [GitHub Issues](https://github.com/taylorelley/safe-apt/issues)
- Documentation: See README.md and DESIGN.md
