# safe-apt

A security-focused APT mirror system that filters packages through vulnerability scanning before making them available to internal clients.

## Overview

**safe-apt** implements a two-layer architecture:

1. **Staging Mirror**: Exact copy of upstream Ubuntu/Debian repositories
2. **Approved Mirror**: Filtered repository containing only scanned and approved packages

Packages are automatically scanned for vulnerabilities using Trivy or Grype, and only packages meeting your security policy are published to clients.

## Features

### Core Security Features

- **Multi-layer security scanning** with comprehensive threat detection
  - **Vulnerability scanning** (CVE detection) using Trivy/Grype
  - **Virus/malware scanning** using ClamAV antivirus
  - **Package integrity verification** (format, structure, checksums)
  - **Maintainer script analysis** (dangerous command detection)
  - **Binary safety checks** (SUID/SGID, suspicious permissions)

- **Policy-based filtering** with configurable security thresholds
- **CVE drift detection** through nightly rescanning
- **Comprehensive audit logging** of all operations
- **GPG-signed repositories** for package authenticity
- **HTTPS-only distribution** for secure delivery
- **Default-deny security model** - failed scans automatically block packages
- **Parallel scanning** for performance optimization

## Architecture

```
Upstream Repositories (Ubuntu, Debian)
           ↓
    Staging Mirror (aptly)
           ↓
     Snapshot + Diff
           ↓
     Scan Pipeline
    (Extract + Scan)
           ↓
  Approved Packages Only
           ↓
  Approved Mirror (aptly)
           ↓
    Internal Clients
```

## Prerequisites

- Ubuntu 20.04+ or Debian 11+
- Root access for installation
- At least 100GB disk space (varies by mirror size)
- Network access to upstream repositories

### Required Software

- **aptly** - Debian repository management tool
- **Trivy** OR **Grype** - Vulnerability scanner (CVE detection)
- **ClamAV** - Antivirus scanner (virus/malware detection)
- **nginx** OR **Apache** - Web server for HTTPS
- **Python 3.8+** - For scanner and publisher components
- **GPG** - For repository signing
- **binutils** - For binary analysis (readelf)

## Quick Start

### 1. Install Dependencies

```bash
# Ubuntu/Debian base packages
sudo apt-get update
sudo apt-get install -y aptly gnupg nginx python3 python3-pip binutils dpkg-dev

# Install ClamAV antivirus (required for virus scanning)
sudo apt-get install -y clamav clamav-daemon clamav-freshclam

# Install Trivy (recommended vulnerability scanner)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# OR install Grype (alternative vulnerability scanner)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

### 2. Clone and Setup

```bash
git clone https://github.com/taylorelley/safe-apt.git
cd safe-apt
sudo ./scripts/setup.sh
```

### 3. Configure

Edit the configuration file:

```bash
sudo nano /opt/apt-mirror-system/config.yaml
```

Key settings to customize:
- Mirror URLs and distributions
- Scanner type (trivy or grype)
- Security policy (CVSS thresholds, blocked severities)
- GPG key ID for signing

### 4. Create Aptly Mirror

```bash
# Create mirror for Ubuntu Jammy
sudo aptly mirror create ubuntu-jammy \
    http://archive.ubuntu.com/ubuntu \
    jammy main restricted universe multiverse

# Initial mirror sync (this may take a while)
sudo aptly mirror update ubuntu-jammy
```

### 5. Generate GPG Key (if needed)

```bash
sudo gpg --full-generate-key
# Follow prompts to create key

# List keys to get Key ID
sudo gpg --list-keys

# Export public key for clients
sudo gpg --armor --export YOUR_KEY_ID > /var/lib/aptly/public/apt-mirror.gpg
```

### 6. Configure Nginx

```bash
# Edit the configuration
sudo nano /etc/nginx/sites-available/apt-mirror

# Update:
# - server_name (your domain)
# - SSL certificate paths

# Enable site
sudo ln -s /etc/nginx/sites-available/apt-mirror /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Run Pipeline

```bash
# First run (manual)
sudo /opt/apt-mirror-system/scripts/run-pipeline.sh

# Check logs
tail -f /opt/apt-mirror-system/logs/pipeline-*.log
```

### 8. Configure Clients

On client machines:

```bash
# Add GPG key
wget -O - https://apt.internal.example.com/apt-mirror.gpg | sudo apt-key add -

# Add repository
echo "deb https://apt.internal.example.com jammy main" | sudo tee /etc/apt/sources.list.d/safe-apt.list

# Update package list
sudo apt-get update
```

## Configuration

See `config/config.yaml.example` for full configuration options.

### Scanner Configuration

```yaml
scanner:
  type: trivy  # or grype
  timeout: 300  # seconds
  workers: 4  # parallel scanning
  update_interval: 24  # hours

  # Enhanced multi-layer security scanning
  enhanced_scanning:
    enabled: true

    # Virus/malware scanning with ClamAV
    virus_scanning:
      enabled: true
      update_on_start: true

    # Package integrity verification
    integrity_checking:
      enabled: true

    # Maintainer script security analysis
    script_analysis:
      enabled: true
      block_on_critical: true
      block_on_high: true

    # Binary safety checks (SUID/SGID, permissions)
    binary_checking:
      enabled: true
      block_suspicious_suid: true
      block_world_writable: true
```

### Security Policy

```yaml
policy:
  # Block packages with CVSS score >= 7.0
  min_cvss_score: 7.0

  # Block packages with these severities
  block_severities:
    - CRITICAL
    - HIGH

  # Override: allow specific CVEs
  allowed_cves:
    - CVE-2023-1234  # Known false positive

  # Override: block specific CVEs
  blocked_cves:
    - CVE-2024-5678  # Critical vulnerability
```

### Mirror Configuration

```yaml
mirrors:
  - name: ubuntu-jammy
    archive_url: http://archive.ubuntu.com/ubuntu
    distribution: jammy
    components:
      - main
      - restricted
      - universe
      - multiverse
    architectures:
      - amd64
```

## Usage

### Manual Pipeline Run

```bash
sudo /opt/apt-mirror-system/scripts/run-pipeline.sh
```

### Scan Individual Package

```bash
python3 -m src.scanner /path/to/package.deb
```

### Build Approved List

```bash
python3 -m src.publisher \
    --package-list packages.txt \
    --output approved.txt
```

### Rescan Existing Packages

```bash
sudo /opt/apt-mirror-system/scripts/rescan-packages.sh approved-20251119
```

## Automation

The setup script configures cron jobs for:

- **Daily pipeline run** (2:00 AM) - Syncs, scans, and publishes
- **Nightly rescan** (3:00 AM) - Checks for CVE drift

View cron configuration:

```bash
cat /etc/cron.d/safe-apt
```

## Monitoring

### Check Logs

```bash
# Pipeline logs
tail -f /opt/apt-mirror-system/logs/pipeline-*.log

# Scanner logs
tail -f /opt/apt-mirror-system/logs/scanner.log

# Publisher logs
tail -f /opt/apt-mirror-system/logs/publisher.log

# Nginx access logs
tail -f /var/log/nginx/apt-mirror-access.log
```

### Verify Publication

```bash
# Check aptly publications
aptly publish list

# Check published repository
curl -I https://apt.internal.example.com/dists/jammy/Release

# From client
apt-cache policy
```

### Scan Statistics

```bash
# Count scans
ls -1 /opt/apt-mirror-system/scans/*.json | wc -l

# View recent scans
ls -lt /opt/apt-mirror-system/scans/*.json | head -n 10

# Check approved packages
wc -l /opt/apt-mirror-system/approvals/approved.txt
```

## Troubleshooting

### Pipeline Fails

1. Check logs in `/opt/apt-mirror-system/logs/`
2. Verify aptly mirrors: `aptly mirror list`
3. Test scanner: `trivy --version` or `grype version`
4. Check disk space: `df -h /var/lib/aptly`

### No Packages Approved

1. Check scan results: `cat /opt/apt-mirror-system/scans/*.json`
2. Review policy settings in `config.yaml`
3. Verify scanner database is updated
4. Check for scanning errors in logs

### Client Can't Connect

1. Verify nginx is running: `systemctl status nginx`
2. Check nginx configuration: `nginx -t`
3. Verify SSL certificates are valid
4. Check firewall rules: `ufw status`

### GPG Signing Issues

1. List GPG keys: `gpg --list-keys`
2. Verify key ID in config matches
3. Check GPG agent is running
4. Try manual signing: `gpg --armor --sign test.txt`

## Project Structure

```
safe-apt/
├── src/                    # Python source code
│   ├── common/            # Shared utilities
│   │   ├── logger.py      # Logging infrastructure
│   │   └── config.py      # Configuration management
│   ├── scanner/           # Package scanner
│   │   └── scan_packages.py
│   └── publisher/         # Approval list builder
│       └── build_approved_list.py
├── scripts/               # Shell scripts
│   ├── sync-mirror.sh     # Mirror synchronization
│   ├── detect-changes.sh  # Change detection
│   ├── publish-approved.sh # Publishing
│   ├── rescan-packages.sh # Rescanning
│   ├── run-pipeline.sh    # Main orchestrator
│   └── setup.sh           # Installation script
├── config/                # Configuration templates
│   ├── config.yaml.example
│   └── nginx-apt-mirror.conf.example
├── tests/                 # Test suite
├── docs/                  # Documentation
├── DESIGN.md             # Architecture specification
├── CLAUDE.md             # AI assistant guide
├── README.md             # This file
└── LICENSE               # MIT License
```

## Security Considerations

### Enhanced Multi-Layer Security

safe-apt provides comprehensive security through five independent scanning layers:

1. **Vulnerability Scanning (CVE)**: Detects known security vulnerabilities using Trivy/Grype
2. **Virus/Malware Scanning**: ClamAV antivirus scans all package contents
3. **Integrity Verification**: Validates package format, structure, and checksums
4. **Script Analysis**: Analyzes maintainer scripts for dangerous commands and patterns
5. **Binary Safety**: Detects suspicious SUID/SGID binaries and file permissions

See `docs/ENHANCED_SECURITY.md` for detailed information about each security layer.

### Default-Deny Policy

If **any** security scan fails, the package is **blocked by default**. This ensures:
- No unscanned packages reach clients
- No packages with detected threats are published
- Failed scans are treated as security risks
- System errs on the side of caution

### HTTPS-Only

The system is configured for HTTPS-only distribution. HTTP requests are automatically redirected to HTTPS.

### GPG Signing

All published repositories must be GPG-signed. Configure `gpg_key_id` in `config.yaml`.

### Audit Logging

All operations are logged with timestamps:
- Mirror synchronization
- Package scans with results
- Publication events
- Configuration changes

### Server Hardening

Additional recommendations:
- Run on dedicated server
- Restrict SSH access
- Enable firewall (ufw/iptables)
- Keep system packages updated
- Rotate logs regularly
- Monitor disk usage

## Extending safe-apt

### Adding Custom Scanners

Implement the scanner interface in `src/scanner/`:

```python
def scan_package(package_path: str) -> ScanResult:
    # Your scanning logic
    pass
```

### Custom Security Policies

Modify `src/publisher/build_approved_list.py` to implement custom approval logic.

### Notifications

Future extension: Add email/Slack notifications for blocked packages or pipeline failures.

### Multiple Distributions

Configure multiple mirrors in `config.yaml` and run separate pipelines.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Follow existing code style
5. Submit a pull request

## Testing

```bash
# Install test dependencies
pip3 install -r requirements.txt

# Run unit tests
pytest tests/unit/

# Run integration tests (requires aptly)
pytest tests/integration/

# Run full test suite
pytest
```

## Performance

### Mirror Size

- Ubuntu Jammy (all components): ~250GB
- Debian Bookworm (main only): ~150GB

### Scanning Speed

- Average: 2-5 packages/second
- Varies by package size and scanner
- Parallel scanning with 4 workers recommended

### Storage Requirements

- Mirror data: Varies by distribution
- Scan results: ~10KB per package
- Logs: ~1MB per day (with rotation)

## Known Limitations

1. **False Positives**: Vulnerability scanners may flag safe packages
2. **Scanner Delays**: Large packages take time to scan
3. **CVE Feed Dependency**: Accuracy depends on CVE database freshness
4. **Disk Space**: Full mirrors require significant storage

See `DESIGN.md` Section 13 for detailed risk analysis.

## Roadmap

Future enhancements planned:

- [ ] Web UI for manual review
- [ ] Metrics and dashboards
- [ ] Multi-distribution support
- [ ] Email/Slack notifications
- [ ] Automatic patching for blocked packages
- [ ] Package whitelist/blacklist management
- [ ] Integration with vulnerability management platforms

## License

MIT License - see LICENSE file for details.

Copyright (c) 2025 taylorelley

## Support

- **Issues**: https://github.com/taylorelley/safe-apt/issues
- **Documentation**: See `docs/` directory
- **Design**: See `DESIGN.md` for architecture details

## Acknowledgments

- **Aptly**: Excellent Debian repository management tool
- **Trivy** / **Grype**: Comprehensive vulnerability scanners
- **Ubuntu** / **Debian**: Outstanding package repositories

## References

- [Aptly Documentation](https://www.aptly.info/doc/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Grype Documentation](https://github.com/anchore/grype)
- [Debian Repository Format](https://wiki.debian.org/DebianRepository/Format)
- [CVSS Scoring](https://www.first.org/cvss/)
