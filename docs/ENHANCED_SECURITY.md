# Enhanced Security Scanning

This document describes the comprehensive multi-layer security scanning features in safe-apt.

## Overview

safe-apt now includes **enhanced security scanning** that goes beyond traditional vulnerability (CVE) detection to provide comprehensive package security analysis. The enhanced scanner combines five independent security checks:

1. **Vulnerability Scanning** - CVE detection using Trivy/Grype
2. **Virus/Malware Scanning** - ClamAV antivirus integration
3. **Package Integrity Verification** - Format and structure validation
4. **Maintainer Script Analysis** - Security analysis of installation scripts
5. **Binary Safety Checks** - SUID/SGID and suspicious file detection

## Architecture

```
Package (.deb)
    ↓
┌─────────────────────────────────────────┐
│   Enhanced Security Scanner             │
├─────────────────────────────────────────┤
│ 1. Vulnerability Scan (Trivy/Grype)    │ → CVE detection
│ 2. Virus Scan (ClamAV)                 │ → Malware detection
│ 3. Integrity Check                     │ → Format validation
│ 4. Script Analysis                     │ → Suspicious patterns
│ 5. Binary Safety Check                 │ → SUID/SGID detection
└─────────────────────────────────────────┘
    ↓
Combined Result → APPROVED / BLOCKED / ERROR
```

## Security Layers

### 1. Vulnerability Scanning (CVE Detection)

**Purpose**: Detect known security vulnerabilities in package dependencies.

**Scanner**: Trivy or Grype

**Checks**:
- Scans package contents for known CVEs
- Evaluates CVSS scores
- Matches vulnerabilities against CVE databases
- Identifies vulnerable library versions

**Configuration**:
```yaml
scanner:
  type: trivy  # or grype
  min_cvss_score: 7.0
  block_severities:
    - CRITICAL
    - HIGH
```

**Blocks packages when**:
- CVSS score >= configured threshold
- Contains CRITICAL or HIGH severity CVEs
- Meets configured blocking criteria

---

### 2. Virus/Malware Scanning

**Purpose**: Detect viruses, trojans, malware, and other malicious code.

**Scanner**: ClamAV

**Checks**:
- Scans package file and extracted contents
- Checks against ClamAV virus signature database
- Detects known malware patterns
- Identifies suspicious file characteristics

**Configuration**:
```yaml
scanner:
  enhanced_scanning:
    virus_scanning:
      enabled: true
      update_on_start: true
      timeout: 300
```

**Blocks packages when**:
- Any virus signature is detected
- Malware patterns are found
- Scan error occurs (default-deny)

**Database Updates**:
- Automatic daily updates via `freshclam`
- Manual update: `freshclam`
- Database location: `/var/lib/clamav/`

---

### 3. Package Integrity Verification

**Purpose**: Verify package structure, format, and internal consistency.

**Checks**:
- **Package Format**: Valid .deb (ar archive) structure
- **Control File**: Required metadata fields present and valid
- **Internal Consistency**: No path traversal or malformed entries
- **File Integrity**: Non-empty, readable, valid archive header
- **Checksum Verification**: SHA256 hash matching (if provided)

**Configuration**:
```yaml
scanner:
  enhanced_scanning:
    integrity_checking:
      enabled: true
      check_format: true
      check_control: true
      check_consistency: true
```

**Blocks packages when**:
- Invalid .deb format detected
- Control file missing or malformed
- Suspicious path patterns found (e.g., `/../`, `//`)
- Package file is corrupted or empty
- Checksum mismatch (if reference provided)

**Suspicious Patterns Detected**:
- Path traversal attempts (`/../`)
- Double slashes in paths (`//`)
- Absolute paths escaping package root
- Missing required package metadata

---

### 4. Maintainer Script Security Analysis

**Purpose**: Analyze installation scripts for dangerous commands and suspicious patterns.

**Scripts Analyzed**:
- `preinst` - Pre-installation script
- `postinst` - Post-installation script
- `prerm` - Pre-removal script
- `postrm` - Post-removal script
- `config` - Package configuration script

**Dangerous Commands Detected**:

**Critical Severity**:
- `rm -rf /` - Recursive root deletion
- `dd if=/dev/zero of=/dev/` - Disk overwrite
- `mkfs` - Filesystem creation
- `:(){ :|:& };:` - Fork bomb
- `/etc/shadow` access - Password file manipulation
- `useradd -o -u 0` - UID 0 user creation

**High Severity**:
- `curl | sh` / `wget | bash` - Pipe to shell from network
- `eval $(...)` - Dynamic code evaluation
- `/etc/passwd` manipulation - User database changes
- `chmod u+s` - SUID bit modification
- `setenforce 0` - SELinux disable
- Kernel memory access (`/proc/kcore`, `/dev/mem`)

**Medium Severity**:
- `chmod 777` - Overly permissive permissions
- `/dev/tcp/` or `/dev/udp/` - Network device access
- `nc -l` / `ncat -l` - Netcat listeners
- `iptables -F` - Firewall flush
- `modprobe` - Kernel module loading

**Configuration**:
```yaml
scanner:
  enhanced_scanning:
    script_analysis:
      enabled: true
      block_on_critical: true
      block_on_high: true
      analyze_scripts:
        - preinst
        - postinst
        - prerm
        - postrm
        - config
```

**Blocks packages when**:
- Critical severity issues found
- High severity issues found (configurable)
- Dangerous command patterns detected
- Suspicious environment variable manipulation
- Insecure temporary file usage

**Additional Checks**:
- Environment variable manipulation (PATH, LD_PRELOAD, LD_LIBRARY_PATH)
- Insecure temp file usage
- Network connection attempts
- Command injection patterns

---

### 5. Binary Safety Checks

**Purpose**: Detect suspicious file permissions and dangerous binaries.

**Checks**:

**SUID Binary Detection**:
- Detects binaries with SUID (Set User ID) bit
- Flags suspicious SUID binaries (shells, interpreters, network tools)
- Verifies legitimate SUID binaries (sudo, passwd, ping, etc.)
- Detects SUID binaries in unusual locations

**SGID Binary Detection**:
- Detects binaries with SGID (Set Group ID) bit
- Flags suspicious SGID on executables
- Identifies group privilege escalation risks

**File Permission Issues**:
- World-writable files (666, 777)
- Overly permissive directories
- Hidden files in unusual locations
- Device files in packages (should never exist)

**Sensitive Location Checks**:
- `/etc/cron*` - Scheduled task manipulation
- `/etc/init.d`, `/etc/systemd/system` - Service control
- `/.ssh/` - SSH configuration
- `/root/` - Root user files
- `/etc/sudoers` - Sudo configuration
- `/etc/passwd`, `/etc/shadow` - User databases

**Suspicious SUID Binaries**:
```
bash, sh, dash, zsh        # Shells
python, perl, ruby, php    # Interpreters
nc, netcat, socat          # Network tools
wget, curl, ftp            # Download tools
vim, vi, nano, emacs       # Editors
find, locate, xargs        # File search
tar, gzip, zip             # Archivers
```

**Configuration**:
```yaml
scanner:
  enhanced_scanning:
    binary_checking:
      enabled: true
      block_suspicious_suid: true
      block_world_writable: true
      block_device_files: true
      warn_on_suid: true
```

**Blocks packages when**:
- Suspicious SUID binaries detected (shells, interpreters)
- Device files found in package (block/char devices)
- World-writable executables found
- SUID/SGID in unusual locations

**Warnings generated for**:
- Legitimate but uncommon SUID binaries
- SGID binaries
- Files in sensitive system locations

---

## Combined Decision Logic

The enhanced scanner uses a **default-deny** approach. A package is only APPROVED if it passes **ALL** security checks.

### Blocking Criteria

A package is **BLOCKED** if:
1. Any virus/malware is detected
2. Package integrity check fails
3. Critical or high-severity script issues found
4. Suspicious SUID binaries detected
5. World-writable files present
6. CVE vulnerabilities exceed threshold
7. 3+ high-severity issues across all checks

### Error Handling

A package scan returns **ERROR** status if:
- Scanner crashes or times out
- Package file not found or unreadable
- Scan infrastructure failure

**Default-Deny Enforcement**:

All scanner errors are treated as BLOCKED to ensure unscanned packages never reach production. This includes:

- **Script extraction failures**: If dpkg-deb fails to extract maintainer scripts, the package is BLOCKED (not treated as "no scripts")
- **File listing failures**: If dpkg-deb fails to list package contents, the package is BLOCKED (not treated as "no files")
- **Empty packages**: Packages with no files are treated as HIGH severity issues and BLOCKED
- **Virus scanner unavailable**: If ClamAV is not responding, scans fail and packages are BLOCKED
- **Integrity check failures**: Any package format validation failure BLOCKS the package
- **Timeout conditions**: All timeouts (extraction, scanning, verification) result in BLOCKED status

This strict error handling prevents "fail-open" scenarios where scanner errors could inadvertently approve malicious packages.

---

## Configuration

### Enable Enhanced Scanning

Edit `/opt/apt-mirror-system/config.yaml`:

```yaml
scanner:
  # Basic vulnerability scanning
  type: trivy
  timeout: 300

  # Enhanced security scanning
  enhanced_scanning:
    enabled: true

    virus_scanning:
      enabled: true
      update_on_start: true
      timeout: 300

    integrity_checking:
      enabled: true
      check_format: true
      check_control: true
      check_consistency: true

    script_analysis:
      enabled: true
      block_on_critical: true
      block_on_high: true

    binary_checking:
      enabled: true
      block_suspicious_suid: true
      block_world_writable: true
      block_device_files: true
```

### Disable Specific Checks

To disable individual security layers:

```yaml
scanner:
  enhanced_scanning:
    enabled: true
    virus_scanning:
      enabled: false  # Disable virus scanning
    binary_checking:
      enabled: false  # Disable binary checks
```

---

## Usage

### Manual Package Scan

Scan a single package with enhanced security:

```bash
python3 -m src.scanner.enhanced_scanner /path/to/package.deb
```

### View Scan Results

Enhanced scan results are saved to `/opt/apt-mirror-system/scans/`:

```bash
# View recent enhanced scans
ls -lt /opt/apt-mirror-system/scans/*_enhanced_*.json | head -5

# View detailed scan result
cat /opt/apt-mirror-system/scans/curl_7.81.0_enhanced_20251120_143022.json
```

### Scan Result Format

```json
{
  "package_name": "example-package",
  "package_version": "1.0.0",
  "overall_status": "blocked",
  "scan_date": "2025-11-20T14:30:22",

  "vulnerability_scan_status": "blocked",
  "cvss_max": 9.8,
  "cve_count": 3,

  "virus_scan_status": "clean",
  "viruses_found": [],

  "integrity_status": "valid",
  "integrity_issues": [],

  "script_analysis_status": "unsafe",
  "script_issues": [
    {
      "severity": "critical",
      "type": "dangerous_command",
      "description": "Dangerous command found: rm -rf /",
      "line_number": 42,
      "code_snippet": "rm -rf / || true"
    }
  ],

  "binary_safety_status": "unsafe",
  "suid_binaries": ["/usr/bin/bash"],
  "world_writable_files": [],

  "critical_issues": 1,
  "high_issues": 2,
  "medium_issues": 5,
  "low_issues": 3,
  "warnings": ["SUID binary found: /usr/bin/sudo"]
}
```

---

## Monitoring and Troubleshooting

### Check Scanner Status

```bash
# Verify ClamAV is running
systemctl status clamav-daemon
systemctl status clamav-freshclam

# Check virus definition age
sigtool --info /var/lib/clamav/main.cvd

# Verify Trivy is available
trivy --version

# Test ClamAV scanning
clamscan --version
```

### Update Security Databases

```bash
# Update virus definitions
sudo freshclam

# Update Trivy vulnerability database
trivy image --download-db-only

# Update Grype vulnerability database
grype db update
```

### View Blocked Packages

```bash
# Find all blocked packages
grep -l '"overall_status": "blocked"' /opt/apt-mirror-system/scans/*_enhanced_*.json

# Count blocking reasons
grep -h '"virus_scan_status"' /opt/apt-mirror-system/scans/*_enhanced_*.json | sort | uniq -c
```

### Logs

```bash
# Enhanced scanner logs
tail -f /opt/apt-mirror-system/logs/scanner.log | grep enhanced_scanner

# Virus scanner logs
tail -f /opt/apt-mirror-system/logs/scanner.log | grep virus_scanner

# Script analyzer logs
tail -f /opt/apt-mirror-system/logs/scanner.log | grep script_analyzer
```

---

## Performance Impact

### Scan Times

Average scan times per package (on modern hardware):

- Vulnerability scan: 2-5 seconds
- Virus scan: 1-3 seconds
- Integrity check: <1 second
- Script analysis: <1 second
- Binary check: <1 second

**Total: 4-10 seconds per package**

### Resource Usage

- CPU: 1-2 cores during scanning
- Memory: 500MB-1GB per scanner worker
- Disk I/O: Moderate (extracting .deb files)
- Network: None (during scanning)

### Optimization

Enable parallel scanning for large repositories:

```yaml
scanner:
  workers: 4  # Scan 4 packages simultaneously
```

---

## Security Best Practices

### 1. Keep Databases Updated

```bash
# Add to cron
0 1 * * * freshclam --quiet
0 1 * * * trivy image --download-db-only
```

### 2. Review Blocked Packages

Regularly review blocked packages to identify:
- False positives requiring policy adjustment
- Upstream security issues to report
- Trends in package security

### 3. Monitor Scanner Health

```bash
# Check ClamAV service
systemctl is-active clamav-daemon

# Verify database freshness
test $(find /var/lib/clamav/main.cvd -mtime -2) && echo "Fresh" || echo "Stale"
```

### 4. Tune Policies

Adjust blocking thresholds based on your risk tolerance:

```yaml
# Stricter policy
policy:
  min_cvss_score: 4.0  # Block medium+ vulnerabilities
  block_severities: [CRITICAL, HIGH, MEDIUM]

# More permissive (not recommended)
policy:
  min_cvss_score: 9.0  # Only block critical
  block_severities: [CRITICAL]
```

---

## Comparison with Basic Scanning

| Feature | Basic Scanner | Enhanced Scanner |
|---------|--------------|------------------|
| CVE Detection | ✅ Trivy/Grype | ✅ Trivy/Grype |
| Virus Scanning | ❌ None | ✅ ClamAV |
| Integrity Checks | ❌ None | ✅ Format, control, consistency |
| Script Analysis | ❌ None | ✅ Dangerous pattern detection |
| Binary Safety | ❌ None | ✅ SUID/SGID, permissions |
| Scan Time | 2-5 sec | 4-10 sec |
| False Positive Rate | Low | Low-Medium |
| Security Coverage | Vulnerabilities only | Comprehensive |

---

## Known Limitations

1. **False Positives**: Script analysis may flag legitimate administrative operations
2. **Performance**: Enhanced scanning adds 2-5 seconds per package
3. **ClamAV Coverage**: Antivirus detection limited to known signatures
4. **SUID Detection**: Some legitimate packages use SUID for valid reasons

### Mitigation Strategies

- Review scan results regularly
- Whitelist known-safe patterns
- Adjust severity thresholds
- Enable/disable specific checks as needed

---

## References

- [ClamAV Documentation](https://docs.clamav.net/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Debian Package Format](https://www.debian.org/doc/debian-policy/ch-controlfields.html)
- [SUID/SGID Security](https://www.debian.org/doc/debian-policy/ch-files.html#s-permissions-owners)

---

## Support

For issues with enhanced scanning:
- Check logs in `/opt/apt-mirror-system/logs/`
- Review scan results in `/opt/apt-mirror-system/scans/`
- Verify scanner services are running
- Ensure databases are up to date

Report bugs: https://github.com/taylorelley/safe-apt/issues
