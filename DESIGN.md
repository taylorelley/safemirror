# SafeMirror - Multi-Format Security-Scanned Package Mirror

## 1. Purpose
This system creates internal package mirrors that only publish packages passing security checks.
It provides controlled, repeatable, and audited package updates for multiple package formats.
It uses existing tools where possible and supports:
- Debian/Ubuntu (DEB)
- Red Hat/Rocky/Fedora (RPM)
- Alpine Linux (APK)
- Python packages (PyPI wheels and source distributions)
- Node.js packages (NPM)

## 2. Summary
The mirror has two layers per format:

1. **Staging mirror**: exact copy of upstream repositories.
2. **Approved mirror**: filtered repository containing only scanned and approved packages.

A pipeline keeps the mirrors up to date:

1. Sync upstream into staging.
2. Identify new or changed packages.
3. Extract and scan the packages (5-layer security).
4. Approve or block each package based on policy.
5. Publish only approved packages.
6. Rescan existing packages as CVE data changes.

## 3. Scope
**In Scope**
- Multi-format package mirroring (DEB, RPM, APK, PyPI, NPM)
- 5-layer security scanning:
  - Vulnerability scanning (Trivy, Grype, pip-audit, npm-audit)
  - Virus scanning (ClamAV)
  - Integrity checking
  - Script analysis
  - Binary security checks
- Policy enforcement
- Signed repo publishing
- Automatic updates
- Audit logging

**Out of Scope**
- Custom package builds
- Creating patches for blocked packages
- Full dashboard UI (future extension)

## 4. Architecture
```
                Upstream Repositories
        (Ubuntu, RHEL, Alpine, PyPI, NPM)
                       |
                       v
              +----------------+
              | Format Handler |  <-- Detects format, extracts, parses metadata
              +----------------+
                       |
                       v
              Staging Mirror
        (aptly, createrepo, bandersnatch, verdaccio)
                       |
                 Snapshot + Diff
                       |
                       v
               5-Layer Scan Pipeline
        +----------------------------------+
        | 1. Vulnerability scan (format-specific)
        | 2. Virus scan (ClamAV)
        | 3. Integrity check
        | 4. Script analysis
        | 5. Binary security check
        +----------------------------------+
                       |
              Approved Packages Only
                       v
              Approved Mirror
                       |
                       v
                Internal Clients
```

## 5. Components

### 5.1 Format Handlers (`src/formats/`)
Abstraction layer for package formats:
- `base.py` - PackageFormat protocol, PackageMetadata, ExtractedContent
- `registry.py` - Format detection and handler registry
- `deb.py` - Debian package handler
- `rpm.py` - RPM package handler
- `apk.py` - Alpine APK handler
- `wheel.py` - Python wheel handler
- `sdist.py` - Python source distribution handler
- `npm.py` - NPM package handler

### 5.2 Repository Managers (`src/repos/`)
Abstraction for different repository tools:
- `base.py` - RepositoryManager protocol
- `registry.py` - Manager registration
- `aptly.py` - Debian (aptly)
- `createrepo.py` - RPM (createrepo_c)
- `bandersnatch.py` - PyPI mirroring
- `verdaccio.py` - NPM registry
- `apk_mirror.py` - Alpine tools

### 5.3 Security Scanners (`src/scanner/`)
5-layer security scanning:
- `scan_packages.py` - Main scanner with format support
- `enhanced_scanner.py` - Orchestrates all security layers
- `integrity_checker.py` - Format-specific integrity validation
- `script_analyzer.py` - Multi-format script analysis
- `binary_checker.py` - Binary security checks

### 5.4 Vulnerability Scanners
Format-specific scanners:
| Format | Primary Scanner | Fallback |
|--------|----------------|----------|
| DEB | Trivy | Grype |
| RPM | Trivy | Grype |
| APK | Trivy | Grype |
| PyPI | pip-audit | Trivy |
| NPM | npm-audit | Trivy |

### 5.5 Publisher (`src/publisher/`)
Builds filtered snapshots and publishes approved packages.

### 5.6 Web Server
HTTPS server (nginx/Apache) serving published repositories.

## 6. Workflow

### 6.1 Sync (per format)
```bash
# DEB
aptly mirror update <mirror>
aptly snapshot create staging-YYYYMMDD

# RPM
dnf reposync --repoid=<repo>
createrepo_c <path>

# PyPI
bandersnatch mirror

# NPM
verdaccio sync
```

### 6.2 Detect Changes
Compare snapshots to identify new/changed packages.

### 6.3 Scan Packages
Run 5-layer security scan on each changed package:
```python
# Auto-detect format and run appropriate checks
handler = detect_format(package_path)
scanner = EnhancedScanner(format_handler=handler)
result = scanner.scan(package_path)
```

### 6.4 Build Approved List
Generate list of approved package keys based on scan results.

### 6.5 Publish Approved Mirror
Filter and publish only approved packages.

### 6.6 Client Configuration
```bash
# DEB
deb https://apt.internal.example.com jammy main

# RPM
[internal-repo]
baseurl=https://rpm.internal.example.com/rocky/9

# PyPI
pip config set global.index-url https://pypi.internal.example.com/simple

# NPM
npm config set registry https://npm.internal.example.com
```

## 7. Security Controls
- Harden mirror server
- Restricted GPG keys
- HTTPS only
- Comprehensive logging
- Default-deny policy (block on scan failure)
- Path traversal protection in all format handlers

## 8. Security Check Matrix
| Check | DEB | RPM | Wheel | sdist | NPM | APK |
|-------|-----|-----|-------|-------|-----|-----|
| Vulnerability scan | Trivy | Trivy | pip-audit | pip-audit | npm-audit | Trivy |
| Virus scan | Yes | Yes | Yes | Yes | Yes | Yes |
| Integrity check | Yes | Yes | Yes | Yes | Yes | Yes |
| Script analysis | Shell | Shell | Skip | Python | JSON | Shell |
| Binary check | Full | Full | Extensions | Skip | Native | Full |

## 9. Rescanning and CVE Drift
Nightly rescans detect newly discovered vulnerabilities.
Packages becoming unsafe are removed from approved mirror.

## 10. Monitoring and Logging
Logs per operation:
- Sync runs (by format)
- Scan results (all 5 layers)
- Publish events
- CVE feed updates

## 11. Failure Modes
| Failure | Mitigation |
|--------|------------|
| Upstream unavailable | Retry with exponential backoff |
| Scanner fails | Block by default (default-deny) |
| CVE feed outdated | Force update before scan |
| GPG issues | Halt publishing |
| Publish fails | Keep previous snapshot |

## 12. Configuration
```yaml
# config/multi-format.yaml
formats:
  deb:
    enabled: true
    repo_manager: aptly
    vulnerability_scanner: trivy
  rpm:
    enabled: true
    repo_manager: createrepo
  wheel:
    enabled: true
    repo_manager: bandersnatch
    vulnerability_scanner: pip-audit
  npm:
    enabled: true
    repo_manager: verdaccio
    vulnerability_scanner: npm-audit
  apk:
    enabled: true
    repo_manager: apk_mirror

scanner:
  severity_threshold: high
  virus_scan_enabled: true
  script_analysis_enabled: true
```

## 13. Directory Layout
```
/opt/safemirror/
    config/
        multi-format.yaml
    data/
        deb/
        rpm/
        pypi/
        npm/
        apk/
    scans/
        deb/
        rpm/
        ...
    approvals/
    logs/
    scripts/
```

## 14. Future Extensions
- Metrics and dashboards
- Web UI for manual review
- Email/Slack notifications
- Custom vulnerability rules

## 15. Testing

### Test Suite Overview
SafeMirror maintains 519+ automated tests covering all components:

- **Unit tests** (`tests/unit/`): Test individual components in isolation
- **Integration tests** (`tests/integration/`): Test multi-component interactions
- **Benchmark tests** (`tests/benchmark/`): Performance measurement

### Coverage Targets
| Component | Target | Current |
|-----------|--------|---------|
| scanner/* | 85% | 85% |
| formats/* | 85% | 78% |
| repos/* | 80% | 68% |
| Overall | 85% | 72% |

### Running Tests
```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=html

# Benchmarks only
pytest tests/benchmark/ --benchmark-only

# Skip slow tests
pytest tests/ -m "not slow"
```

### CI/CD Integration
GitHub Actions workflow runs on every push/PR:
- Tests on Python 3.10, 3.11, 3.12
- Coverage reporting to Codecov
- Linting (ruff, flake8, black)
- Type checking (mypy)
- Security scanning (bandit)

See `docs/TESTING.md` for full testing documentation.

## 16. Risks
- False positives from scanners
- Scanner delays on large packages
- Strict policies may block critical updates
- CVE feed reliability

## 17. Conclusion
SafeMirror provides a controlled, multi-format package mirror with 5-layer security scanning.
It uses standard tools for each format while providing a unified security policy across all package types.
