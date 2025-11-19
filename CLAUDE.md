# CLAUDE.md - AI Assistant Guide for safe-apt

## Project Overview

**safe-apt** is a security-focused APT mirror system that filters packages through vulnerability scanning before making them available to internal clients. The project implements a two-layer architecture:

1. **Staging Mirror**: Exact copy of upstream Ubuntu/Debian repositories
2. **Approved Mirror**: Filtered repository containing only scanned and approved packages

**Current Status**: Design phase - comprehensive architecture documented in DESIGN.md, but no implementation code exists yet.

**License**: MIT (taylorelley, 2025)

**Repository**: taylorelley/safe-apt

---

## Repository Structure

### Current State (Design Phase)

```
/home/user/safe-apt/
├── .git/              # Git repository metadata
├── DESIGN.md          # Comprehensive architecture specification (157 lines)
├── LICENSE            # MIT License
└── CLAUDE.md          # This file - AI assistant guide
```

### Planned Implementation Structure

```
/opt/apt-mirror-system/     # Production deployment location
├── scans/                   # Vulnerability scan results (JSON)
├── snapshots/               # Aptly snapshot metadata
├── approvals/               # Approved package lists (approved.txt)
├── logs/                    # Audit and operation logs
└── scripts/                 # Automation scripts

/home/user/safe-apt/        # Development repository
├── src/                     # Implementation code (not yet created)
│   ├── scanner/            # Scanner worker implementation
│   ├── publisher/          # Publishing automation
│   └── config/             # Configuration templates
├── tests/                   # Test suite (not yet created)
├── docs/                    # Additional documentation
├── scripts/                 # Development and deployment scripts
├── requirements.txt        # Python dependencies (when created)
├── README.md               # Setup and usage (to be created)
└── .gitignore             # Git ignore patterns (to be created)
```

---

## Architecture Overview

### Core Components

1. **Aptly** - Repository mirroring, snapshot management, and publishing
2. **Vulnerability Scanner** - Trivy or Grype (JSON output, CVE support)
3. **Scanner Worker** - Extracts .deb files and orchestrates scanning
4. **Publisher** - Filters packages and publishes approved snapshots
5. **Web Server** - nginx/Apache serving HTTPS repository

### Workflow Pipeline

```
Upstream → Staging Mirror → Snapshot → Detect Changes →
Scan Packages → Build Approved List → Publish → Internal Clients
```

**Key Operations:**
- Sync: `aptly mirror update <mirror>` + snapshot creation
- Diff: `aptly snapshot diff old new` to find changed packages
- Scan: Extract .deb, run Trivy/Grype, store results
- Filter: `aptly snapshot filter` with approved.txt
- Publish: `aptly publish switch jammy approved-YYYYMMDD`
- Rescan: Nightly CVE updates for existing packages

---

## Development Workflows

### Starting New Work

1. **Check current branch**: Should be on a `claude/` prefixed branch
2. **Review DESIGN.md**: Understand architecture before implementing
3. **Create directory structure**: Follow planned layout in section 12 of DESIGN.md
4. **Identify component**: Determine which component you're working on

### Implementation Phases (Recommended Order)

**Phase 1: Foundation**
- Create directory structure
- Write setup scripts
- Define configuration schemas
- Create README.md with installation instructions

**Phase 2: Core Pipeline**
- Implement sync automation (Aptly integration)
- Build change detection logic
- Create scanner worker (package extraction + scanning)
- Implement approval list generation

**Phase 3: Publishing**
- Develop publisher automation
- Implement snapshot filtering
- Add GPG signing integration
- Configure web server setup

**Phase 4: Resilience**
- Add error handling and retry logic
- Implement logging infrastructure
- Create monitoring hooks
- Build rescan automation

**Phase 5: Operations**
- Write deployment documentation
- Create operational runbooks
- Add metrics collection
- Build testing framework

### Git Workflow

**Branch**: Always work on `claude/claude-md-mi5k0swaotla2ac6-01CXvdqFF1k97V5NW5HEUtGu`

**Committing:**
```bash
git add <files>
git commit -m "Clear, descriptive message"
```

**Pushing:**
```bash
git push -u origin claude/claude-md-mi5k0swaotla2ac6-01CXvdqFF1k97V5NW5HEUtGu
```

**CRITICAL**: Only push to branches starting with `claude/` and matching the session ID. Network failures should retry up to 4 times with exponential backoff (2s, 4s, 8s, 16s).

---

## Key Conventions

### Code Style

**Shell Scripts:**
- Use `#!/bin/bash` shebang
- Enable strict mode: `set -euo pipefail`
- Document functions with comments
- Use meaningful variable names (UPPER_CASE for constants, lower_case for variables)
- Quote all variables: `"${variable}"`
- Check exit codes explicitly for critical operations

**Python:**
- Follow PEP 8 style guide
- Type hints for function signatures
- Docstrings for all public functions/classes
- Use pathlib for file operations
- Handle exceptions explicitly
- Use logging module (not print statements)

**Configuration:**
- YAML for complex configuration
- Simple key=value for environment configs
- JSON for structured data interchange (scanner output)
- Document all configuration options

### Naming Conventions

**Files:**
- Scripts: `verb-noun.sh` (e.g., `sync-mirror.sh`, `scan-packages.sh`)
- Python modules: `lowercase_with_underscores.py`
- Config files: `component.yaml` or `component.conf`

**Functions/Methods:**
- Shell: `verb_noun()` (e.g., `create_snapshot()`)
- Python: `verb_noun()` (e.g., `scan_package()`)

**Variables:**
- Constants: `STAGING_MIRROR_URL`
- Variables: `snapshot_name`, `scan_result`
- Snapshots: `staging-YYYYMMDD`, `approved-YYYYMMDD`

**Logging:**
- Timestamps: ISO 8601 format `YYYY-MM-DDTHH:MM:SS`
- Log files: `operation-YYYYMMDD.log`
- Severity levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

### Directory Conventions

**Production:**
- `/opt/apt-mirror-system/` - Installation root
- `/var/lib/aptly/` - Aptly data (standard location)
- `/var/lib/aptly/public/` - Published repository
- `/var/log/apt-mirror-system/` - Logs

**Development:**
- `src/` - All source code
- `tests/` - Test files mirror src/ structure
- `scripts/` - Utility and deployment scripts
- `docs/` - Documentation beyond README/DESIGN

---

## Security Considerations

### Critical Security Requirements

1. **Default-Deny Policy**: If scanning fails, block the package
2. **GPG Signing**: All published repositories must be signed
3. **HTTPS Only**: No HTTP serving of packages
4. **Audit Logging**: Log all sync, scan, and publish operations
5. **Server Hardening**: Minimal attack surface on mirror server
6. **Key Management**: Restricted access to GPG signing keys
7. **Input Validation**: Sanitize all package names and paths
8. **Privilege Separation**: Run components with minimal required privileges

### Vulnerability Management

**Scanning Strategy:**
- Use established tools (Trivy/Grype) - don't write custom CVE detection
- Support JSON output for programmatic processing
- Store scan results for audit trail
- Implement rescanning for CVE drift detection

**False Positive Handling:**
- Log all blocked packages with scan results
- Provide manual review mechanism (future extension)
- Document override process for known false positives

**CVE Feed Management:**
- Daily CVE database updates
- Force update capability when feed is stale
- Monitor feed freshness

---

## Implementation Guidelines

### When Implementing Features

1. **Read DESIGN.md First**: Understand the architectural context
2. **Check Scope**: Verify feature is in-scope (Section 3 of DESIGN.md)
3. **Follow Architecture**: Respect the component boundaries (Section 5)
4. **Use Existing Tools**: Prefer aptly, Trivy/Grype over custom solutions
5. **Maintain Compatibility**: Keep Debian/Ubuntu package format compatibility
6. **Add Logging**: Log all significant operations
7. **Handle Failures**: Implement mitigations from Section 10 of DESIGN.md
8. **Document**: Update docs as you implement

### Dependencies to Use

**Required:**
- `aptly` - Debian repository management
- `trivy` OR `grype` - Vulnerability scanning
- `nginx` OR `apache2` - HTTPS serving
- `gpg` - Repository signing

**Python (when needed):**
- `requests` - HTTP operations
- `pyyaml` - Configuration parsing
- `click` - CLI building
- Standard library where possible

**Avoid:**
- Custom package format parsers
- Home-grown CVE databases
- Reinventing repository tools

### Error Handling Patterns

**Shell Scripts:**
```bash
# Check aptly commands
if ! aptly mirror update ubuntu-jammy; then
    log_error "Mirror update failed"
    exit 1
fi

# Use traps for cleanup
cleanup() {
    rm -rf "${temp_dir}"
}
trap cleanup EXIT
```

**Python:**
```python
import logging

try:
    result = scan_package(package_path)
except ScannerError as e:
    logging.error(f"Scan failed for {package_path}: {e}")
    # Default-deny: treat as vulnerable
    return BlockedPackage(package_path, reason=str(e))
```

### Logging Best Practices

**What to Log:**
- Sync start/end times and package counts
- Each package scan with result (approved/blocked)
- Publish operations with snapshot names
- All errors and warnings
- Configuration changes
- Manual overrides

**Log Format:**
```
YYYY-MM-DDTHH:MM:SS [LEVEL] [component] message
2025-11-19T14:23:45 [INFO] [scanner] Scanning package: curl_7.81.0-1ubuntu1.16_amd64.deb
2025-11-19T14:23:47 [WARNING] [scanner] CVE-2023-1234 found in curl_7.81.0
2025-11-19T14:23:47 [INFO] [scanner] Package blocked: curl_7.81.0-1ubuntu1.16_amd64.deb
```

---

## Testing Strategy

### Testing Levels (When Implemented)

**Unit Tests:**
- Test individual functions (parsing, filtering logic)
- Mock external dependencies (aptly, scanners)
- Fast execution (<1s per test)
- Location: `tests/unit/`

**Integration Tests:**
- Test component interactions
- Use test fixtures (sample .deb files)
- Verify aptly commands produce expected output
- Location: `tests/integration/`

**End-to-End Tests:**
- Full pipeline from sync to publish
- Use test repository (small package set)
- Verify published repository is usable
- Location: `tests/e2e/`

### Test Data

**Create Test Fixtures:**
- Small .deb files (sample packages)
- Mock scan results (JSON)
- Test GPG keys (not production keys!)
- Sample approved.txt files

**Test Scenarios:**
- Clean package (no vulnerabilities)
- Vulnerable package (with known CVE)
- Malformed package (invalid .deb)
- Scanner failure (timeout, error)
- Upstream unavailable
- CVE feed stale

### Running Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests (requires aptly)
pytest tests/integration/

# Full pipeline
pytest tests/e2e/

# Coverage report
pytest --cov=src --cov-report=html
```

---

## Common Tasks

### Adding a New Component

1. Create directory in `src/<component>/`
2. Add `__init__.py` if Python
3. Create corresponding test directory `tests/unit/<component>/`
4. Document component purpose in README
5. Add to DESIGN.md if architectural change

### Modifying the Pipeline

1. Review current workflow (Section 6 of DESIGN.md)
2. Identify insertion point
3. Ensure logging is added
4. Update failure modes table if needed
5. Test with small package set first

### Updating Dependencies

1. Test in isolated environment first
2. Update requirements.txt (Python) or document in README
3. Test full pipeline
4. Update documentation
5. Commit with clear message about dependency change

### Debugging Issues

**Check Logs:**
```bash
tail -f /var/log/apt-mirror-system/scanner.log
tail -f /var/log/apt-mirror-system/publisher.log
```

**Verify Aptly State:**
```bash
aptly mirror list
aptly snapshot list
aptly publish list
```

**Test Scanner Manually:**
```bash
trivy fs --format json /path/to/extracted/package
```

**Validate Published Repo:**
```bash
curl -I https://apt.internal.example.com/dists/jammy/Release
apt-cache policy  # From client
```

---

## Documentation Standards

### Code Comments

**When to Comment:**
- Complex algorithms or logic
- Non-obvious security decisions
- Workarounds for tool limitations
- References to DESIGN.md sections

**When NOT to Comment:**
- Self-explanatory code
- Obvious operations
- Redundant descriptions

### Commit Messages

**Format:**
```
<type>: <summary in imperative mood>

<optional detailed description>

<optional references>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code restructuring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat: Implement scanner worker for package extraction

Add Python module to extract .deb files and invoke Trivy scanner.
Includes retry logic and structured JSON output.

Refs: DESIGN.md Section 5.3
```

```
fix: Handle aptly snapshot diff empty output

When no packages changed, aptly returns empty output which caused
pipeline failure. Now treats empty diff as success case.
```

### README Requirements

**README.md Should Include:**
1. Project description and purpose
2. Prerequisites (aptly, Trivy/Grype, etc.)
3. Installation instructions
4. Configuration guide
5. Usage examples
6. Architecture diagram
7. Contributing guidelines
8. License information

---

## Known Risks and Mitigations

### Documented Risks (DESIGN.md Section 13)

1. **False Positives**: Vulnerability scanners may flag safe packages
   - Mitigation: Manual review capability, override mechanism

2. **Scanner Delays**: Large packages take time to scan
   - Mitigation: Parallel scanning, timeout configuration

3. **Strict Policies**: May remove packages too aggressively
   - Mitigation: Configurable policies, notification before removal

4. **CVE Feed Reliance**: Accuracy depends on external CVE data
   - Mitigation: Multiple scanner support, feed freshness monitoring

### Failure Modes (DESIGN.md Section 10)

| Failure | Default Behavior | Implementation Note |
|---------|-----------------|-------------------|
| Upstream unavailable | Retry with exponential backoff | Max 4 retries at 2s, 4s, 8s, 16s |
| Scanner fails | Block package by default | Never allow unscanned packages |
| CVE feed outdated | Force update before scan | Check feed age threshold |
| GPG issues | Halt publishing | Never publish unsigned repos |
| Publish fails | Keep previous snapshot | Atomic publish switching |

---

## Future Extensions (DESIGN.md Section 11)

**Planned but Out of Current Scope:**
- Metrics collection and dashboards
- Web UI for manual review
- Multi-distribution support (beyond Ubuntu/Debian)
- Email/Slack notifications
- Custom package builds
- Automatic patching

**When Implementing Extensions:**
1. Update DESIGN.md Section 11
2. Ensure core pipeline remains stable
3. Make extensions optional/pluggable
4. Document configuration clearly

---

## AI Assistant Specific Notes

### Before Starting Work

1. **Always read DESIGN.md**: Contains authoritative architecture
2. **Check current state**: Repository is in design phase, no implementation yet
3. **Verify branch**: Must be on `claude/` prefixed branch
4. **Understand scope**: Don't implement out-of-scope features without discussion

### When Asked to Implement Features

1. **Confirm alignment**: Check if feature matches DESIGN.md
2. **Propose structure**: Suggest file/directory organization first
3. **Use existing tools**: Prefer aptly, Trivy/Grype over custom code
4. **Add tests**: Include test files with implementation
5. **Update docs**: Keep CLAUDE.md and README in sync

### When Asked to Debug

1. **Check logs first**: Implementation should have comprehensive logging
2. **Verify configuration**: Validate against DESIGN.md
3. **Test in isolation**: Break down pipeline into components
4. **Review security**: Ensure no security controls were bypassed

### When Asked Questions

1. **Reference DESIGN.md**: Use section numbers (e.g., "See DESIGN.md Section 5.3")
2. **Be specific**: Cite file paths, line numbers, function names
3. **Consider security**: Always evaluate security implications
4. **Think systematically**: Use the architectural diagram as reference

### Code Quality Standards

**Always:**
- Follow the conventions in this document
- Add logging for operations
- Handle errors explicitly
- Write tests for new code
- Update documentation
- Use type hints (Python) or declare variables (Bash)

**Never:**
- Commit secrets or credentials
- Skip error handling
- Write security-critical custom code without review
- Ignore test failures
- Use HTTP where HTTPS is required
- Allow unscanned packages through

---

## Quick Reference

### Essential Files

- `DESIGN.md` - Architecture specification (157 lines)
- `CLAUDE.md` - This file - AI assistant guide
- `LICENSE` - MIT License
- `README.md` - To be created (setup instructions)

### Essential Commands

```bash
# Aptly operations
aptly mirror update <mirror>
aptly snapshot create <name> from mirror <mirror>
aptly snapshot diff <old> <new>
aptly snapshot filter <source> <dest> -include-file=approved.txt
aptly publish switch <dist> <snapshot>

# Scanning (when implemented)
trivy fs --format json <path>
grype dir:<path> -o json

# Git operations
git status
git add <files>
git commit -m "message"
git push -u origin <branch>
```

### Key Locations

- Design docs: `/home/user/safe-apt/DESIGN.md`
- Deployment: `/opt/apt-mirror-system/` (planned)
- Aptly data: `/var/lib/aptly/` (standard)
- Published repo: `/var/lib/aptly/public/`
- Logs: `/var/log/apt-mirror-system/` (planned)

### Important Principles

1. **Security First**: Default-deny, HTTPS-only, signed repositories
2. **Use Standard Tools**: aptly, Trivy/Grype, nginx/Apache
3. **Maintain Compatibility**: Debian/Ubuntu package formats
4. **Comprehensive Logging**: Audit all operations
5. **Graceful Degradation**: Handle failures per DESIGN.md Section 10

---

## Version History

- **2025-11-19**: Initial CLAUDE.md created during design phase
  - Comprehensive guide for AI assistants
  - Based on DESIGN.md architecture
  - No implementation code exists yet

---

## Questions or Issues?

1. **Architecture Questions**: See DESIGN.md
2. **Implementation Details**: See this file (CLAUDE.md)
3. **Repository Issues**: Check git history and commit messages
4. **License Questions**: See LICENSE (MIT)

This guide should be updated as the implementation progresses. Always keep CLAUDE.md synchronized with actual codebase state.
