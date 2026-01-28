# Multi-Format Package Support

SafeMirror supports security scanning for multiple package formats. This document details the format-specific behavior, capabilities, and configuration.

## Supported Formats

| Format | Extension | Handler | Repo Manager | Vulnerability Scanner |
|--------|-----------|---------|--------------|----------------------|
| Debian | `.deb` | `deb.py` | aptly | Trivy/Grype |
| RPM | `.rpm` | `rpm.py` | createrepo_c | Trivy/Grype |
| Alpine APK | `.apk` | `apk.py` | apk-tools | Trivy/Grype |
| Python Wheel | `.whl` | `wheel.py` | bandersnatch | pip-audit |
| Python sdist | `.tar.gz` | `sdist.py` | bandersnatch | pip-audit |
| NPM | `.tgz` | `npm.py` | verdaccio | npm-audit |

## Format Detection

SafeMirror automatically detects package formats using:
1. **Magic bytes** - Binary signature at file start
2. **File extension** - Fallback detection
3. **Content inspection** - Format-specific validation

```python
from src.formats import detect_format

handler = detect_format(Path("/path/to/package.deb"))
if handler:
    print(f"Detected format: {handler.format_name}")
```

## Format Capabilities

Each format has different security check applicability:

### Debian (`.deb`)
- **Vulnerability scan**: Trivy/Grype
- **Virus scan**: Full
- **Integrity check**: ar archive validation, control file presence
- **Script analysis**: preinst, postinst, prerm, postrm (shell scripts)
- **Binary check**: Full (SUID, device files, symlinks)

### RPM (`.rpm`)
- **Vulnerability scan**: Trivy/Grype
- **Virus scan**: Full
- **Integrity check**: rpm -K signature validation
- **Script analysis**: %pre, %post, %preun, %postun scriptlets
- **Binary check**: Full

### Alpine APK (`.apk`)
- **Vulnerability scan**: Trivy/Grype
- **Virus scan**: Full
- **Integrity check**: gzip + tar validation, .PKGINFO presence
- **Script analysis**: .pre-install, .post-install, .trigger scripts
- **Binary check**: Full

### Python Wheel (`.whl`)
- **Vulnerability scan**: pip-audit (primary), Trivy (fallback)
- **Virus scan**: Full
- **Integrity check**: ZIP validation, METADATA presence
- **Script analysis**: Skipped (wheels don't have install scripts)
- **Binary check**: Extension modules only (`.so`, `.pyd`)

### Python Source Distribution (`.tar.gz`)
- **Vulnerability scan**: pip-audit (primary), Trivy (fallback)
- **Virus scan**: Full
- **Integrity check**: tar.gz validation
- **Script analysis**: setup.py, pyproject.toml analysis
- **Binary check**: Skipped (source only)

### NPM (`.tgz`)
- **Vulnerability scan**: npm-audit (primary), Trivy (fallback)
- **Virus scan**: Full
- **Integrity check**: package.json validation
- **Script analysis**: preinstall, install, postinstall scripts
- **Binary check**: Native addons only

## Script Analysis Patterns

### Shell Scripts (DEB, RPM, APK)
Detected dangerous patterns:
- `rm -rf /` - Recursive root deletion
- `curl | sh` / `wget | bash` - Remote code execution
- `chmod 777` - Overly permissive permissions
- `eval` with user input - Code injection
- Base64 decoding to shell - Obfuscated commands

### Python Scripts (sdist)
Detected dangerous patterns:
- `subprocess.call()` / `os.system()` - Shell execution
- `eval()` / `exec()` - Dynamic code execution
- `__import__()` - Dynamic imports
- Network operations during install

### NPM Scripts (package.json)
Detected dangerous patterns:
- `child_process` - Subprocess execution
- `eval()` - Dynamic code execution
- Network calls (`http`, `https`, `request`)
- File system access outside package

## Package Key Formats

Each format has a specific key format for identification:

```python
# DEB: {name}_{version}_{architecture}
"curl_7.81.0-1ubuntu1.16_amd64"

# RPM: {name}-{version}-{release}.{architecture}
"curl-7.76.1-14.el8.x86_64"

# APK: {name}-{version}-r{release}
"curl-7.83.1-r0"

# Wheel/sdist: {name}-{version}
"requests-2.28.1"

# NPM: {name}@{version} or @{scope}/{name}@{version}
"lodash@4.17.21"
"@types/node@18.0.0"
```

## Configuration

### Enabling/Disabling Formats

```yaml
formats:
  deb:
    enabled: true
    repo_manager: aptly
  rpm:
    enabled: false  # Disabled
  wheel:
    enabled: true
    repo_manager: bandersnatch
```

### Format-Specific Scanner Configuration

```yaml
formats:
  wheel:
    vulnerability_scanner: pip-audit
    fallback_scanner: trivy
  npm:
    vulnerability_scanner: npm-audit
    fallback_scanner: trivy
```

### Mirror Configuration

```yaml
formats:
  deb:
    mirrors:
      - name: ubuntu-jammy
        upstream_url: http://archive.ubuntu.com/ubuntu
        distributions:
          - jammy
          - jammy-updates
        components:
          - main
          - universe
        architectures:
          - amd64
```

## Usage Examples

### Scanning a Package

```python
from pathlib import Path
from src.formats import detect_format
from src.scanner.enhanced_scanner import EnhancedScanner

# Auto-detect format
package_path = Path("/path/to/package.whl")
handler = detect_format(package_path)

# Create scanner with format handler
scanner = EnhancedScanner(format_handler=handler)
result = scanner.scan(package_path)

print(f"Status: {result['overall_status']}")
```

### Extracting Package Contents

```python
from src.formats.wheel import WheelPackageFormat

handler = WheelPackageFormat()
extracted = handler.extract(Path("/path/to/package.whl"))

print(f"Package: {extracted.metadata.name} {extracted.metadata.version}")
print(f"Files: {len(extracted.file_list)}")
print(f"Scripts: {len(extracted.scripts)}")

# Clean up
extracted.cleanup()
```

### Running Pipeline for Specific Format

```bash
# Single format
./scripts/run-pipeline.sh --format rpm

# All enabled formats
./scripts/run-pipeline.sh --all-formats

# With custom config
./scripts/run-pipeline.sh --format npm --config /path/to/config.yaml
```

## Adding New Formats

To add a new package format:

1. Create handler in `src/formats/`:
```python
from src.formats.base import PackageFormat, FormatCapabilities

class NewFormat(PackageFormat):
    @property
    def format_name(self) -> str:
        return "newformat"

    @property
    def file_extensions(self) -> List[str]:
        return [".new"]

    @property
    def capabilities(self) -> FormatCapabilities:
        return FormatCapabilities(
            supports_vulnerability_scan=True,
            # ... other capabilities
        )

    def detect(self, path: Path) -> bool:
        # Magic byte or extension detection
        pass

    def extract(self, path: Path, dest: Path = None) -> ExtractedContent:
        # Extract package contents
        pass

    # ... implement other required methods
```

2. Register in `src/formats/registry.py`:
```python
def auto_register_formats():
    # ... existing registrations
    try:
        from .newformat import NewFormat
        register_handler(NewFormat())
    except ImportError:
        pass
```

3. Add repository manager in `src/repos/`:
```python
from src.repos.base import RepositoryManager

class NewRepoManager(RepositoryManager):
    # ... implement sync, snapshot, publish methods
```

4. Update configuration schema in `src/common/config.py`

5. Add tests in `tests/unit/formats/test_newformat.py`

## Security Considerations

### Path Traversal Protection
All format handlers validate paths to prevent:
- `../` traversal attacks
- Absolute path extraction
- Symlink-based escapes

### Default-Deny Policy
If any security check fails or cannot be performed:
- Package is blocked by default
- Error is logged with details
- Manual review can override (if configured)

### Signature Verification
Formats supporting signatures (DEB, RPM, APK):
- Signature validation is part of integrity check
- Missing signatures can be configured to warn or block
