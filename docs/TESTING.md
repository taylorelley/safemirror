# Testing Guide

This document describes the testing strategy, structure, and procedures for SafeMirror.

## Test Suite Overview

SafeMirror maintains a comprehensive test suite with 510+ tests covering:

- **Unit tests**: Individual component testing with mocks
- **Integration tests**: Multi-component interaction testing
- **Format tests**: Package format extraction and validation
- **Security tests**: Malicious pattern detection verification

## Running Tests

### Quick Test Run

```bash
# Run all tests
pytest tests/ -v

# Run with short output
pytest tests/ -q

# Run specific test file
pytest tests/unit/scanner/test_virus_scanner.py -v

# Run specific test class
pytest tests/unit/scanner/test_virus_scanner.py::TestVirusScannerScanPackage -v

# Run tests matching a pattern
pytest tests/ -k "virus" -v
```

### Coverage Analysis

```bash
# Run with coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Generate HTML coverage report
pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html in browser

# Generate XML for CI
pytest tests/ --cov=src --cov-report=xml
```

### Running by Category

```bash
# Run only unit tests
pytest tests/unit/ -v

# Run only integration tests
pytest tests/integration/ -v

# Skip slow tests
pytest tests/ -m "not slow" -v

# Run only benchmark tests
pytest tests/ -m benchmark --benchmark-only
```

## Test Structure

```
tests/
├── conftest.py                    # Shared fixtures
├── fixtures/
│   ├── conftest.py               # Fixture-specific configuration
│   ├── packages/                 # Sample package files
│   │   ├── deb/
│   │   ├── rpm/
│   │   ├── wheel/
│   │   ├── npm/
│   │   ├── apk/
│   │   └── sdist/
│   └── __init__.py
├── integration/
│   ├── test_multi_format.py      # Cross-format testing
│   ├── test_scan_pipeline.py     # Full pipeline tests
│   └── __init__.py
└── unit/
    ├── common/
    │   └── test_config.py        # Configuration tests
    ├── formats/
    │   ├── test_apk.py           # Alpine package tests
    │   ├── test_base.py          # Base format tests
    │   ├── test_corrupt_packages.py  # Malformed input tests
    │   ├── test_deb.py           # Debian package tests
    │   ├── test_malicious_paths.py   # Path attack tests
    │   ├── test_npm.py           # NPM package tests
    │   ├── test_registry.py      # Format registry tests
    │   ├── test_rpm.py           # RPM package tests
    │   ├── test_sdist.py         # Python sdist tests
    │   └── test_wheel.py         # Python wheel tests
    ├── publisher/
    │   └── test_build_approved_list.py
    ├── repos/
    │   ├── test_aptly.py         # Aptly integration tests
    │   ├── test_base.py          # Base repository tests
    │   └── test_registry.py      # Repo registry tests
    └── scanner/
        ├── test_binary_checker_extended.py  # Binary analysis
        ├── test_format_scanners.py          # Format-specific scanning
        ├── test_scan_packages.py            # Package scanning
        ├── test_script_patterns.py          # Malicious pattern detection
        └── test_virus_scanner.py            # Virus/malware scanning
```

## Test Categories

### Unit Tests

Located in `tests/unit/`, these test individual components in isolation using mocks:

- **Format handlers**: Package extraction and metadata parsing
- **Scanners**: Vulnerability detection, binary analysis, script analysis
- **Publishers**: Approved list generation
- **Configuration**: YAML parsing and validation

### Integration Tests

Located in `tests/integration/`, these test component interactions:

- **Pipeline tests**: Full scan workflow from input to result
- **Multi-format tests**: Concurrent format processing
- **Registry tests**: Dynamic format/repository registration

### Security Tests

Spread across multiple test files, these verify security controls:

- **Pattern detection**: Shell injection, curl-pipe-bash, network exfiltration
- **Path attacks**: Symlink escape, directory traversal, unicode confusion
- **Corrupt input**: Truncated files, zip bombs, malformed archives
- **Binary analysis**: Setuid detection, unusual interpreters

## Key Test Files

### `test_virus_scanner.py`

Tests ClamAV/Trivy/Grype integration:

```python
class TestVirusScannerInitialization:
    test_init_validates_clamav()
    test_init_fails_without_clamav()
    test_init_with_update()

class TestVirusScannerScanPackage:
    test_scan_package_clean()
    test_scan_package_infected()
    test_scan_package_timeout()
```

### `test_script_patterns.py`

Tests dangerous pattern detection:

```python
class TestShellPatterns:
    test_rm_rf_root_detection()
    test_curl_pipe_bash_detection()
    test_wget_pipe_bash_detection()
    test_base64_decode_execution()

class TestNpmScriptPatterns:
    test_npm_child_process_detection()
    test_npm_env_exfiltration()

class TestPythonScriptPatterns:
    test_setup_py_subprocess_detection()
    test_python_eval_detection()
```

### `test_corrupt_packages.py`

Tests handling of malformed input:

```python
class TestTruncatedPackages:
    test_truncated_deb_file()
    test_truncated_rpm_file()
    test_corrupt_zip_wheel()

class TestZeroByte:
    test_zero_byte_package()

class TestZipBombs:
    test_compression_bomb_detection()
```

### `test_scan_pipeline.py`

Tests full scanning workflow:

```python
class TestFullPipeline:
    test_deb_full_pipeline()
    test_rpm_full_pipeline()
    test_wheel_full_pipeline()
    test_npm_full_pipeline()
    test_apk_full_pipeline()
    test_sdist_full_pipeline()
```

## Writing New Tests

### Test Conventions

1. **Use descriptive names**: `test_scan_package_returns_blocked_for_high_severity_cve`
2. **One assertion per test**: Each test verifies a single behavior
3. **Use fixtures**: Share setup code via pytest fixtures
4. **Mock external dependencies**: Don't call real scanners in unit tests
5. **Test edge cases**: Include malformed input, timeouts, errors

### Fixture Usage

Common fixtures in `tests/conftest.py`:

```python
@pytest.fixture
def temp_package(tmp_path):
    """Create a temporary package file."""
    pkg_path = tmp_path / "test.deb"
    pkg_path.write_bytes(b"package content")
    return pkg_path

@pytest.fixture
def mock_scanner(mocker):
    """Mock the vulnerability scanner."""
    return mocker.patch("src.scanner.virus_scanner.subprocess.run")

@pytest.fixture
def sample_config():
    """Return a valid configuration dictionary."""
    return {
        "formats": {"deb": {"enabled": True}},
        "scanners": {"trivy": {"enabled": True}}
    }
```

### Test Template

```python
import pytest
from unittest.mock import Mock, patch

from src.scanner.some_module import SomeClass


class TestSomeClass:
    """Tests for SomeClass functionality."""

    @pytest.fixture
    def instance(self):
        """Create a SomeClass instance for testing."""
        return SomeClass()

    def test_method_returns_expected_value(self, instance):
        """Verify method returns correct value for valid input."""
        result = instance.method("input")
        assert result == "expected"

    def test_method_raises_on_invalid_input(self, instance):
        """Verify method raises ValueError for invalid input."""
        with pytest.raises(ValueError, match="invalid"):
            instance.method(None)

    def test_method_handles_edge_case(self, instance):
        """Verify method handles empty input gracefully."""
        result = instance.method("")
        assert result is None
```

## Coverage Targets

| Module | Target | Current |
|--------|--------|---------|
| scanner/binary_checker.py | 90% | 91% |
| scanner/virus_scanner.py | 90% | 86% |
| scanner/script_analyzer.py | 85% | 74% |
| scanner/scan_packages.py | 85% | 84% |
| formats/*.py | 85% | 77-88% |
| repos/*.py | 80% | 59-89% |
| **Overall** | **85%** | **74%** |

## Continuous Integration

Tests run automatically on:

- Every push to `main`
- Every pull request targeting `main`

CI checks include:

1. **Unit tests**: `pytest tests/unit/`
2. **Integration tests**: `pytest tests/integration/`
3. **Coverage**: Must maintain >70% (target 85%)
4. **Linting**: `ruff check`, `flake8`
5. **Formatting**: `black --check`
6. **Type checking**: `mypy src/`
7. **Security**: `bandit -r src/`

## Troubleshooting

### Tests Fail Locally But Pass in CI

- Check Python version: CI runs 3.10, 3.11, 3.12
- Clear pytest cache: `pytest --cache-clear`
- Check for stale `.pyc` files: `find . -name "*.pyc" -delete`

### Coverage Not Updating

- Clear coverage data: `rm .coverage`
- Run with `--cov-append=False`

### Slow Tests

- Use `-m "not slow"` to skip slow tests
- Run specific test files instead of full suite
- Check for unnecessary I/O in fixtures

### Import Errors

- Verify PYTHONPATH includes project root
- Check `__init__.py` files exist in all packages
- Verify dependencies installed: `pip install -r requirements.txt`
