"""Pytest configuration and shared fixtures."""

import pytest


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
    }
