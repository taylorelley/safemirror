"""Tests for multi-format configuration module."""

import pytest
import tempfile
from pathlib import Path

import yaml

from src.common.config import (
    MirrorConfig,
    FormatConfig,
    ScannerConfig,
    SafeMirrorConfig,
    parse_mirror_config,
    parse_format_config,
    parse_scanner_config,
    parse_config,
    load_config,
    load_typed_config,
    get_enabled_formats,
    get_scanner_for_format,
    DEFAULT_SCANNER_CONFIG,
)


class TestMirrorConfig:
    """Tests for MirrorConfig parsing."""

    def test_parse_basic_mirror(self):
        """Test parsing basic mirror config."""
        mirror_dict = {
            "name": "ubuntu-jammy",
            "upstream_url": "http://archive.ubuntu.com/ubuntu",
            "distributions": ["jammy", "jammy-updates"],
            "components": ["main", "universe"],
            "architectures": ["amd64"],
        }
        mirror = parse_mirror_config(mirror_dict)

        assert mirror.name == "ubuntu-jammy"
        assert mirror.upstream_url == "http://archive.ubuntu.com/ubuntu"
        assert "jammy" in mirror.distributions
        assert "main" in mirror.components
        assert "amd64" in mirror.architectures

    def test_parse_mirror_with_gpg(self):
        """Test parsing mirror with GPG key."""
        mirror_dict = {
            "name": "test",
            "upstream_url": "http://example.com",
            "gpg_key_url": "http://example.com/key.gpg",
        }
        mirror = parse_mirror_config(mirror_dict)

        assert mirror.gpg_key_url == "http://example.com/key.gpg"

    def test_parse_mirror_with_extra_options(self):
        """Test parsing mirror with extra options."""
        mirror_dict = {
            "name": "test",
            "upstream_url": "http://example.com",
            "extra_options": {
                "gpgcheck": True,
                "timeout": 60,
            },
        }
        mirror = parse_mirror_config(mirror_dict)

        assert mirror.extra_options["gpgcheck"] is True
        assert mirror.extra_options["timeout"] == 60


class TestFormatConfig:
    """Tests for FormatConfig parsing."""

    def test_parse_deb_format(self):
        """Test parsing DEB format config."""
        format_dict = {
            "enabled": True,
            "repo_manager": "aptly",
            "vulnerability_scanner": "trivy",
            "mirrors": [
                {
                    "name": "ubuntu",
                    "upstream_url": "http://archive.ubuntu.com/ubuntu",
                }
            ],
        }
        config = parse_format_config("deb", format_dict)

        assert config.enabled
        assert config.repo_manager == "aptly"
        assert config.vulnerability_scanner == "trivy"
        assert len(config.mirrors) == 1

    def test_parse_format_uses_defaults(self):
        """Test format config uses default scanners."""
        config = parse_format_config("wheel", {"enabled": True})

        # Should use pip-audit as default for wheel
        assert config.vulnerability_scanner == "pip-audit"
        assert config.fallback_scanner == "trivy"

    def test_parse_disabled_format(self):
        """Test parsing disabled format."""
        config = parse_format_config("rpm", {"enabled": False})

        assert not config.enabled


class TestScannerConfig:
    """Tests for ScannerConfig parsing."""

    def test_parse_scanner_defaults(self):
        """Test scanner config defaults."""
        config = parse_scanner_config({})

        assert config.virus_scan_enabled
        assert config.integrity_check_enabled
        assert config.script_analysis_enabled
        assert config.binary_check_enabled
        assert config.severity_threshold == "high"
        assert config.max_parallel_scans == 4
        assert config.scan_timeout == 300

    def test_parse_scanner_custom(self):
        """Test custom scanner config."""
        scanner_dict = {
            "virus_scan_enabled": False,
            "severity_threshold": "critical",
            "max_parallel_scans": 8,
        }
        config = parse_scanner_config(scanner_dict)

        assert not config.virus_scan_enabled
        assert config.severity_threshold == "critical"
        assert config.max_parallel_scans == 8


class TestSafeMirrorConfig:
    """Tests for full SafeMirrorConfig parsing."""

    def test_parse_full_config(self):
        """Test parsing full configuration."""
        config_dict = {
            "data_dir": "/data",
            "log_dir": "/logs",
            "formats": {
                "deb": {
                    "enabled": True,
                    "repo_manager": "aptly",
                    "mirrors": [{"name": "ubuntu", "upstream_url": "http://ubuntu.com"}],
                },
                "rpm": {
                    "enabled": False,
                },
            },
            "scanner": {
                "severity_threshold": "critical",
            },
        }
        config = parse_config(config_dict)

        assert config.data_dir == "/data"
        assert config.log_dir == "/logs"
        assert "deb" in config.formats
        assert config.formats["deb"].enabled
        assert not config.formats["rpm"].enabled
        assert config.scanner.severity_threshold == "critical"

    def test_parse_empty_config(self):
        """Test parsing empty configuration."""
        config = parse_config({})

        assert len(config.formats) == 0
        assert config.scanner.virus_scan_enabled  # Uses defaults


class TestConfigUtilities:
    """Tests for configuration utility functions."""

    def test_get_enabled_formats(self):
        """Test getting enabled formats."""
        config = SafeMirrorConfig(
            formats={
                "deb": FormatConfig(enabled=True),
                "rpm": FormatConfig(enabled=False),
                "wheel": FormatConfig(enabled=True),
            }
        )
        enabled = get_enabled_formats(config)

        assert "deb" in enabled
        assert "wheel" in enabled
        assert "rpm" not in enabled

    def test_get_scanner_for_format_custom(self):
        """Test getting scanner for format with custom config."""
        config = SafeMirrorConfig(
            formats={
                "deb": FormatConfig(vulnerability_scanner="grype"),
            }
        )
        scanner = get_scanner_for_format(config, "deb")

        assert scanner == "grype"

    def test_get_scanner_for_format_default(self):
        """Test getting scanner for format with default."""
        config = SafeMirrorConfig()
        scanner = get_scanner_for_format(config, "npm")

        # Should fall back to default
        assert scanner == "npm-audit"


class TestLoadConfig:
    """Tests for loading configuration from files."""

    def test_load_yaml_config(self, tmp_path):
        """Test loading YAML configuration."""
        config_content = """
data_dir: /test/data
formats:
  deb:
    enabled: true
    repo_manager: aptly
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_content)

        config_dict = load_config(str(config_file))

        assert config_dict["data_dir"] == "/test/data"
        assert config_dict["formats"]["deb"]["enabled"]

    def test_load_config_nonexistent(self, tmp_path):
        """Test loading nonexistent config raises error."""
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_load_config_env_expansion(self, tmp_path, monkeypatch):
        """Test environment variable expansion."""
        monkeypatch.setenv("TEST_DIR", "/expanded/path")

        config_content = """
data_dir: ${TEST_DIR}/data
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_content)

        config_dict = load_config(str(config_file))

        assert config_dict["data_dir"] == "/expanded/path/data"

    def test_load_typed_config(self, tmp_path):
        """Test loading typed configuration."""
        config_content = """
data_dir: /test/data
formats:
  deb:
    enabled: true
    repo_manager: aptly
    vulnerability_scanner: trivy
scanner:
  severity_threshold: high
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_content)

        config = load_typed_config(str(config_file))

        assert isinstance(config, SafeMirrorConfig)
        assert config.data_dir == "/test/data"
        assert config.formats["deb"].enabled
        assert config.scanner.severity_threshold == "high"


class TestDefaultScannerConfig:
    """Tests for default scanner configuration."""

    def test_deb_defaults(self):
        """Test DEB format defaults."""
        assert DEFAULT_SCANNER_CONFIG["deb"]["vulnerability_scanner"] == "trivy"

    def test_wheel_defaults(self):
        """Test wheel format defaults."""
        assert DEFAULT_SCANNER_CONFIG["wheel"]["vulnerability_scanner"] == "pip-audit"

    def test_npm_defaults(self):
        """Test NPM format defaults."""
        assert DEFAULT_SCANNER_CONFIG["npm"]["vulnerability_scanner"] == "npm-audit"
