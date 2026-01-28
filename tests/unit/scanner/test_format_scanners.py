"""Unit tests for format-specific scanner integrations.

Tests vulnerability scanners (Trivy, Grype, pip-audit, npm-audit) for
different package formats.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
import subprocess

from src.scanner.scan_packages import PackageScanner, ScanResult, ScanStatus


class TestTrivyScanner:
    """Tests for Trivy scanner integration."""

    @pytest.fixture
    def scanner(self, tmp_path):
        """Create a Trivy scanner with mocked validation."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            return PackageScanner(
                scanner_type="trivy",
                timeout=60,
                scans_dir=str(tmp_path / "scans"),
                min_cvss_score=7.0,
                block_severities=["CRITICAL", "HIGH"]
            )

    def test_trivy_invocation_success(self, scanner):
        """Test successful Trivy invocation."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "Results": [{
                        "Vulnerabilities": [{
                            "VulnerabilityID": "CVE-2023-1234",
                            "Severity": "HIGH",
                            "CVSS": {"nvd": {"V3Score": 8.5}},
                            "PkgName": "libtest",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1"
                        }]
                    }]
                }).encode()
            )

            vulns = scanner._run_trivy("/tmp/scan_path")

            assert len(vulns) == 1
            assert vulns[0]["cve_id"] == "CVE-2023-1234"
            assert vulns[0]["severity"] == "HIGH"
            assert vulns[0]["cvss_score"] == 8.5

    def test_trivy_no_vulnerabilities(self, scanner):
        """Test Trivy with clean package."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"Results": []}).encode()
            )

            vulns = scanner._run_trivy("/tmp/clean_package")

            assert vulns == []

    def test_trivy_empty_output(self, scanner):
        """Test handling empty Trivy output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b""
            )

            vulns = scanner._run_trivy("/tmp/test")

            assert vulns == []

    def test_trivy_invalid_json(self, scanner):
        """Test handling invalid JSON from Trivy."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"not valid json"
            )

            vulns = scanner._run_trivy("/tmp/test")

            assert vulns == []

    def test_trivy_timeout_handling(self, scanner):
        """Test Trivy timeout is properly handled."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("trivy", 60)

            with pytest.raises(RuntimeError, match="timed out"):
                scanner._run_scanner("/tmp/test")

    def test_trivy_deb_scan(self, scanner, tmp_path):
        """Test Trivy scanning a Debian package."""
        pkg_dir = tmp_path / "extracted_deb"
        pkg_dir.mkdir()
        (pkg_dir / "usr" / "bin").mkdir(parents=True)
        (pkg_dir / "usr" / "bin" / "test").write_text("#!/bin/bash")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"Results": []}).encode()
            )

            vulns = scanner._run_trivy(str(pkg_dir))

            # Verify correct trivy command
            call_args = mock_run.call_args[0][0]
            assert "trivy" in call_args
            assert "fs" in call_args

    def test_trivy_rpm_scan(self, scanner, tmp_path):
        """Test Trivy scanning an RPM package."""
        pkg_dir = tmp_path / "extracted_rpm"
        pkg_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"Results": []}).encode()
            )

            vulns = scanner._run_trivy(str(pkg_dir))

            assert vulns == []

    def test_trivy_apk_scan(self, scanner, tmp_path):
        """Test Trivy scanning an Alpine package."""
        pkg_dir = tmp_path / "extracted_apk"
        pkg_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"Results": []}).encode()
            )

            vulns = scanner._run_trivy(str(pkg_dir))

            assert vulns == []


class TestGrypeScanner:
    """Tests for Grype scanner integration."""

    @pytest.fixture
    def scanner(self, tmp_path):
        """Create a Grype scanner with mocked validation."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            return PackageScanner(
                scanner_type="grype",
                timeout=60,
                scans_dir=str(tmp_path / "scans"),
                min_cvss_score=7.0,
                block_severities=["CRITICAL", "HIGH"]
            )

    def test_grype_invocation_success(self, scanner):
        """Test successful Grype invocation."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "matches": [{
                        "vulnerability": {
                            "id": "CVE-2023-5678",
                            "severity": "Critical",
                            "cvss": [{"metrics": {"baseScore": 9.8}}],
                            "description": "Test vulnerability"
                        },
                        "artifact": {
                            "name": "testpkg",
                            "version": "1.0.0"
                        }
                    }]
                }).encode()
            )

            vulns = scanner._run_grype("/tmp/scan_path")

            assert len(vulns) == 1
            assert vulns[0]["cve_id"] == "CVE-2023-5678"
            assert vulns[0]["cvss_score"] == 9.8

    def test_grype_no_vulnerabilities(self, scanner):
        """Test Grype with clean package."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"matches": []}).encode()
            )

            vulns = scanner._run_grype("/tmp/clean")

            assert vulns == []

    def test_grype_result_parsing(self, scanner):
        """Test Grype output parsing with various fields."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "matches": [{
                        "vulnerability": {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "severity": "High",
                            "fix": {"versions": ["2.0.0"]},
                            "namespace": "github:python"
                        },
                        "artifact": {
                            "name": "requests",
                            "version": "2.20.0"
                        }
                    }]
                }).encode()
            )

            vulns = scanner._run_grype("/tmp/test")

            assert vulns[0]["cve_id"] == "GHSA-xxxx-yyyy-zzzz"
            assert vulns[0]["package"] == "requests"
            assert vulns[0]["installed_version"] == "2.20.0"
            assert vulns[0]["fixed_version"] == "2.0.0"


class TestPipAuditScanner:
    """Tests for pip-audit scanner integration."""

    @pytest.fixture
    def scanner(self, tmp_path):
        """Create a pip-audit scanner with mocked validation."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            return PackageScanner(
                scanner_type="pip-audit",
                timeout=60,
                scans_dir=str(tmp_path / "scans"),
                min_cvss_score=7.0,
                block_severities=["CRITICAL", "HIGH"]
            )

    def test_pip_audit_wheel_scan(self, scanner, tmp_path):
        """Test pip-audit scanning a wheel package."""
        pkg_dir = tmp_path / "extracted_wheel"
        pkg_dir.mkdir()
        (pkg_dir / "requirements.txt").write_text("requests==2.20.0\n")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "dependencies": [{
                        "name": "requests",
                        "version": "2.20.0",
                        "vulns": [{
                            "id": "CVE-2023-9999",
                            "fix_versions": ["2.31.0"],
                            "description": "Security issue"
                        }]
                    }]
                }).encode()
            )

            vulns = scanner._run_pip_audit(str(pkg_dir))

            assert len(vulns) == 1
            assert vulns[0]["package"] == "requests"

    def test_pip_audit_sdist_scan(self, scanner, tmp_path):
        """Test pip-audit scanning a source distribution."""
        pkg_dir = tmp_path / "extracted_sdist"
        pkg_dir.mkdir()
        (pkg_dir / "setup.py").write_text("from setuptools import setup")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"dependencies": []}).encode()
            )

            vulns = scanner._run_pip_audit(str(pkg_dir))

            assert vulns == []

    def test_pip_audit_not_found_fallback(self, scanner, tmp_path):
        """Test fallback to trivy when pip-audit not found."""
        pkg_dir = tmp_path / "test"
        pkg_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            # First call (pip-audit) fails, second call (trivy) succeeds
            mock_run.side_effect = [
                FileNotFoundError("pip-audit not found"),
                MagicMock(returncode=0, stdout=json.dumps({"Results": []}).encode())
            ]

            vulns = scanner._run_pip_audit(str(pkg_dir))

            assert vulns == []

    def test_pip_audit_severity_mapping(self, scanner):
        """Test severity mapping for pip-audit results."""
        # GHSA IDs
        vuln = {"id": "GHSA-xxxx-yyyy-zzzz"}
        assert scanner._pip_audit_severity(vuln) == "HIGH"

        # CVE IDs
        vuln = {"id": "CVE-2023-1234"}
        assert scanner._pip_audit_severity(vuln) == "HIGH"

        # Unknown IDs
        vuln = {"id": "UNKNOWN-123"}
        assert scanner._pip_audit_severity(vuln) == "MEDIUM"


class TestNpmAuditScanner:
    """Tests for npm audit scanner integration."""

    @pytest.fixture
    def scanner(self, tmp_path):
        """Create an npm-audit scanner with mocked validation."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            return PackageScanner(
                scanner_type="npm-audit",
                timeout=60,
                scans_dir=str(tmp_path / "scans"),
                min_cvss_score=7.0,
                block_severities=["CRITICAL", "HIGH"]
            )

    def test_npm_audit_scan(self, scanner, tmp_path):
        """Test npm audit scanning."""
        pkg_dir = tmp_path / "npm_package"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text('{"name": "test", "version": "1.0.0"}')

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "vulnerabilities": {
                        "lodash": {
                            "severity": "high",
                            "via": [{
                                "title": "Prototype Pollution",
                                "url": "https://npmjs.com/advisories/1234"
                            }],
                            "range": "< 4.17.21"
                        }
                    }
                }).encode()
            )

            vulns = scanner._run_npm_audit(str(pkg_dir))

            assert len(vulns) == 1
            assert vulns[0]["package"] == "lodash"
            assert vulns[0]["severity"] == "HIGH"

    def test_npm_audit_no_package_json(self, scanner, tmp_path):
        """Test npm audit without package.json."""
        pkg_dir = tmp_path / "no_package_json"
        pkg_dir.mkdir()

        vulns = scanner._run_npm_audit(str(pkg_dir))

        assert vulns == []

    def test_npm_audit_not_found_fallback(self, scanner, tmp_path):
        """Test fallback to trivy when npm not found."""
        pkg_dir = tmp_path / "test"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text('{}')

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                FileNotFoundError("npm not found"),
                MagicMock(returncode=0, stdout=json.dumps({"Results": []}).encode())
            ]

            vulns = scanner._run_npm_audit(str(pkg_dir))

            assert vulns == []


class TestScannerFallback:
    """Tests for scanner fallback behavior on errors."""

    @pytest.fixture
    def scanner(self, tmp_path):
        """Create a scanner with mocked validation."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            return PackageScanner(
                scanner_type="trivy",
                timeout=60,
                scans_dir=str(tmp_path / "scans")
            )

    def test_scanner_fallback_on_error(self, scanner, tmp_path):
        """Test that scanner errors result in blocked status (default-deny)."""
        pkg = tmp_path / "test.deb"
        pkg.write_bytes(b"!<arch>\ntest")

        with patch.object(scanner, "_run_scanner") as mock_run:
            mock_run.side_effect = RuntimeError("Scanner crashed")

            # Also patch extraction since the deb is not valid
            with patch.object(scanner, "_extract_package"):
                result = scanner.scan_package(str(pkg))

                assert result.status == ScanStatus.ERROR
                assert result.error_message is not None

    def test_scanner_not_found_error(self, tmp_path):
        """Test error when scanner is not found."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("trivy not found")

            with pytest.raises(RuntimeError, match="not available"):
                PackageScanner(
                    scanner_type="trivy",
                    scans_dir=str(tmp_path / "scans")
                )


class TestScannerDatabaseManagement:
    """Tests for vulnerability database updates."""

    @pytest.fixture
    def scanner(self, tmp_path):
        """Create scanner with mocked validation."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            return PackageScanner(
                scanner_type="trivy",
                timeout=60,
                scans_dir=str(tmp_path / "scans")
            )

    @patch("subprocess.run")
    def test_trivy_db_update(self, mock_run, scanner):
        """Test Trivy database update."""
        mock_run.return_value = MagicMock(returncode=0)

        result = scanner.update_scanner_db()

        assert result is True
        call_args = mock_run.call_args[0][0]
        assert "trivy" in call_args
        assert "--download-db-only" in call_args

    @patch("subprocess.run")
    def test_grype_db_update(self, mock_run, tmp_path):
        """Test Grype database update."""
        with patch("src.scanner.scan_packages.PackageScanner._validate_scanner"):
            scanner = PackageScanner(
                scanner_type="grype",
                scans_dir=str(tmp_path / "scans")
            )

        mock_run.return_value = MagicMock(returncode=0)

        result = scanner.update_scanner_db()

        assert result is True

    @patch("subprocess.run")
    def test_db_update_failure(self, mock_run, scanner):
        """Test database update failure handling."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "trivy")

        result = scanner.update_scanner_db()

        assert result is False

    @patch("subprocess.run")
    def test_db_update_timeout(self, mock_run, scanner):
        """Test database update timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 600)

        result = scanner.update_scanner_db()

        assert result is False
