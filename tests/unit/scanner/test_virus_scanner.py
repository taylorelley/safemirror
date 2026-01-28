"""Unit tests for virus scanner integration.

Tests ClamAV-based virus scanning including invocation, timeout handling,
result parsing, and database management.
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
import subprocess

from src.scanner.virus_scanner import VirusScanner, VirusScanResult


class TestVirusScannerInitialization:
    """Tests for VirusScanner initialization."""

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_init_validates_clamav(self, mock_run):
        """Test that initialization validates ClamAV availability."""
        mock_run.return_value = MagicMock(returncode=0)

        scanner = VirusScanner(timeout=60)

        mock_run.assert_called_once()
        assert "clamscan" in mock_run.call_args[0][0]

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_init_fails_without_clamav(self, mock_run):
        """Test initialization fails when ClamAV is not available."""
        mock_run.side_effect = FileNotFoundError("clamscan not found")

        with pytest.raises(RuntimeError, match="ClamAV not available"):
            VirusScanner(timeout=60)

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_init_with_update(self, mock_run):
        """Test initialization with update_on_init flag."""
        mock_run.return_value = MagicMock(returncode=0)

        scanner = VirusScanner(timeout=60, update_on_init=True)

        # Should call clamscan --version and freshclam
        assert mock_run.call_count >= 2


class TestVirusScannerScanPackage:
    """Tests for scan_package method."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with mocked validation."""
        with patch("src.scanner.virus_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ClamAV 1.0.0")
            return VirusScanner(timeout=60)

    def test_scan_package_file_not_found(self, scanner):
        """Test scanning nonexistent package returns error result."""
        result = scanner.scan_package("/nonexistent/package.deb")

        assert not result.clean
        assert result.files_scanned == 0
        assert "not found" in result.error_message

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_scan_package_clean(self, mock_run, scanner, tmp_path):
        """Test scanning a clean package."""
        # Create test package
        pkg = tmp_path / "clean.deb"
        pkg.write_bytes(b"!<arch>\ntest content")

        # Mock successful scan with no threats
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"",
            stderr=b""
        )

        result = scanner.scan_package(str(pkg))

        assert result.clean
        assert result.threats_found == []
        assert result.error_message is None

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_scan_package_infected(self, mock_run, scanner, tmp_path):
        """Test scanning an infected package."""
        pkg = tmp_path / "infected.deb"
        pkg.write_bytes(b"!<arch>\neicar test")

        # Mock scan with threat found
        mock_run.return_value = MagicMock(
            returncode=1,  # Exit code 1 = virus found
            stdout=b"/path/to/file: Eicar-Test-Signature FOUND\n",
            stderr=b""
        )

        result = scanner.scan_package(str(pkg))

        assert not result.clean
        assert len(result.threats_found) == 1
        assert "Eicar-Test-Signature" in result.threats_found[0]

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_scan_package_scanner_error(self, mock_run, scanner, tmp_path):
        """Test handling scanner error (exit code 2)."""
        pkg = tmp_path / "error.deb"
        pkg.write_bytes(b"!<arch>\ntest")

        mock_run.return_value = MagicMock(
            returncode=2,  # Exit code 2 = error
            stdout=b"",
            stderr=b"Can't open database: No such file or directory"
        )

        result = scanner.scan_package(str(pkg))

        assert not result.clean
        assert "Scan error" in result.error_message

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_scan_package_timeout(self, mock_run, scanner, tmp_path):
        """Test handling scan timeout."""
        pkg = tmp_path / "timeout.deb"
        pkg.write_bytes(b"!<arch>\nlarge content")

        mock_run.side_effect = subprocess.TimeoutExpired("clamscan", 60)

        result = scanner.scan_package(str(pkg))

        assert not result.clean
        assert "timed out" in result.error_message


class TestVirusScannerScanDirectory:
    """Tests for scan_directory method."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with mocked validation."""
        with patch("src.scanner.virus_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ClamAV 1.0.0")
            return VirusScanner(timeout=60)

    def test_scan_directory_not_found(self, scanner):
        """Test scanning nonexistent directory returns error."""
        result = scanner.scan_directory("/nonexistent/dir")

        assert not result.clean
        assert "not found" in result.error_message

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_scan_directory_clean(self, mock_run, scanner, tmp_path):
        """Test scanning a clean directory."""
        # Create directory with files
        (tmp_path / "file1.txt").write_text("safe content")
        (tmp_path / "file2.txt").write_text("also safe")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"",
            stderr=b""
        )

        result = scanner.scan_directory(str(tmp_path))

        assert result.clean
        assert result.files_scanned >= 2

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_scan_directory_multiple_threats(self, mock_run, scanner, tmp_path):
        """Test scanning directory with multiple threats."""
        (tmp_path / "virus1.exe").write_bytes(b"malware")
        (tmp_path / "virus2.exe").write_bytes(b"trojan")

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=b"/path/virus1.exe: Trojan.GenericKD FOUND\n/path/virus2.exe: Win.Malware.Agent FOUND\n",
            stderr=b""
        )

        result = scanner.scan_directory(str(tmp_path))

        assert not result.clean
        assert len(result.threats_found) == 2


class TestVirusScannerResultParsing:
    """Tests for ClamAV output parsing."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked validation."""
        with patch("src.scanner.virus_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ClamAV 1.0.0")
            return VirusScanner(timeout=60)

    def test_parse_empty_output(self, scanner):
        """Test parsing empty scan output."""
        threats = scanner._parse_scan_output("")
        assert threats == []

    def test_parse_single_threat(self, scanner):
        """Test parsing output with single threat."""
        output = "/tmp/test.exe: Eicar-Test-Signature FOUND\n"
        threats = scanner._parse_scan_output(output)

        assert len(threats) == 1
        assert "Eicar-Test-Signature" in threats[0]

    def test_parse_multiple_threats(self, scanner):
        """Test parsing output with multiple threats."""
        output = """/tmp/file1.exe: Trojan.GenericKD FOUND
/tmp/file2.dll: Win.Malware.Agent FOUND
/tmp/file3.bat: Unix.Trojan.Generic FOUND
"""
        threats = scanner._parse_scan_output(output)

        assert len(threats) == 3
        assert any("Trojan" in t for t in threats)

    def test_parse_output_with_path_containing_colon(self, scanner):
        """Test parsing when file path contains colon."""
        output = "C:\\Users\\test\\file.exe: Win.Test FOUND\n"
        threats = scanner._parse_scan_output(output)

        assert len(threats) == 1


class TestVirusScannerDatabaseManagement:
    """Tests for database update and info methods."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked validation."""
        with patch("src.scanner.virus_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ClamAV 1.0.0")
            return VirusScanner(timeout=60)

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_update_definitions_success(self, mock_run, scanner):
        """Test successful virus definition update."""
        mock_run.return_value = MagicMock(returncode=0)

        result = scanner.update_definitions()

        assert result is True
        # Should stop clamd, run freshclam, start clamd
        assert mock_run.call_count >= 2

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_update_definitions_timeout(self, mock_run, scanner):
        """Test handling update timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("freshclam", 600)

        result = scanner.update_definitions()

        assert result is False

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_get_database_info_success(self, mock_run, scanner):
        """Test getting database information."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Build time: 01 Jan 2024\nVersion: 26500\n"
        )

        info = scanner.get_database_info()

        assert "Build time" in info or "Version" in info

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_get_database_info_failure(self, mock_run, scanner):
        """Test database info when sigtool fails."""
        mock_run.side_effect = FileNotFoundError("sigtool not found")

        info = scanner.get_database_info()

        assert info == {}


class TestVirusScannerVersionInfo:
    """Tests for scanner version retrieval."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked validation."""
        with patch("src.scanner.virus_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ClamAV 1.0.0")
            return VirusScanner(timeout=60)

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_get_scanner_version(self, mock_run, scanner):
        """Test getting scanner version."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"ClamAV 0.103.8/26860/Tue Apr 18 08:12:50 2023"
        )

        version = scanner._get_scanner_version()

        assert "0.103.8" in version

    @patch("src.scanner.virus_scanner.subprocess.run")
    def test_get_scanner_version_error(self, mock_run, scanner):
        """Test version retrieval when command fails."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "clamscan")

        version = scanner._get_scanner_version()

        assert version == "unknown"


class TestVirusScanResult:
    """Tests for VirusScanResult dataclass."""

    def test_clean_result(self):
        """Test creating a clean scan result."""
        result = VirusScanResult(
            clean=True,
            threats_found=[],
            files_scanned=10,
            scan_date=datetime.now().isoformat(),
            scanner_version="1.0.0"
        )

        assert result.clean
        assert result.threats_found == []
        assert result.error_message is None

    def test_infected_result(self):
        """Test creating an infected scan result."""
        result = VirusScanResult(
            clean=False,
            threats_found=["Eicar-Test-Signature", "Win.Malware.Generic"],
            files_scanned=5,
            scan_date=datetime.now().isoformat(),
            scanner_version="1.0.0"
        )

        assert not result.clean
        assert len(result.threats_found) == 2

    def test_error_result(self):
        """Test creating an error scan result."""
        result = VirusScanResult(
            clean=False,
            threats_found=[],
            files_scanned=0,
            scan_date=datetime.now().isoformat(),
            scanner_version="unknown",
            error_message="Scanner timeout"
        )

        assert not result.clean
        assert result.error_message is not None
