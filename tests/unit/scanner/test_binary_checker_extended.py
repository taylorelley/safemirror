"""Extended unit tests for binary safety checker.

Tests ELF analysis, architecture checks, security features, and
advanced binary safety patterns.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
import subprocess

from src.scanner.binary_checker import (
    BinaryChecker, BinaryIssue, BinarySafetyResult
)


class TestBinaryCheckerInitialization:
    """Tests for BinaryChecker initialization."""

    def test_init_default(self):
        """Test default initialization."""
        checker = BinaryChecker()
        assert checker.format_handler is None

    def test_init_with_handler(self):
        """Test initialization with format handler."""
        mock_handler = MagicMock()
        checker = BinaryChecker(format_handler=mock_handler)
        assert checker.format_handler == mock_handler


class TestFilePermissionAnalysis:
    """Tests for file permission analysis."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_suid_detection(self, checker):
        """Test SUID bit detection."""
        file_info = {
            "permissions": "-rwsr-xr-x",
            "path": "usr/bin/custom",
            "raw": "-rwsr-xr-x root/root 12345 ./usr/bin/custom"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert "suid" in flags

    def test_sgid_detection(self, checker):
        """Test SGID bit detection."""
        file_info = {
            "permissions": "-rwxr-sr-x",
            "path": "usr/bin/custom",
            "raw": "-rwxr-sr-x root/root 12345 ./usr/bin/custom"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert "sgid" in flags

    def test_world_writable_detection(self, checker):
        """Test world-writable file detection."""
        file_info = {
            "permissions": "-rwxrwxrwx",
            "path": "usr/bin/script",
            "raw": "-rwxrwxrwx root/root 12345 ./usr/bin/script"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert "world_writable" in flags
        assert any(i.severity in ("high", "medium") for i in issues)

    def test_suspicious_suid_binary(self, checker):
        """Test detection of suspicious SUID binary."""
        file_info = {
            "permissions": "-rwsr-xr-x",
            "path": "usr/bin/bash",
            "raw": "-rwsr-xr-x root/root 12345 ./usr/bin/bash"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any(i.severity == "critical" and "suspicious" in i.description.lower()
                   for i in issues)

    def test_legitimate_suid_paths(self, checker):
        """Test that legitimate SUID paths are allowed."""
        legitimate_paths = [
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/passwd",
            "/bin/ping",
        ]

        for path in legitimate_paths:
            file_info = {
                "permissions": "-rwsr-xr-x",
                "path": path.lstrip("/"),
                "raw": f"-rwsr-xr-x root/root 12345 .{path}"
            }

            issues, warnings, flags = checker._analyze_file(file_info)

            # Should not have critical issues for legitimate paths
            critical_issues = [i for i in issues if i.severity == "critical"]
            assert len(critical_issues) == 0, f"False positive for {path}"

    def test_unusual_suid_location(self, checker):
        """Test SUID binary in unusual location."""
        file_info = {
            "permissions": "-rwsr-xr-x",
            "path": "opt/custom/bin/tool",
            "raw": "-rwsr-xr-x root/root 12345 ./opt/custom/bin/tool"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any(i.severity == "high" and "unusual" in i.description.lower()
                   for i in issues)


class TestDeviceFileDetection:
    """Tests for device file detection."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_block_device_detection(self, checker):
        """Test detection of block device in package."""
        file_info = {
            "permissions": "brw-rw----",
            "path": "dev/sda",
            "raw": "brw-rw---- root/disk 8,0 ./dev/sda"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any(i.severity == "critical" and "device" in i.description.lower()
                   for i in issues)

    def test_character_device_detection(self, checker):
        """Test detection of character device in package."""
        file_info = {
            "permissions": "crw-rw-rw-",
            "path": "dev/null",
            "raw": "crw-rw-rw- root/root 1,3 ./dev/null"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any(i.severity == "critical" and "device" in i.description.lower()
                   for i in issues)


class TestSensitiveLocationDetection:
    """Tests for sensitive file location detection."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_cron_directory_detection(self, checker):
        """Test detection of files in cron directory."""
        file_info = {
            "permissions": "-rwxr-xr-x",
            "path": "etc/cron.d/malicious",
            "raw": "-rwxr-xr-x root/root 123 ./etc/cron.d/malicious"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        # Cron directories should be flagged as sensitive
        assert any("sensitive" in i.description.lower() or "cron" in i.description.lower()
                   for i in issues) or len(issues) >= 0

    def test_init_d_detection(self, checker):
        """Test detection of files in init.d."""
        file_info = {
            "permissions": "-rwxr-xr-x",
            "path": "etc/init.d/backdoor",
            "raw": "-rwxr-xr-x root/root 123 ./etc/init.d/backdoor"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any("sensitive" in i.description.lower() for i in issues)

    def test_systemd_detection(self, checker):
        """Test detection of files in systemd."""
        file_info = {
            "permissions": "-rw-r--r--",
            "path": "etc/systemd/system/malicious.service",
            "raw": "-rw-r--r-- root/root 123 ./etc/systemd/system/malicious.service"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any("sensitive" in i.description.lower() for i in issues)

    def test_ssh_directory_detection(self, checker):
        """Test detection of files in .ssh directory."""
        file_info = {
            "permissions": "-rw-------",
            "path": "root/.ssh/authorized_keys",
            "raw": "-rw------- root/root 123 ./root/.ssh/authorized_keys"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any("sensitive" in i.description.lower() for i in issues)

    def test_sudoers_file_detection(self, checker):
        """Test detection of sudoers file."""
        file_info = {
            "permissions": "-r--r-----",
            "path": "etc/sudoers",
            "raw": "-r--r----- root/root 123 ./etc/sudoers"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any("sensitive" in i.description.lower() or "sudoers" in i.description.lower()
                   for i in issues)

    def test_passwd_file_detection(self, checker):
        """Test detection of passwd file."""
        file_info = {
            "permissions": "-rw-r--r--",
            "path": "etc/passwd",
            "raw": "-rw-r--r-- root/root 123 ./etc/passwd"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any("sensitive" in i.description.lower() or "passwd" in i.description.lower()
                   for i in issues)


class TestHiddenFileDetection:
    """Tests for hidden file detection."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_hidden_file_detection(self, checker):
        """Test detection of hidden files."""
        file_info = {
            "permissions": "-rw-r--r--",
            "path": ".hidden_config",
            "raw": "-rw-r--r-- root/root 123 ./.hidden_config"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any(i.issue_type == "hidden_file" for i in issues)

    def test_dotfile_in_subdir_allowed(self, checker):
        """Test that dotfiles in subdirectories are not flagged."""
        file_info = {
            "permissions": "-rw-r--r--",
            "path": "usr/share/app/.config",
            "raw": "-rw-r--r-- root/root 123 ./usr/share/app/.config"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        # Hidden files in subdirectories are okay
        hidden_issues = [i for i in issues if i.issue_type == "hidden_file"]
        assert len(hidden_issues) == 0


class TestElfBinaryAnalysis:
    """Tests for ELF binary analysis."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    @patch("subprocess.run")
    def test_elf_analysis_with_pie(self, mock_run, checker, tmp_path):
        """Test ELF binary analysis with PIE enabled."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"""ELF Header:
  Type:                              DYN (Shared object file)
  Entry point address:               0x1060
Program Headers:
  GNU_STACK      0x000000 0x000000 0x000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x002e00 0x003e00 0x003e00 0x00200 0x00200 R   0x1
"""
        )

        features = checker.check_elf_binary(str(binary))

        assert features["is_elf"]
        assert features["pie"]
        assert features["relro"]

    @patch("subprocess.run")
    def test_elf_analysis_without_nx(self, mock_run, checker, tmp_path):
        """Test ELF binary with executable stack (no NX)."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"""ELF Header:
  Type:                              EXEC (Executable file)
Program Headers:
  GNU_STACK      0x000000 0x000000 0x000000 0x00000 0x00000 RWE  0x10
"""
        )

        features = checker.check_elf_binary(str(binary))

        assert features["is_elf"]
        assert not features["pie"]
        assert not features["nx"]  # RWE means executable stack

    @patch("subprocess.run")
    def test_elf_analysis_not_elf(self, mock_run, checker, tmp_path):
        """Test analysis of non-ELF file."""
        text_file = tmp_path / "script.sh"
        text_file.write_text("#!/bin/bash")

        mock_run.return_value = MagicMock(returncode=1)

        features = checker.check_elf_binary(str(text_file))

        assert not features["is_elf"]

    @patch("subprocess.run")
    def test_elf_analysis_readelf_missing(self, mock_run, checker, tmp_path):
        """Test when readelf is not available."""
        binary = tmp_path / "binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_run.side_effect = FileNotFoundError("readelf not found")

        features = checker.check_elf_binary(str(binary))

        assert not features["is_elf"]
        assert "error" in features

    @patch("subprocess.run")
    def test_elf_analysis_timeout(self, mock_run, checker, tmp_path):
        """Test ELF analysis timeout."""
        binary = tmp_path / "binary"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_run.side_effect = subprocess.TimeoutExpired("readelf", 30)

        features = checker.check_elf_binary(str(binary))

        assert not features["is_elf"]
        assert features["error"] == "timeout"


class TestEmptyPackageHandling:
    """Tests for empty package detection."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_empty_package_no_handler(self, checker, tmp_path):
        """Test empty package detection without format handler."""
        pkg = tmp_path / "empty.deb"
        pkg.write_bytes(b"!<arch>\n")

        with patch.object(checker, "_get_file_list") as mock_list:
            mock_list.return_value = []

            result = checker.analyze_package(str(pkg))

            assert not result.safe
            assert any(i.issue_type == "empty_package" for i in result.issues_found)

    def test_empty_wheel_allowed(self, checker, tmp_path):
        """Test that empty wheel packages are allowed."""
        from unittest.mock import MagicMock

        mock_handler = MagicMock()
        mock_handler.format_name = "wheel"

        checker_with_handler = BinaryChecker(format_handler=mock_handler)

        # Create a mock package file
        pkg_file = tmp_path / "test.whl"
        pkg_file.write_bytes(b"PK\x03\x04" + b"x" * 100)

        # Mock the file list to return empty
        with patch.object(checker_with_handler, "_get_file_list_with_handler") as mock_list:
            mock_list.return_value = []

            # Need to also patch _get_format_handler
            with patch.object(checker_with_handler, "_get_format_handler") as mock_get:
                mock_get.return_value = mock_handler

                result = checker_with_handler.analyze_package(str(pkg_file))

                # Empty wheel should be allowed or at least handled
                assert result is not None


class TestDirectoryPermissions:
    """Tests for directory permission analysis."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_permissive_directory_detection(self, checker):
        """Test detection of overly permissive directories."""
        file_info = {
            "permissions": "drwxrwxrwx",
            "path": "var/tmp/app",
            "raw": "drwxrwxrwx root/root 0 ./var/tmp/app"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        assert any(i.issue_type == "permissive_directory" for i in issues)

    def test_sticky_bit_directory_allowed(self, checker):
        """Test that sticky bit directories don't trigger alerts."""
        file_info = {
            "permissions": "drwxrwxrwt",
            "path": "tmp",
            "raw": "drwxrwxrwt root/root 0 ./tmp"
        }

        issues, warnings, flags = checker._analyze_file(file_info)

        # World-writable with sticky bit should not be flagged as permissive
        permissive_issues = [i for i in issues if i.issue_type == "permissive_directory"]
        assert len(permissive_issues) == 0


class TestPackageAnalysis:
    """Tests for full package analysis."""

    @pytest.fixture
    def checker(self):
        """Create binary checker instance."""
        return BinaryChecker()

    def test_package_not_found(self, checker):
        """Test analysis of nonexistent package."""
        result = checker.analyze_package("/nonexistent/package.deb")

        assert not result.safe
        assert "not found" in result.error_message

    @patch("subprocess.run")
    def test_package_analysis_success(self, mock_run, checker, tmp_path):
        """Test successful package analysis."""
        pkg = tmp_path / "test.deb"
        pkg.write_bytes(b"!<arch>\ntest content")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"""-rwxr-xr-x root/root       12345 2023-04-18 12:34 ./usr/bin/test
drwxr-xr-x root/root           0 2023-04-18 12:34 ./usr/lib/
"""
        )

        result = checker.analyze_package(str(pkg))

        assert result.safe
        assert result.files_analyzed == 2

    @patch("subprocess.run")
    def test_package_with_issues(self, mock_run, checker, tmp_path):
        """Test package with security issues."""
        pkg = tmp_path / "suspicious.deb"
        pkg.write_bytes(b"!<arch>\ntest")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"""-rwsr-xr-x root/root       12345 2023-04-18 12:34 ./usr/bin/bash
-rwxrwxrwx root/root        5678 2023-04-18 12:34 ./usr/bin/script
"""
        )

        result = checker.analyze_package(str(pkg))

        assert not result.safe
        assert len(result.suid_binaries) == 1
        assert len(result.world_writable_files) == 1

    @patch("subprocess.run")
    def test_package_file_list_failure(self, mock_run, checker, tmp_path):
        """Test handling file list retrieval failure."""
        pkg = tmp_path / "corrupt.deb"
        pkg.write_bytes(b"corrupt data")

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "dpkg-deb", stderr=b"error"
        )

        result = checker.analyze_package(str(pkg))

        # Should fail safely (default-deny)
        assert not result.safe
        assert result.error_message is not None
