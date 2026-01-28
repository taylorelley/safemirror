"""Tests for RPM package format handler."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.formats.rpm import RpmPackageFormat
from src.formats.base import ScriptType


class TestRpmPackageFormat:
    """Tests for RpmPackageFormat class."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return RpmPackageFormat()

    def test_format_name(self, handler):
        """Test format name property."""
        assert handler.format_name == "rpm"

    def test_file_extensions(self, handler):
        """Test file extensions."""
        assert ".rpm" in handler.file_extensions

    def test_capabilities(self, handler):
        """Test capabilities."""
        caps = handler.capabilities
        assert caps.supports_vulnerability_scan
        assert caps.supports_virus_scan
        assert caps.supports_script_analysis
        assert caps.supports_binary_check
        assert caps.has_signature
        assert ScriptType.PRE_INSTALL in caps.script_types
        assert ScriptType.POST_INSTALL in caps.script_types
        assert caps.preferred_vulnerability_scanner == "trivy"

    def test_parse_filename_standard(self, handler):
        """Test parsing standard rpm filename."""
        name, version = handler.parse_filename("curl-7.76.1-14.el8.x86_64.rpm")
        assert name == "curl"
        assert version == "7.76.1"

    def test_parse_filename_noarch(self, handler):
        """Test parsing noarch rpm filename."""
        name, version = handler.parse_filename("python3-pip-22.0.2-1.fc37.noarch.rpm")
        assert name == "python3-pip"
        assert version == "22.0.2"

    def test_parse_filename_complex(self, handler):
        """Test parsing complex rpm filename."""
        name, version = handler.parse_filename("kernel-devel-5.14.0-284.25.1.el9_2.x86_64.rpm")
        assert name == "kernel-devel"
        assert version == "5.14.0"

    def test_script_type_map(self, handler):
        """Test script type mapping."""
        assert handler.SCRIPT_TYPE_MAP["prein"] == ScriptType.PRE_INSTALL
        assert handler.SCRIPT_TYPE_MAP["postin"] == ScriptType.POST_INSTALL
        assert handler.SCRIPT_TYPE_MAP["preun"] == ScriptType.PRE_REMOVE
        assert handler.SCRIPT_TYPE_MAP["postun"] == ScriptType.POST_REMOVE


class TestRpmPackageFormatIntegration:
    """Integration tests for RpmPackageFormat (mocked subprocess)."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return RpmPackageFormat()

    @pytest.fixture
    def rpm_file(self, tmp_path):
        """Create a mock rpm file with correct magic bytes."""
        rpm_path = tmp_path / "test-1.0.0-1.x86_64.rpm"
        # RPM magic bytes: ed ab ee db
        rpm_path.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 100)
        return rpm_path

    def test_detect_by_magic(self, handler, rpm_file):
        """Test detection by magic bytes."""
        assert handler.detect(rpm_file)

    def test_detect_wrong_magic(self, handler, tmp_path):
        """Test detection with wrong magic falls back to extension."""
        # RPM detection falls back to extension check, so .rpm files are detected
        wrong_file = tmp_path / "wrong.rpm"
        wrong_file.write_bytes(b"wrong magic bytes")
        # This returns True because the extension matches
        assert handler.detect(wrong_file)

    def test_detect_wrong_magic_wrong_ext(self, handler, tmp_path):
        """Test detection fails with wrong magic and wrong extension."""
        wrong_file = tmp_path / "wrong.txt"
        wrong_file.write_bytes(b"wrong magic bytes")
        assert not handler.detect(wrong_file)

    def test_detect_by_extension_fallback(self, handler, tmp_path):
        """Test detection falls back to extension."""
        # File that can't be read but has .rpm extension
        rpm_file = tmp_path / "test.rpm"
        rpm_file.write_bytes(b"corrupted")
        assert handler.detect(rpm_file)

    def test_detect_nonexistent(self, handler, tmp_path):
        """Test detection of nonexistent file."""
        assert not handler.detect(tmp_path / "nonexistent.rpm")

    @patch("subprocess.run")
    def test_parse_metadata(self, mock_run, handler, rpm_file):
        """Test metadata parsing with mocked rpm command."""
        mock_run.side_effect = [
            # First call: rpm -qp --queryformat
            MagicMock(
                returncode=0,
                stdout=b"curl\n7.76.1\n14.el8\nx86_64\nA utility for transferring data\nRed Hat\nhttps://curl.se/\nMIT\n",
            ),
            # Second call: rpm -qp --requires
            MagicMock(
                returncode=0,
                stdout=b"libc.so.6\nlibssl.so.1.1\n",
            ),
        ]

        metadata = handler.parse_metadata(rpm_file)

        assert metadata.name == "curl"
        assert metadata.version == "7.76.1"
        assert metadata.release == "14.el8"
        assert metadata.architecture == "x86_64"
        assert metadata.format_type == "rpm"
        assert "libc.so.6" in metadata.dependencies

    @patch("subprocess.run")
    def test_validate_integrity_valid(self, mock_run, handler, rpm_file):
        """Test integrity validation with valid rpm."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"test.rpm: digests OK",
            stderr=b"",
        )

        assert handler.validate_integrity(rpm_file)

    @patch("subprocess.run")
    def test_validate_integrity_failed(self, mock_run, handler, rpm_file):
        """Test integrity validation with corrupted rpm."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=b"test.rpm: DIGESTS NOT OK",
            stderr=b"",
        )

        assert not handler.validate_integrity(rpm_file)

    def test_validate_integrity_wrong_magic(self, handler, tmp_path):
        """Test integrity validation fails with wrong magic bytes."""
        bad_rpm = tmp_path / "bad.rpm"
        bad_rpm.write_bytes(b"not an rpm file")

        assert not handler.validate_integrity(bad_rpm)

    @patch("subprocess.run")
    def test_get_file_list(self, mock_run, handler, rpm_file):
        """Test getting file list."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"-rwxr-xr-x /usr/bin/curl\n-rw-r--r-- /usr/share/doc/curl/README\n",
            stderr=b"",
        )

        files = handler.get_file_list(rpm_file)

        assert len(files) == 2
        assert files[0].path == "usr/bin/curl"
        assert files[0].permissions == "-rwxr-xr-x"
        assert files[1].path == "usr/share/doc/curl/README"

    @patch("subprocess.run")
    def test_extract_scripts(self, mock_run, handler, rpm_file):
        """Test script extraction."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"""prein scriptlet (using /bin/sh):
echo "Installing..."
postin scriptlet (using /bin/sh):
systemctl start myservice
""",
            stderr=b"",
        )

        scripts = handler._extract_scripts(rpm_file)

        assert len(scripts) >= 2
        # Script names match the SCRIPT_TYPE_MAP keys (prein, postin, etc.)
        prein = [s for s in scripts if s.name == "prein"][0]
        assert prein.script_type == ScriptType.PRE_INSTALL
        assert "Installing" in prein.content

    def test_parse_scripts_output(self, handler):
        """Test parsing rpm --scripts output."""
        # RPM uses short script names like prein, postin
        output = """prein scriptlet (using /bin/sh):
echo "Pre-install"

postin scriptlet (using /bin/bash):
systemctl daemon-reload
systemctl start nginx
"""
        scripts = handler._parse_scripts_output(output)

        assert len(scripts) == 2
        # Script names match the SCRIPT_TYPE_MAP keys
        assert scripts[0].name == "prein"
        assert scripts[0].interpreter == "/bin/sh"
        assert scripts[1].name == "postin"
        assert scripts[1].interpreter == "/bin/bash"


class TestRpmFileListParsing:
    """Test RPM file list parsing."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return RpmPackageFormat()

    def test_parse_file_list_basic(self, handler):
        """Test basic file list parsing."""
        output = """-rwxr-xr-x /usr/bin/curl
-rw-r--r-- /etc/curl.conf
drwxr-xr-x /usr/share/doc/curl
"""
        files = handler._parse_file_list(output)

        assert len(files) == 3
        assert files[0].path == "usr/bin/curl"
        assert files[0].permissions == "-rwxr-xr-x"
        assert files[0].file_type == "-"

        assert files[2].path == "usr/share/doc/curl"
        assert files[2].file_type == "d"

    def test_parse_file_list_symlink(self, handler):
        """Test parsing symlinks."""
        output = """lrwxrwxrwx /usr/bin/link -> target
"""
        files = handler._parse_file_list(output)

        assert len(files) == 1
        assert files[0].file_type == "l"

    def test_parse_file_list_no_perms(self, handler):
        """Test parsing when permissions are missing."""
        output = """/usr/bin/curl
/etc/curl.conf
"""
        files = handler._parse_file_list(output)

        assert len(files) == 2
        assert files[0].path == "usr/bin/curl"
        assert files[0].permissions == "-rw-r--r--"  # Default
