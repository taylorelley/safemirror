"""Tests for Debian package format handler."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
import subprocess

from src.formats.deb import DebPackageFormat
from src.formats.base import ScriptType, FormatCapabilities


class TestDebPackageFormat:
    """Tests for DebPackageFormat class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.handler = DebPackageFormat()

    def test_format_name(self):
        """Test format name property."""
        assert self.handler.format_name == "deb"

    def test_file_extensions(self):
        """Test file extensions property."""
        extensions = self.handler.file_extensions
        assert ".deb" in extensions
        assert ".udeb" in extensions

    def test_capabilities(self):
        """Test capabilities property."""
        caps = self.handler.capabilities
        assert isinstance(caps, FormatCapabilities)
        assert caps.supports_vulnerability_scan
        assert caps.supports_virus_scan
        assert caps.supports_integrity_check
        assert caps.supports_script_analysis
        assert caps.supports_binary_check
        assert caps.has_maintainer_scripts
        assert caps.has_binary_content
        assert caps.preferred_vulnerability_scanner == "trivy"
        assert ScriptType.POST_INSTALL in caps.script_types

    def test_detect_by_magic(self, tmp_path):
        """Test detection by ar archive magic bytes."""
        # Create file with ar magic
        deb_file = tmp_path / "test.deb"
        deb_file.write_bytes(b"!<arch>\n" + b"x" * 100)

        assert self.handler.detect(deb_file)

    def test_detect_by_extension(self, tmp_path):
        """Test detection by .deb extension."""
        # Create file without ar magic but with .deb extension
        deb_file = tmp_path / "test.deb"
        deb_file.write_bytes(b"not ar magic" + b"x" * 100)

        # Should detect by extension when magic fails
        assert self.handler.detect(deb_file)

    def test_detect_nonexistent(self, tmp_path):
        """Test detection of nonexistent file."""
        nonexistent = tmp_path / "nonexistent.deb"
        assert not self.handler.detect(nonexistent)

    def test_detect_wrong_format(self, tmp_path):
        """Test detection of wrong format."""
        rpm_file = tmp_path / "test.rpm"
        rpm_file.write_bytes(b"\xed\xab\xee\xdb" + b"x" * 100)

        assert not self.handler.detect(rpm_file)

    def test_parse_filename_standard(self):
        """Test parsing standard .deb filename."""
        name, version = self.handler.parse_filename("curl_7.81.0-1ubuntu1.16_amd64.deb")
        assert name == "curl"
        assert version == "7.81.0-1ubuntu1.16"

    def test_parse_filename_simple(self):
        """Test parsing simple .deb filename."""
        name, version = self.handler.parse_filename("test_1.0_all.deb")
        assert name == "test"
        assert version == "1.0"

    def test_parse_filename_no_underscore(self):
        """Test parsing filename without underscores."""
        name, version = self.handler.parse_filename("package.deb")
        assert name == "package"
        assert version == "unknown"

    def test_parse_control_content(self):
        """Test parsing control file content."""
        control = """Package: test-package
Version: 1.2.3-4ubuntu5
Architecture: amd64
Maintainer: Test User <test@example.com>
Description: A test package
 This is a longer description
 spanning multiple lines.
Depends: libc6 (>= 2.17), libssl1.1
Homepage: https://example.com
"""
        metadata = self.handler._parse_control_content(control, "test.deb")

        assert metadata.name == "test-package"
        assert metadata.version == "1.2.3-4ubuntu5"
        assert metadata.architecture == "amd64"
        assert metadata.maintainer == "Test User <test@example.com>"
        assert "A test package" in metadata.description
        assert metadata.homepage == "https://example.com"
        assert "libc6 (>= 2.17)" in metadata.dependencies

    def test_parse_file_list(self):
        """Test parsing dpkg-deb -c output."""
        output = """-rwxr-xr-x root/root       12345 2023-04-18 12:34 ./usr/bin/test
drwxr-xr-x root/root           0 2023-04-18 12:34 ./usr/lib/
-rw-r--r-- root/root        5678 2023-04-18 12:34 ./usr/lib/libtest.so
lrwxrwxrwx root/root           0 2023-04-18 12:34 ./usr/lib/libtest.so.1 -> libtest.so
"""
        file_list = self.handler._parse_file_list(output)

        assert len(file_list) == 4

        # Check first file (binary)
        assert file_list[0].path == "usr/bin/test"
        assert file_list[0].permissions == "-rwxr-xr-x"
        assert file_list[0].size == 12345
        assert file_list[0].owner == "root"
        assert file_list[0].group == "root"
        assert file_list[0].file_type == "-"

        # Check directory
        assert file_list[1].path == "usr/lib/"
        assert file_list[1].file_type == "d"

        # Check symlink
        assert file_list[3].path == "usr/lib/libtest.so.1"
        assert file_list[3].link_target == "libtest.so"
        assert file_list[3].file_type == "l"

    def test_parse_file_list_suid(self):
        """Test parsing files with SUID/SGID bits."""
        output = """-rwsr-xr-x root/root       12345 2023-04-18 12:34 ./usr/bin/sudo
-rwxr-sr-x root/root        5678 2023-04-18 12:34 ./usr/bin/write
"""
        file_list = self.handler._parse_file_list(output)

        assert len(file_list) == 2
        assert file_list[0].is_suid
        assert not file_list[0].is_sgid
        assert not file_list[1].is_suid
        assert file_list[1].is_sgid


class TestDebPackageFormatIntegration:
    """Integration tests for DebPackageFormat (require dpkg-deb)."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return DebPackageFormat()

    @pytest.fixture
    def mock_dpkg_deb(self):
        """Mock dpkg-deb subprocess calls."""
        with patch("subprocess.run") as mock_run:
            yield mock_run

    def test_validate_integrity_valid(self, handler, mock_dpkg_deb, tmp_path):
        """Test integrity validation of valid package."""
        # Create mock deb file with ar magic
        deb_file = tmp_path / "test.deb"
        deb_file.write_bytes(b"!<arch>\n" + b"x" * 100)

        # Mock dpkg-deb --info success
        mock_dpkg_deb.return_value = MagicMock(returncode=0)

        assert handler.validate_integrity(deb_file)

    def test_validate_integrity_invalid_magic(self, handler, tmp_path):
        """Test integrity validation with invalid magic bytes."""
        deb_file = tmp_path / "test.deb"
        deb_file.write_bytes(b"not ar archive")

        assert not handler.validate_integrity(deb_file)

    def test_validate_integrity_empty_file(self, handler, tmp_path):
        """Test integrity validation of empty file."""
        deb_file = tmp_path / "test.deb"
        deb_file.write_bytes(b"")

        assert not handler.validate_integrity(deb_file)

    def test_validate_integrity_nonexistent(self, handler, tmp_path):
        """Test integrity validation of nonexistent file."""
        nonexistent = tmp_path / "nonexistent.deb"

        with pytest.raises(RuntimeError, match="not found"):
            handler.validate_integrity(nonexistent)

    def test_parse_metadata_success(self, handler, mock_dpkg_deb):
        """Test successful metadata parsing."""
        mock_dpkg_deb.return_value = MagicMock(
            returncode=0,
            stdout=b"""Package: test-package
Version: 1.0.0
Architecture: amd64
Maintainer: Test <test@example.com>
Description: Test package
"""
        )

        metadata = handler.parse_metadata(Path("/tmp/test.deb"))

        assert metadata.name == "test-package"
        assert metadata.version == "1.0.0"
        assert metadata.architecture == "amd64"
        assert metadata.format_type == "deb"

    def test_parse_metadata_failure(self, handler, mock_dpkg_deb):
        """Test metadata parsing failure."""
        mock_dpkg_deb.side_effect = subprocess.CalledProcessError(
            1, "dpkg-deb", stderr=b"error"
        )

        with pytest.raises(RuntimeError, match="Failed to read control file"):
            handler.parse_metadata(Path("/tmp/test.deb"))

    def test_get_file_list_success(self, handler, mock_dpkg_deb):
        """Test successful file listing."""
        mock_dpkg_deb.return_value = MagicMock(
            returncode=0,
            stdout=b"""-rwxr-xr-x root/root       12345 2023-04-18 12:34 ./usr/bin/test
drwxr-xr-x root/root           0 2023-04-18 12:34 ./usr/lib/
"""
        )

        file_list = handler.get_file_list(Path("/tmp/test.deb"))

        assert len(file_list) == 2
        mock_dpkg_deb.assert_called_once()

    def test_get_file_list_failure(self, handler, mock_dpkg_deb):
        """Test file listing failure."""
        mock_dpkg_deb.side_effect = subprocess.CalledProcessError(
            1, "dpkg-deb", stderr=b"error"
        )

        with pytest.raises(RuntimeError, match="Failed to list package contents"):
            handler.get_file_list(Path("/tmp/test.deb"))

    def test_extract_scripts_success(self, handler, mock_dpkg_deb, tmp_path):
        """Test successful script extraction."""
        # This test uses the actual temp directory mechanism
        def mock_run(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            if "dpkg-deb" in cmd and "-e" in cmd:
                # Extract control to temp dir
                dest_dir = cmd[-1]
                postinst = Path(dest_dir) / "postinst"
                postinst.write_text("#!/bin/bash\necho 'Hello'")
                return MagicMock(returncode=0)
            return MagicMock(returncode=0, stdout=b"")

        mock_dpkg_deb.side_effect = mock_run

        scripts = handler._extract_scripts(Path("/tmp/test.deb"))

        # Should find the postinst script
        assert len(scripts) == 1
        assert scripts[0].name == "postinst"
        assert scripts[0].script_type == ScriptType.POST_INSTALL
        assert scripts[0].interpreter == "/bin/bash"
        assert "echo 'Hello'" in scripts[0].content
