"""Tests for Alpine APK package format handler."""

import pytest
import tarfile
from pathlib import Path
from io import BytesIO

from src.formats.apk import ApkPackageFormat
from src.formats.base import ScriptType


class TestApkPackageFormat:
    """Tests for ApkPackageFormat class."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return ApkPackageFormat()

    def test_format_name(self, handler):
        """Test format name property."""
        assert handler.format_name == "apk"

    def test_file_extensions(self, handler):
        """Test file extensions."""
        assert ".apk" in handler.file_extensions

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
        """Test parsing standard apk filename."""
        name, version = handler.parse_filename("curl-7.83.1-r0.apk")
        assert name == "curl"
        assert version == "7.83.1"

    def test_parse_filename_complex(self, handler):
        """Test parsing complex apk filename."""
        name, version = handler.parse_filename("python3-3.10.5-r0.apk")
        assert name == "python3"
        assert version == "3.10.5"

    def test_parse_filename_dashed_name(self, handler):
        """Test parsing filename with dashes in name."""
        name, version = handler.parse_filename("ca-certificates-20220614-r0.apk")
        assert name == "ca-certificates"
        assert version == "20220614"

    def test_script_type_map(self, handler):
        """Test script type mapping."""
        assert handler.SCRIPT_TYPE_MAP[".pre-install"] == ScriptType.PRE_INSTALL
        assert handler.SCRIPT_TYPE_MAP[".post-install"] == ScriptType.POST_INSTALL
        assert handler.SCRIPT_TYPE_MAP[".pre-deinstall"] == ScriptType.PRE_REMOVE
        assert handler.SCRIPT_TYPE_MAP[".post-deinstall"] == ScriptType.POST_REMOVE


class TestApkPackageFormatIntegration:
    """Integration tests for ApkPackageFormat."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return ApkPackageFormat()

    @pytest.fixture
    def sample_apk(self, tmp_path):
        """Create a sample APK file."""
        apk_path = tmp_path / "sample-1.0.0-r0.apk"

        with tarfile.open(apk_path, "w:gz") as tar:
            # Add .PKGINFO
            pkginfo = b"""pkgname = sample
pkgver = 1.0.0-r0
pkgdesc = A sample package
url = https://example.com
license = MIT
arch = x86_64
maintainer = Test <test@example.com>
depend = musl
depend = libcurl
"""
            info = tarfile.TarInfo(name=".PKGINFO")
            info.size = len(pkginfo)
            tar.addfile(info, BytesIO(pkginfo))

            # Add a binary
            binary = b"ELF binary content"
            info = tarfile.TarInfo(name="usr/bin/sample")
            info.size = len(binary)
            info.mode = 0o755
            tar.addfile(info, BytesIO(binary))

            # Add a directory
            info = tarfile.TarInfo(name="usr/share/doc/sample")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tar.addfile(info)

        return apk_path

    @pytest.fixture
    def apk_with_scripts(self, tmp_path):
        """Create an APK with install scripts."""
        apk_path = tmp_path / "scripted-1.0.0-r0.apk"

        with tarfile.open(apk_path, "w:gz") as tar:
            pkginfo = b"pkgname = scripted\npkgver = 1.0.0-r0\n"
            info = tarfile.TarInfo(name=".PKGINFO")
            info.size = len(pkginfo)
            tar.addfile(info, BytesIO(pkginfo))

            # Add pre-install script
            pre_install = b"""#!/bin/sh
echo "Pre-installing..."
"""
            info = tarfile.TarInfo(name=".pre-install")
            info.size = len(pre_install)
            tar.addfile(info, BytesIO(pre_install))

            # Add post-install script
            post_install = b"""#!/bin/sh
/sbin/ldconfig
"""
            info = tarfile.TarInfo(name=".post-install")
            info.size = len(post_install)
            tar.addfile(info, BytesIO(post_install))

        return apk_path

    def test_detect_valid_apk(self, handler, sample_apk):
        """Test detecting valid APK."""
        assert handler.detect(sample_apk)

    def test_detect_nonexistent(self, handler, tmp_path):
        """Test detecting nonexistent file."""
        assert not handler.detect(tmp_path / "nonexistent.apk")

    def test_detect_wrong_extension(self, handler, tmp_path):
        """Test detecting file with wrong extension."""
        wrong_ext = tmp_path / "test.rpm"
        wrong_ext.write_text("not an apk")
        assert not handler.detect(wrong_ext)

    def test_detect_by_extension_fallback(self, handler, tmp_path):
        """Test detection falls back to extension."""
        apk_file = tmp_path / "test.apk"
        apk_file.write_bytes(b"some content")
        assert handler.detect(apk_file)

    def test_parse_metadata(self, handler, sample_apk):
        """Test metadata parsing."""
        metadata = handler.parse_metadata(sample_apk)

        assert metadata.name == "sample"
        assert metadata.version == "1.0.0"
        assert metadata.release == "0"
        assert metadata.format_type == "apk"
        assert metadata.architecture == "x86_64"
        assert metadata.description == "A sample package"
        assert metadata.homepage == "https://example.com"
        assert metadata.license == "MIT"
        assert "musl" in metadata.dependencies
        assert "libcurl" in metadata.dependencies

    def test_validate_integrity_valid(self, handler, sample_apk):
        """Test integrity validation of valid APK."""
        assert handler.validate_integrity(sample_apk)

    def test_validate_integrity_missing_pkginfo(self, handler, tmp_path):
        """Test integrity validation fails without .PKGINFO."""
        apk_path = tmp_path / "invalid-1.0.0-r0.apk"

        with tarfile.open(apk_path, "w:gz") as tar:
            readme = b"No PKGINFO"
            info = tarfile.TarInfo(name="README")
            info.size = len(readme)
            tar.addfile(info, BytesIO(readme))

        assert not handler.validate_integrity(apk_path)

    def test_validate_integrity_not_gzip(self, handler, tmp_path):
        """Test integrity validation fails for non-gzip file."""
        apk_path = tmp_path / "notgzip.apk"
        apk_path.write_text("not a gzip file")

        assert not handler.validate_integrity(apk_path)

    def test_get_file_list(self, handler, sample_apk):
        """Test getting file list."""
        files = handler.get_file_list(sample_apk)

        assert len(files) >= 2
        paths = [f.path for f in files]
        assert any("usr/bin/sample" in p for p in paths)

    def test_extract(self, handler, sample_apk, tmp_path):
        """Test extraction."""
        dest = tmp_path / "extracted"
        result = handler.extract(sample_apk, dest)

        assert result.extract_path == dest
        assert result.metadata.name == "sample"
        assert result.metadata.version == "1.0.0"
        assert len(result.file_list) > 0

        # Check files were actually extracted
        assert (dest / "data" / "usr" / "bin" / "sample").exists()

    def test_extract_with_scripts(self, handler, apk_with_scripts, tmp_path):
        """Test extraction captures install scripts."""
        dest = tmp_path / "extracted"
        result = handler.extract(apk_with_scripts, dest)

        assert len(result.scripts) == 2

        pre_install = [s for s in result.scripts if s.name == ".pre-install"][0]
        assert pre_install.script_type == ScriptType.PRE_INSTALL
        assert "Pre-installing" in pre_install.content
        assert pre_install.interpreter == "/bin/sh"

        post_install = [s for s in result.scripts if s.name == ".post-install"][0]
        assert post_install.script_type == ScriptType.POST_INSTALL


class TestApkPkginfoParsing:
    """Test .PKGINFO parsing."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return ApkPackageFormat()

    def test_parse_pkginfo_full(self, handler):
        """Test parsing full .PKGINFO content."""
        content = """pkgname = curl
pkgver = 7.83.1-r0
pkgdesc = A command line tool for transferring data
url = https://curl.se/
license = MIT
arch = x86_64
maintainer = Someone <someone@example.com>
depend = musl
depend = libcurl
depend = ca-certificates
"""
        metadata = handler._parse_pkginfo(content, "curl-7.83.1-r0.apk")

        assert metadata.name == "curl"
        assert metadata.version == "7.83.1"
        assert metadata.release == "0"
        assert len(metadata.dependencies) == 3
        assert "musl" in metadata.dependencies

    def test_parse_pkginfo_minimal(self, handler):
        """Test parsing minimal .PKGINFO."""
        content = """pkgname = minimal
pkgver = 1.0-r0
"""
        metadata = handler._parse_pkginfo(content, "minimal-1.0-r0.apk")

        assert metadata.name == "minimal"
        assert metadata.version == "1.0"

    def test_parse_pkginfo_with_comments(self, handler):
        """Test parsing .PKGINFO with comments."""
        content = """# Generated by abuild
pkgname = sample
# version info
pkgver = 2.0-r1
"""
        metadata = handler._parse_pkginfo(content, "sample-2.0-r1.apk")

        assert metadata.name == "sample"
        assert metadata.version == "2.0"


class TestApkSuspiciousPaths:
    """Test security checks for suspicious paths."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return ApkPackageFormat()

    def test_validate_rejects_path_traversal(self, handler, tmp_path):
        """Test that path traversal is rejected."""
        apk_path = tmp_path / "evil-1.0.0-r0.apk"

        with tarfile.open(apk_path, "w:gz") as tar:
            pkginfo = b"pkgname = evil\npkgver = 1.0.0-r0\n"
            info = tarfile.TarInfo(name=".PKGINFO")
            info.size = len(pkginfo)
            tar.addfile(info, BytesIO(pkginfo))

            malicious = b"malicious content"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(malicious)
            tar.addfile(info, BytesIO(malicious))

        assert not handler.validate_integrity(apk_path)

    def test_validate_rejects_absolute_path(self, handler, tmp_path):
        """Test that absolute paths are rejected."""
        apk_path = tmp_path / "evil-1.0.0-r0.apk"

        with tarfile.open(apk_path, "w:gz") as tar:
            pkginfo = b"pkgname = evil\npkgver = 1.0.0-r0\n"
            info = tarfile.TarInfo(name=".PKGINFO")
            info.size = len(pkginfo)
            tar.addfile(info, BytesIO(pkginfo))

            malicious = b"malicious content"
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = len(malicious)
            tar.addfile(info, BytesIO(malicious))

        assert not handler.validate_integrity(apk_path)


class TestApkModeConversion:
    """Test permission mode conversion."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return ApkPackageFormat()

    def test_mode_755_dir(self, handler):
        """Test converting 0o755 directory mode."""
        perms = handler._mode_to_permissions(0o755, True)
        assert perms == "drwxr-xr-x"

    def test_mode_755_file(self, handler):
        """Test converting 0o755 file mode."""
        perms = handler._mode_to_permissions(0o755, False)
        assert perms == "-rwxr-xr-x"

    def test_mode_644(self, handler):
        """Test converting 0o644 mode."""
        perms = handler._mode_to_permissions(0o644, False)
        assert perms == "-rw-r--r--"

    def test_mode_suid(self, handler):
        """Test converting SUID mode."""
        perms = handler._mode_to_permissions(0o4755, False)
        assert perms == "-rwsr-xr-x"

    def test_mode_sgid(self, handler):
        """Test converting SGID mode."""
        perms = handler._mode_to_permissions(0o2755, False)
        assert perms == "-rwxr-sr-x"

    def test_mode_sticky(self, handler):
        """Test converting sticky bit mode."""
        perms = handler._mode_to_permissions(0o1755, True)
        assert perms == "drwxr-xr-t"
