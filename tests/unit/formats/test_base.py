"""Tests for base format classes and data structures."""

import pytest
from pathlib import Path

from src.formats.base import (
    PackageMetadata,
    FileInfo,
    ScriptInfo,
    ScriptType,
    FormatCapabilities,
    ExtractedContent,
)


class TestPackageMetadata:
    """Tests for PackageMetadata class."""

    def test_deb_package_key(self):
        """Test package key generation for Debian format."""
        metadata = PackageMetadata(
            name="curl",
            version="7.81.0-1ubuntu1.16",
            format_type="deb",
            architecture="amd64",
        )
        assert metadata.get_package_key() == "curl_7.81.0-1ubuntu1.16_amd64"

    def test_deb_package_key_default_arch(self):
        """Test package key with default architecture."""
        metadata = PackageMetadata(
            name="python3-pip",
            version="22.0.2",
            format_type="deb",
        )
        assert metadata.get_package_key() == "python3-pip_22.0.2_all"

    def test_rpm_package_key(self):
        """Test package key generation for RPM format."""
        metadata = PackageMetadata(
            name="curl",
            version="7.76.1",
            format_type="rpm",
            architecture="x86_64",
            release="14.el8",
        )
        assert metadata.get_package_key() == "curl-7.76.1-14.el8.x86_64"

    def test_rpm_package_key_defaults(self):
        """Test RPM package key with default values."""
        metadata = PackageMetadata(
            name="python-pip",
            version="21.2.3",
            format_type="rpm",
        )
        assert metadata.get_package_key() == "python-pip-21.2.3-1.noarch"

    def test_wheel_package_key(self):
        """Test package key generation for Python wheel."""
        metadata = PackageMetadata(
            name="requests",
            version="2.28.1",
            format_type="wheel",
        )
        assert metadata.get_package_key() == "requests-2.28.1"

    def test_npm_package_key(self):
        """Test package key generation for NPM package."""
        metadata = PackageMetadata(
            name="lodash",
            version="4.17.21",
            format_type="npm",
        )
        assert metadata.get_package_key() == "lodash@4.17.21"

    def test_npm_scoped_package_key(self):
        """Test package key generation for scoped NPM package."""
        metadata = PackageMetadata(
            name="cli",
            version="7.24.0",
            format_type="npm",
            scope="angular",
        )
        assert metadata.get_package_key() == "@angular/cli@7.24.0"

    def test_apk_package_key(self):
        """Test package key generation for Alpine APK."""
        metadata = PackageMetadata(
            name="curl",
            version="7.83.1",
            format_type="apk",
            release="0",
        )
        assert metadata.get_package_key() == "curl-7.83.1-r0"


class TestFileInfo:
    """Tests for FileInfo class."""

    def test_regular_file(self):
        """Test regular file detection."""
        info = FileInfo(
            path="usr/bin/curl",
            permissions="-rwxr-xr-x",
        )
        assert not info.is_suid
        assert not info.is_sgid
        assert not info.is_world_writable
        assert not info.is_directory
        assert not info.is_device

    def test_suid_detection(self):
        """Test SUID bit detection."""
        info = FileInfo(
            path="usr/bin/sudo",
            permissions="-rwsr-xr-x",
        )
        assert info.is_suid
        assert not info.is_sgid

    def test_suid_no_execute(self):
        """Test SUID bit without execute (S instead of s)."""
        info = FileInfo(
            path="usr/bin/test",
            permissions="-rwSr-xr-x",
        )
        assert info.is_suid

    def test_sgid_detection(self):
        """Test SGID bit detection."""
        info = FileInfo(
            path="usr/bin/write",
            permissions="-rwxr-sr-x",
        )
        assert not info.is_suid
        assert info.is_sgid

    def test_world_writable_detection(self):
        """Test world-writable detection."""
        info = FileInfo(
            path="tmp/test",
            permissions="-rw-rw-rw-",
        )
        assert info.is_world_writable

    def test_directory_detection(self):
        """Test directory detection."""
        info = FileInfo(
            path="usr/lib",
            permissions="drwxr-xr-x",
            file_type="d",
        )
        assert info.is_directory

    def test_device_detection(self):
        """Test device file detection."""
        # Block device
        block = FileInfo(
            path="dev/sda",
            permissions="brw-rw----",
            file_type="b",
        )
        assert block.is_device

        # Character device
        char = FileInfo(
            path="dev/null",
            permissions="crw-rw-rw-",
            file_type="c",
        )
        assert char.is_device

    def test_symlink(self):
        """Test symlink handling."""
        info = FileInfo(
            path="usr/lib/libcurl.so",
            permissions="lrwxrwxrwx",
            file_type="l",
            link_target="libcurl.so.4",
        )
        assert info.link_target == "libcurl.so.4"
        assert not info.is_device


class TestScriptInfo:
    """Tests for ScriptInfo class."""

    def test_basic_script(self):
        """Test basic script creation."""
        script = ScriptInfo(
            name="postinst",
            script_type=ScriptType.POST_INSTALL,
            content="#!/bin/bash\necho 'Hello'",
            interpreter="/bin/bash",
        )
        assert script.name == "postinst"
        assert script.script_type == ScriptType.POST_INSTALL
        assert script.interpreter == "/bin/bash"

    def test_npm_script(self):
        """Test NPM lifecycle script."""
        script = ScriptInfo(
            name="postinstall",
            script_type=ScriptType.NPM_POSTINSTALL,
            content="node scripts/build.js",
            interpreter="node",
        )
        assert script.script_type == ScriptType.NPM_POSTINSTALL


class TestFormatCapabilities:
    """Tests for FormatCapabilities class."""

    def test_default_capabilities(self):
        """Test default capability values."""
        caps = FormatCapabilities()
        assert caps.supports_vulnerability_scan
        assert caps.supports_virus_scan
        assert caps.supports_integrity_check
        assert caps.supports_script_analysis
        assert caps.supports_binary_check

    def test_python_wheel_capabilities(self):
        """Test capabilities for Python wheel (no scripts)."""
        caps = FormatCapabilities(
            supports_script_analysis=False,  # Pure wheels have no scripts
            has_maintainer_scripts=False,
            has_binary_content=True,  # C extensions
            preferred_vulnerability_scanner="pip-audit",
        )
        assert not caps.supports_script_analysis
        assert not caps.has_maintainer_scripts
        assert caps.preferred_vulnerability_scanner == "pip-audit"


class TestExtractedContent:
    """Tests for ExtractedContent class."""

    def test_get_suid_files(self):
        """Test filtering SUID files."""
        content = ExtractedContent(
            extract_path=Path("/tmp/test"),
            file_list=[
                FileInfo(path="usr/bin/sudo", permissions="-rwsr-xr-x"),
                FileInfo(path="usr/bin/curl", permissions="-rwxr-xr-x"),
                FileInfo(path="usr/bin/su", permissions="-rwsr-xr-x"),
            ],
            scripts=[],
            metadata=PackageMetadata(name="test", version="1.0", format_type="deb"),
        )

        suid_files = content.get_suid_files()
        assert len(suid_files) == 2
        assert all(f.is_suid for f in suid_files)

    def test_get_files_in_path(self):
        """Test filtering files by path prefix."""
        content = ExtractedContent(
            extract_path=Path("/tmp/test"),
            file_list=[
                FileInfo(path="usr/bin/curl", permissions="-rwxr-xr-x"),
                FileInfo(path="usr/lib/libcurl.so", permissions="-rw-r--r--"),
                FileInfo(path="etc/curl.conf", permissions="-rw-r--r--"),
            ],
            scripts=[],
            metadata=PackageMetadata(name="test", version="1.0", format_type="deb"),
        )

        usr_files = content.get_files_in_path("usr/")
        assert len(usr_files) == 2
        assert all(f.path.startswith("usr/") for f in usr_files)
