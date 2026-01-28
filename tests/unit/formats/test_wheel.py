"""Tests for Python wheel package format handler."""

import pytest
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from src.formats.wheel import WheelPackageFormat
from src.formats.base import ScriptType


class TestWheelPackageFormat:
    """Tests for WheelPackageFormat class."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return WheelPackageFormat()

    def test_format_name(self, handler):
        """Test format name property."""
        assert handler.format_name == "wheel"

    def test_file_extensions(self, handler):
        """Test file extensions."""
        assert ".whl" in handler.file_extensions

    def test_capabilities(self, handler):
        """Test capabilities."""
        caps = handler.capabilities
        assert caps.supports_vulnerability_scan
        assert caps.supports_virus_scan
        assert not caps.supports_script_analysis  # Wheels don't have install scripts
        assert caps.supports_binary_check
        assert caps.preferred_vulnerability_scanner == "pip-audit"

    def test_parse_filename_standard(self, handler):
        """Test parsing standard wheel filename."""
        name, version = handler.parse_filename("requests-2.28.1-py3-none-any.whl")
        assert name == "requests"
        assert version == "2.28.1"

    def test_parse_filename_with_underscore(self, handler):
        """Test parsing filename with underscores."""
        name, version = handler.parse_filename("zope_interface-5.4.0-cp39-cp39-manylinux1_x86_64.whl")
        assert name == "zope-interface"
        assert version == "5.4.0"

    def test_parse_filename_complex(self, handler):
        """Test parsing complex wheel filename."""
        name, version = handler.parse_filename("numpy-1.23.5-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl")
        assert name == "numpy"
        assert version == "1.23.5"


class TestWheelPackageFormatIntegration:
    """Integration tests for WheelPackageFormat."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return WheelPackageFormat()

    @pytest.fixture
    def sample_wheel(self, tmp_path):
        """Create a sample wheel file."""
        wheel_path = tmp_path / "sample-1.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            # Add METADATA
            metadata = """Metadata-Version: 2.1
Name: sample
Version: 1.0.0
Summary: A sample package
Author: Test Author
License: MIT
Requires-Dist: requests>=2.0
Requires-Dist: click
"""
            zf.writestr("sample-1.0.0.dist-info/METADATA", metadata)

            # Add WHEEL
            wheel_info = """Wheel-Version: 1.0
Generator: test
Root-Is-Purelib: true
Tag: py3-none-any
"""
            zf.writestr("sample-1.0.0.dist-info/WHEEL", wheel_info)

            # Add RECORD
            zf.writestr("sample-1.0.0.dist-info/RECORD", "")

            # Add a module
            zf.writestr("sample/__init__.py", "# sample package")

        return wheel_path

    @pytest.fixture
    def wheel_with_entry_points(self, tmp_path):
        """Create a wheel with entry points."""
        wheel_path = tmp_path / "cli_tool-2.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            metadata = """Metadata-Version: 2.1
Name: cli-tool
Version: 2.0.0
"""
            zf.writestr("cli_tool-2.0.0.dist-info/METADATA", metadata)
            zf.writestr("cli_tool-2.0.0.dist-info/WHEEL", "Wheel-Version: 1.0")

            entry_points = """[console_scripts]
cli-tool = cli_tool.main:cli
helper = cli_tool.helper:run
"""
            zf.writestr("cli_tool-2.0.0.dist-info/entry_points.txt", entry_points)
            zf.writestr("cli_tool/__init__.py", "")

        return wheel_path

    def test_detect_valid_wheel(self, handler, sample_wheel):
        """Test detecting valid wheel."""
        assert handler.detect(sample_wheel)

    def test_detect_nonexistent(self, handler, tmp_path):
        """Test detecting nonexistent file."""
        assert not handler.detect(tmp_path / "nonexistent.whl")

    def test_detect_wrong_extension(self, handler, tmp_path):
        """Test detecting file with wrong extension."""
        wrong_ext = tmp_path / "test.tar.gz"
        wrong_ext.write_text("not a wheel")
        assert not handler.detect(wrong_ext)

    def test_parse_metadata(self, handler, sample_wheel):
        """Test metadata parsing."""
        metadata = handler.parse_metadata(sample_wheel)

        assert metadata.name == "sample"
        assert metadata.version == "1.0.0"
        assert metadata.format_type == "wheel"
        assert metadata.description == "A sample package"
        assert metadata.maintainer == "Test Author"
        assert metadata.license == "MIT"
        assert "requests" in metadata.dependencies
        assert "click" in metadata.dependencies

    def test_validate_integrity_valid(self, handler, sample_wheel):
        """Test integrity validation of valid wheel."""
        assert handler.validate_integrity(sample_wheel)

    def test_validate_integrity_missing_metadata(self, handler, tmp_path):
        """Test integrity validation fails without METADATA."""
        wheel_path = tmp_path / "invalid-1.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            # Only add WHEEL, no METADATA
            zf.writestr("invalid-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0")

        assert not handler.validate_integrity(wheel_path)

    def test_validate_integrity_missing_wheel(self, handler, tmp_path):
        """Test integrity validation fails without WHEEL file."""
        wheel_path = tmp_path / "invalid-1.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            # Only add METADATA, no WHEEL
            zf.writestr("invalid-1.0.0.dist-info/METADATA", "Name: invalid\nVersion: 1.0.0")

        assert not handler.validate_integrity(wheel_path)

    def test_validate_integrity_bad_zip(self, handler, tmp_path):
        """Test integrity validation fails for corrupted ZIP."""
        wheel_path = tmp_path / "corrupted.whl"
        wheel_path.write_text("not a zip file")

        assert not handler.validate_integrity(wheel_path)

    def test_get_file_list(self, handler, sample_wheel):
        """Test getting file list."""
        files = handler.get_file_list(sample_wheel)

        assert len(files) > 0
        paths = [f.path for f in files]
        assert any("METADATA" in p for p in paths)
        assert any("__init__.py" in p for p in paths)

    def test_extract(self, handler, sample_wheel, tmp_path):
        """Test extraction."""
        dest = tmp_path / "extracted"
        result = handler.extract(sample_wheel, dest)

        assert result.extract_path == dest
        assert result.metadata.name == "sample"
        assert result.metadata.version == "1.0.0"
        assert len(result.file_list) > 0

        # Check files were actually extracted
        assert (dest / "sample" / "__init__.py").exists()

    def test_extract_with_entry_points(self, handler, wheel_with_entry_points, tmp_path):
        """Test extraction parses entry points."""
        dest = tmp_path / "extracted"
        result = handler.extract(wheel_with_entry_points, dest)

        # Entry points should be captured as scripts
        assert len(result.scripts) == 2
        assert result.scripts[0].name == "cli-tool"
        assert result.scripts[1].name == "helper"

    def test_has_native_extensions_false(self, handler, sample_wheel):
        """Test native extension detection - pure Python."""
        assert not handler.has_native_extensions(sample_wheel)

    def test_has_native_extensions_true(self, handler, tmp_path):
        """Test native extension detection - has .so file."""
        wheel_path = tmp_path / "native-1.0.0-cp39-cp39-linux_x86_64.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("native-1.0.0.dist-info/METADATA", "Name: native\nVersion: 1.0.0")
            zf.writestr("native-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0")
            zf.writestr("native/_native.cpython-39-x86_64-linux-gnu.so", b"ELF binary")

        assert handler.has_native_extensions(wheel_path)


class TestWheelSuspiciousPaths:
    """Test security checks for suspicious paths."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return WheelPackageFormat()

    def test_validate_rejects_path_traversal(self, handler, tmp_path):
        """Test that path traversal is rejected."""
        wheel_path = tmp_path / "evil-1.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("evil-1.0.0.dist-info/METADATA", "Name: evil\nVersion: 1.0.0")
            zf.writestr("evil-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0")
            zf.writestr("../../../etc/passwd", "malicious content")

        assert not handler.validate_integrity(wheel_path)

    def test_validate_rejects_absolute_path(self, handler, tmp_path):
        """Test that absolute paths are rejected."""
        wheel_path = tmp_path / "evil-1.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("evil-1.0.0.dist-info/METADATA", "Name: evil\nVersion: 1.0.0")
            zf.writestr("evil-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0")
            zf.writestr("/etc/passwd", "malicious content")

        assert not handler.validate_integrity(wheel_path)
