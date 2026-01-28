"""Tests for Python source distribution (sdist) package format handler."""

import pytest
import tempfile
import tarfile
from pathlib import Path
from io import BytesIO

from src.formats.sdist import SdistPackageFormat
from src.formats.base import ScriptType


class TestSdistPackageFormat:
    """Tests for SdistPackageFormat class."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return SdistPackageFormat()

    def test_format_name(self, handler):
        """Test format name property."""
        assert handler.format_name == "sdist"

    def test_file_extensions(self, handler):
        """Test file extensions."""
        assert ".tar.gz" in handler.file_extensions
        assert ".tgz" in handler.file_extensions

    def test_capabilities(self, handler):
        """Test capabilities."""
        caps = handler.capabilities
        assert caps.supports_vulnerability_scan
        assert caps.supports_virus_scan
        assert caps.supports_script_analysis  # setup.py needs analysis
        assert not caps.supports_binary_check  # Source only
        assert ScriptType.SETUP_PY in caps.script_types
        assert ScriptType.PYPROJECT_TOML in caps.script_types
        assert caps.preferred_vulnerability_scanner == "pip-audit"

    def test_parse_filename_standard(self, handler):
        """Test parsing standard sdist filename."""
        name, version = handler.parse_filename("requests-2.28.1.tar.gz")
        assert name == "requests"
        assert version == "2.28.1"

    def test_parse_filename_tgz(self, handler):
        """Test parsing .tgz filename."""
        name, version = handler.parse_filename("click-8.1.0.tgz")
        assert name == "click"
        assert version == "8.1.0"

    def test_parse_filename_dotted_name(self, handler):
        """Test parsing filename with dots in name."""
        name, version = handler.parse_filename("zope.interface-5.4.0.tar.gz")
        assert name == "zope.interface"
        assert version == "5.4.0"


class TestSdistPackageFormatIntegration:
    """Integration tests for SdistPackageFormat."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return SdistPackageFormat()

    @pytest.fixture
    def sample_sdist(self, tmp_path):
        """Create a sample sdist file."""
        sdist_path = tmp_path / "sample-1.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            # Add PKG-INFO
            pkg_info = b"""Metadata-Version: 1.0
Name: sample
Version: 1.0.0
Summary: A sample package
Author: Test Author
License: MIT
"""
            info = tarfile.TarInfo(name="sample-1.0.0/PKG-INFO")
            info.size = len(pkg_info)
            tar.addfile(info, BytesIO(pkg_info))

            # Add setup.py
            setup_py = b"""#!/usr/bin/env python
from setuptools import setup
setup(
    name='sample',
    version='1.0.0',
    packages=['sample'],
)
"""
            info = tarfile.TarInfo(name="sample-1.0.0/setup.py")
            info.size = len(setup_py)
            tar.addfile(info, BytesIO(setup_py))

            # Add package directory
            info = tarfile.TarInfo(name="sample-1.0.0/sample")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)

            # Add __init__.py
            init_py = b"# sample package"
            info = tarfile.TarInfo(name="sample-1.0.0/sample/__init__.py")
            info.size = len(init_py)
            tar.addfile(info, BytesIO(init_py))

        return sdist_path

    @pytest.fixture
    def sdist_with_pyproject(self, tmp_path):
        """Create an sdist with pyproject.toml."""
        sdist_path = tmp_path / "modern-2.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            # Add PKG-INFO
            pkg_info = b"Name: modern\nVersion: 2.0.0"
            info = tarfile.TarInfo(name="modern-2.0.0/PKG-INFO")
            info.size = len(pkg_info)
            tar.addfile(info, BytesIO(pkg_info))

            # Add pyproject.toml
            pyproject = b"""[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "modern"
version = "2.0.0"
"""
            info = tarfile.TarInfo(name="modern-2.0.0/pyproject.toml")
            info.size = len(pyproject)
            tar.addfile(info, BytesIO(pyproject))

        return sdist_path

    def test_detect_valid_sdist(self, handler, sample_sdist):
        """Test detecting valid sdist."""
        assert handler.detect(sample_sdist)

    def test_detect_nonexistent(self, handler, tmp_path):
        """Test detecting nonexistent file."""
        assert not handler.detect(tmp_path / "nonexistent.tar.gz")

    def test_detect_wrong_extension(self, handler, tmp_path):
        """Test detecting file with wrong extension."""
        wrong_ext = tmp_path / "test.whl"
        wrong_ext.write_text("not an sdist")
        assert not handler.detect(wrong_ext)

    def test_parse_metadata(self, handler, sample_sdist):
        """Test metadata parsing."""
        metadata = handler.parse_metadata(sample_sdist)

        assert metadata.name == "sample"
        assert metadata.version == "1.0.0"
        assert metadata.format_type == "sdist"
        assert metadata.description == "A sample package"
        assert metadata.maintainer == "Test Author"
        assert metadata.license == "MIT"

    def test_validate_integrity_valid(self, handler, sample_sdist):
        """Test integrity validation of valid sdist."""
        assert handler.validate_integrity(sample_sdist)

    def test_validate_integrity_missing_pkg_info(self, handler, tmp_path):
        """Test integrity validation passes with just setup.py."""
        sdist_path = tmp_path / "minimal-1.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            setup_py = b"from setuptools import setup\nsetup()"
            info = tarfile.TarInfo(name="minimal-1.0.0/setup.py")
            info.size = len(setup_py)
            tar.addfile(info, BytesIO(setup_py))

        assert handler.validate_integrity(sdist_path)

    def test_validate_integrity_no_metadata(self, handler, tmp_path):
        """Test integrity validation fails without any metadata."""
        sdist_path = tmp_path / "nometa-1.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            readme = b"Just a readme"
            info = tarfile.TarInfo(name="nometa-1.0.0/README.md")
            info.size = len(readme)
            tar.addfile(info, BytesIO(readme))

        assert not handler.validate_integrity(sdist_path)

    def test_validate_integrity_bad_archive(self, handler, tmp_path):
        """Test integrity validation fails for corrupted archive."""
        sdist_path = tmp_path / "corrupted.tar.gz"
        sdist_path.write_text("not a tar.gz file")

        assert not handler.validate_integrity(sdist_path)

    def test_get_file_list(self, handler, sample_sdist):
        """Test getting file list."""
        files = handler.get_file_list(sample_sdist)

        assert len(files) > 0
        paths = [f.path for f in files]
        assert any("PKG-INFO" in p for p in paths)
        assert any("setup.py" in p for p in paths)

    def test_extract(self, handler, sample_sdist, tmp_path):
        """Test extraction."""
        dest = tmp_path / "extracted"
        result = handler.extract(sample_sdist, dest)

        assert result.extract_path == dest
        assert result.metadata.name == "sample"
        assert result.metadata.version == "1.0.0"
        assert len(result.file_list) > 0

        # Check setup.py was captured as script
        assert len(result.scripts) >= 1
        setup_script = [s for s in result.scripts if s.name == "setup.py"][0]
        assert setup_script.script_type == ScriptType.SETUP_PY
        assert "setuptools" in setup_script.content

    def test_extract_with_pyproject(self, handler, sdist_with_pyproject, tmp_path):
        """Test extraction captures pyproject.toml."""
        dest = tmp_path / "extracted"
        result = handler.extract(sdist_with_pyproject, dest)

        # pyproject.toml should be captured as script
        pyproject_script = [s for s in result.scripts if s.name == "pyproject.toml"]
        assert len(pyproject_script) == 1
        assert pyproject_script[0].script_type == ScriptType.PYPROJECT_TOML

    def test_has_setup_py(self, handler, sample_sdist):
        """Test setup.py detection."""
        assert handler.has_setup_py(sample_sdist)

    def test_has_setup_py_false(self, handler, sdist_with_pyproject):
        """Test setup.py detection - modern package."""
        assert not handler.has_setup_py(sdist_with_pyproject)

    def test_has_pyproject_toml(self, handler, sdist_with_pyproject):
        """Test pyproject.toml detection."""
        assert handler.has_pyproject_toml(sdist_with_pyproject)

    def test_has_pyproject_toml_false(self, handler, sample_sdist):
        """Test pyproject.toml detection - legacy package."""
        assert not handler.has_pyproject_toml(sample_sdist)


class TestSdistSuspiciousPaths:
    """Test security checks for suspicious paths."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return SdistPackageFormat()

    def test_validate_rejects_path_traversal(self, handler, tmp_path):
        """Test that path traversal is rejected."""
        sdist_path = tmp_path / "evil-1.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            content = b"malicious"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(content)
            tar.addfile(info, BytesIO(content))

        assert not handler.validate_integrity(sdist_path)

    def test_validate_rejects_absolute_path(self, handler, tmp_path):
        """Test that absolute paths are rejected."""
        sdist_path = tmp_path / "evil-1.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            content = b"malicious"
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = len(content)
            tar.addfile(info, BytesIO(content))

        assert not handler.validate_integrity(sdist_path)

    def test_extract_rejects_unsafe_paths(self, handler, tmp_path):
        """Test that extraction rejects unsafe paths."""
        sdist_path = tmp_path / "evil-1.0.0.tar.gz"

        with tarfile.open(sdist_path, "w:gz") as tar:
            content = b"malicious"
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = len(content)
            tar.addfile(info, BytesIO(content))

        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler.extract(sdist_path)
