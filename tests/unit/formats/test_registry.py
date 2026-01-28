"""Tests for format registry."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.formats.registry import (
    FormatRegistry,
    get_registry,
    register_handler,
    detect_format,
    get_format_handler,
    read_magic_bytes,
    is_gzip_compressed,
    is_xz_compressed,
    is_zip_archive,
)
from src.formats.base import (
    PackageFormat,
    PackageMetadata,
    ExtractedContent,
    FormatCapabilities,
    FileInfo,
)


class MockFormat(PackageFormat):
    """Mock format handler for testing."""

    def __init__(self, name: str = "mock", extensions: list = None):
        self._name = name
        self._extensions = extensions or [".mock"]

    @property
    def format_name(self) -> str:
        return self._name

    @property
    def file_extensions(self) -> list:
        return self._extensions

    @property
    def capabilities(self) -> FormatCapabilities:
        return FormatCapabilities()

    def detect(self, path: Path) -> bool:
        return path.suffix in self._extensions

    def extract(self, path: Path, dest=None) -> ExtractedContent:
        return ExtractedContent(
            extract_path=dest or Path("/tmp"),
            file_list=[],
            scripts=[],
            metadata=PackageMetadata(name="mock", version="1.0", format_type="mock"),
        )

    def parse_metadata(self, path: Path) -> PackageMetadata:
        return PackageMetadata(name="mock", version="1.0", format_type="mock")

    def validate_integrity(self, path: Path) -> bool:
        return True

    def get_file_list(self, path: Path) -> list:
        return []


class TestFormatRegistry:
    """Tests for FormatRegistry class."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create a fresh registry for each test
        self.registry = FormatRegistry.__new__(FormatRegistry)
        self.registry._handlers = {}

    def test_register_handler(self):
        """Test handler registration."""
        handler = MockFormat("test")
        self.registry.register(handler)
        assert "test" in self.registry.list_formats()

    def test_register_overwrites(self):
        """Test that registering same format overwrites."""
        handler1 = MockFormat("test", [".test1"])
        handler2 = MockFormat("test", [".test2"])

        self.registry.register(handler1)
        self.registry.register(handler2)

        assert self.registry.get_handler("test") == handler2

    def test_unregister_handler(self):
        """Test handler unregistration."""
        handler = MockFormat("test")
        self.registry.register(handler)
        self.registry.unregister("test")
        assert "test" not in self.registry.list_formats()

    def test_get_handler(self):
        """Test getting handler by name."""
        handler = MockFormat("test")
        self.registry.register(handler)
        assert self.registry.get_handler("test") == handler
        assert self.registry.get_handler("nonexistent") is None

    def test_detect_format(self, tmp_path):
        """Test format detection."""
        handler = MockFormat("test", [".test"])
        self.registry.register(handler)

        # Create a test file
        test_file = tmp_path / "package.test"
        test_file.write_text("content")

        detected = self.registry.detect_format(test_file)
        assert detected == handler

    def test_detect_format_unknown(self, tmp_path):
        """Test detection of unknown format."""
        handler = MockFormat("test", [".test"])
        self.registry.register(handler)

        # Create a file with unknown extension
        unknown_file = tmp_path / "package.unknown"
        unknown_file.write_text("content")

        detected = self.registry.detect_format(unknown_file)
        assert detected is None

    def test_detect_format_nonexistent(self, tmp_path):
        """Test detection of nonexistent file."""
        nonexistent = tmp_path / "nonexistent.test"
        detected = self.registry.detect_format(nonexistent)
        assert detected is None

    def test_list_formats(self):
        """Test listing registered formats."""
        self.registry.register(MockFormat("format1"))
        self.registry.register(MockFormat("format2"))

        formats = self.registry.list_formats()
        assert "format1" in formats
        assert "format2" in formats

    def test_list_extensions(self):
        """Test listing extensions by format."""
        self.registry.register(MockFormat("format1", [".f1", ".f1a"]))
        self.registry.register(MockFormat("format2", [".f2"]))

        extensions = self.registry.list_extensions()
        assert extensions["format1"] == [".f1", ".f1a"]
        assert extensions["format2"] == [".f2"]

    def test_clear(self):
        """Test clearing all handlers."""
        self.registry.register(MockFormat("test"))
        self.registry.clear()
        assert len(self.registry.list_formats()) == 0


class TestMagicByteHelpers:
    """Tests for magic byte helper functions."""

    def test_read_magic_bytes(self, tmp_path):
        """Test reading magic bytes."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x1f\x8b\x08\x00test")

        magic = read_magic_bytes(test_file, 4)
        assert magic == b"\x1f\x8b\x08\x00"

    def test_read_magic_bytes_nonexistent(self, tmp_path):
        """Test reading magic bytes from nonexistent file."""
        nonexistent = tmp_path / "nonexistent"
        magic = read_magic_bytes(nonexistent)
        assert magic == b""

    def test_is_gzip_compressed(self, tmp_path):
        """Test gzip detection."""
        # Gzip magic: 1f 8b
        gzip_file = tmp_path / "test.gz"
        gzip_file.write_bytes(b"\x1f\x8b\x08\x00" + b"x" * 100)

        assert is_gzip_compressed(gzip_file)

        # Non-gzip file
        plain_file = tmp_path / "test.txt"
        plain_file.write_text("plain text")
        assert not is_gzip_compressed(plain_file)

    def test_is_xz_compressed(self, tmp_path):
        """Test xz detection."""
        # XZ magic: fd 37 7a 58 5a 00
        xz_file = tmp_path / "test.xz"
        xz_file.write_bytes(b"\xfd7zXZ\x00" + b"x" * 100)

        assert is_xz_compressed(xz_file)

    def test_is_zip_archive(self, tmp_path):
        """Test ZIP archive detection."""
        # ZIP magic: 50 4b 03 04
        zip_file = tmp_path / "test.zip"
        zip_file.write_bytes(b"PK\x03\x04" + b"x" * 100)

        assert is_zip_archive(zip_file)

        # Non-zip file
        plain_file = tmp_path / "test.txt"
        plain_file.write_text("plain text")
        assert not is_zip_archive(plain_file)


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def setup_method(self):
        """Clear global registry before each test."""
        get_registry().clear()

    def teardown_method(self):
        """Clear global registry after each test."""
        get_registry().clear()

    def test_register_handler_global(self):
        """Test global register_handler function."""
        handler = MockFormat("global_test")
        register_handler(handler)
        assert get_format_handler("global_test") == handler

    def test_detect_format_global(self, tmp_path):
        """Test global detect_format function."""
        handler = MockFormat("global_test", [".gtest"])
        register_handler(handler)

        test_file = tmp_path / "package.gtest"
        test_file.write_text("content")

        detected = detect_format(test_file)
        assert detected == handler
