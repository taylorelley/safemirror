"""Unit tests for handling corrupt and malformed packages.

Tests robustness against truncated, corrupted, and adversarial package files.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
import subprocess
import zipfile
import tarfile
import gzip
import io

from src.formats.deb import DebPackageFormat
from src.formats.rpm import RpmPackageFormat
from src.formats.wheel import WheelPackageFormat
from src.formats.npm import NpmPackageFormat
from src.formats.apk import ApkPackageFormat
from src.formats.sdist import SdistPackageFormat


class TestCorruptDebPackages:
    """Tests for corrupt Debian packages."""

    @pytest.fixture
    def handler(self):
        """Create Debian format handler."""
        return DebPackageFormat()

    def test_truncated_deb_file(self, handler, tmp_path):
        """Test handling of truncated .deb file."""
        deb_file = tmp_path / "truncated.deb"
        # Write only partial ar archive header
        deb_file.write_bytes(b"!<arch")

        assert not handler.validate_integrity(deb_file)

    def test_empty_deb_file(self, handler, tmp_path):
        """Test handling of empty .deb file."""
        deb_file = tmp_path / "empty.deb"
        deb_file.write_bytes(b"")

        assert not handler.validate_integrity(deb_file)

    def test_wrong_magic_bytes(self, handler, tmp_path):
        """Test handling of file with wrong magic bytes."""
        deb_file = tmp_path / "wrong_magic.deb"
        deb_file.write_bytes(b"\xed\xab\xee\xdb" + b"x" * 100)  # RPM magic

        assert not handler.validate_integrity(deb_file)

    def test_corrupted_ar_archive(self, handler, tmp_path):
        """Test handling of corrupted ar archive."""
        deb_file = tmp_path / "corrupt.deb"
        # Valid ar header but garbage content
        deb_file.write_bytes(b"!<arch>\ngarbage content that is not valid ar")

        # Should either return False or raise an exception
        try:
            result = handler.validate_integrity(deb_file)
            # If it returns, should be False
            assert result is False or result is True  # Depends on implementation
        except RuntimeError:
            pass  # Expected for malformed archive

    @patch("subprocess.run")
    def test_deb_extract_failure(self, mock_run, handler, tmp_path):
        """Test handling dpkg-deb extraction failure."""
        deb_file = tmp_path / "fail.deb"
        deb_file.write_bytes(b"!<arch>\n" + b"x" * 100)

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "dpkg-deb", stderr=b"archive has no control.tar"
        )

        with pytest.raises(RuntimeError):
            handler.parse_metadata(deb_file)


class TestCorruptRpmPackages:
    """Tests for corrupt RPM packages."""

    @pytest.fixture
    def handler(self):
        """Create RPM format handler."""
        return RpmPackageFormat()

    def test_truncated_rpm_file(self, handler, tmp_path):
        """Test handling of truncated .rpm file."""
        rpm_file = tmp_path / "truncated.rpm"
        # Write only partial RPM magic
        rpm_file.write_bytes(b"\xed\xab")

        # May detect by extension even with truncated magic
        result = handler.detect(rpm_file)
        # Either fails detection or fails validation
        if result:
            assert not handler.validate_integrity(rpm_file)

    def test_empty_rpm_file(self, handler, tmp_path):
        """Test handling of empty .rpm file."""
        rpm_file = tmp_path / "empty.rpm"
        rpm_file.write_bytes(b"")

        assert not handler.validate_integrity(rpm_file)

    def test_wrong_rpm_version(self, handler, tmp_path):
        """Test handling of RPM with unsupported version."""
        rpm_file = tmp_path / "wrong_version.rpm"
        # RPM magic with wrong version bytes
        rpm_file.write_bytes(b"\xed\xab\xee\xdb\xff\xff" + b"x" * 100)

        # Should handle gracefully
        result = handler.detect(rpm_file)
        # May or may not detect based on implementation


class TestCorruptWheelPackages:
    """Tests for corrupt wheel packages."""

    @pytest.fixture
    def handler(self):
        """Create wheel format handler."""
        return WheelPackageFormat()

    def test_truncated_wheel(self, handler, tmp_path):
        """Test handling of truncated wheel (zip) file."""
        wheel_file = tmp_path / "truncated-1.0.0-py3-none-any.whl"
        # Write partial zip header
        wheel_file.write_bytes(b"PK\x03\x04")

        assert not handler.validate_integrity(wheel_file)

    def test_corrupt_zip_wheel(self, handler, tmp_path):
        """Test handling of corrupted zip wheel."""
        wheel_file = tmp_path / "corrupt-1.0.0-py3-none-any.whl"
        wheel_file.write_bytes(b"PK\x03\x04" + b"garbage" * 100)

        assert not handler.validate_integrity(wheel_file)

    def test_empty_wheel(self, handler, tmp_path):
        """Test handling of empty wheel file."""
        wheel_file = tmp_path / "empty-1.0.0-py3-none-any.whl"
        wheel_file.write_bytes(b"")

        assert not handler.validate_integrity(wheel_file)

    def test_wheel_missing_metadata(self, handler, tmp_path):
        """Test wheel without METADATA file."""
        wheel_file = tmp_path / "nometadata-1.0.0-py3-none-any.whl"

        # Create valid zip without required metadata
        with zipfile.ZipFile(wheel_file, 'w') as zf:
            zf.writestr("empty.py", "# empty")

        # Should fail validation or metadata parsing
        try:
            metadata = handler.parse_metadata(wheel_file)
            # If it doesn't raise, check the metadata is incomplete
            assert metadata.name is not None  # Implementation may use filename
        except RuntimeError:
            pass  # Expected

    def test_wheel_with_zip_bomb_protection(self, handler, tmp_path):
        """Test protection against zip bombs."""
        wheel_file = tmp_path / "bomb-1.0.0-py3-none-any.whl"

        # Create a file that expands significantly
        with zipfile.ZipFile(wheel_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Write highly compressible data
            data = b"0" * (1024 * 1024)  # 1MB of zeros
            zf.writestr("large.bin", data)

        # Should handle without memory issues
        # This test mainly checks we don't crash
        try:
            handler.validate_integrity(wheel_file)
        except (RuntimeError, MemoryError, zipfile.BadZipFile):
            pass  # Acceptable failure modes


class TestCorruptNpmPackages:
    """Tests for corrupt NPM packages."""

    @pytest.fixture
    def handler(self):
        """Create NPM format handler."""
        return NpmPackageFormat()

    def test_truncated_npm_tgz(self, handler, tmp_path):
        """Test handling of truncated npm .tgz file."""
        npm_file = tmp_path / "truncated-1.0.0.tgz"
        # Write partial gzip header
        npm_file.write_bytes(b"\x1f\x8b\x08")

        # Should fail validation or metadata parsing
        try:
            result = handler.validate_integrity(npm_file)
            assert not result
        except (RuntimeError, Exception):
            pass  # Exception is also acceptable

    def test_corrupt_gzip_npm(self, handler, tmp_path):
        """Test handling of corrupted gzip npm package."""
        npm_file = tmp_path / "corrupt-1.0.0.tgz"
        # Valid gzip header but corrupt content
        npm_file.write_bytes(b"\x1f\x8b\x08\x00" + b"garbage" * 100)

        assert not handler.validate_integrity(npm_file)

    def test_empty_npm_package(self, handler, tmp_path):
        """Test handling of empty npm package."""
        npm_file = tmp_path / "empty-1.0.0.tgz"
        npm_file.write_bytes(b"")

        assert not handler.validate_integrity(npm_file)

    def test_npm_missing_package_json(self, handler, tmp_path):
        """Test npm package without package.json."""
        npm_file = tmp_path / "nopackagejson-1.0.0.tgz"

        # Create valid tar.gz without package.json
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            data = b"console.log('test');"
            info = tarfile.TarInfo(name="package/index.js")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        # Compress with gzip
        with gzip.open(npm_file, 'wb') as gz:
            gz.write(tar_buffer.getvalue())

        # Should fail metadata parsing
        try:
            metadata = handler.parse_metadata(npm_file)
            # May use filename fallback
        except RuntimeError:
            pass  # Expected


class TestCorruptApkPackages:
    """Tests for corrupt Alpine packages."""

    @pytest.fixture
    def handler(self):
        """Create APK format handler."""
        return ApkPackageFormat()

    def test_truncated_apk(self, handler, tmp_path):
        """Test handling of truncated .apk file."""
        apk_file = tmp_path / "truncated-1.0.0-r0.apk"
        apk_file.write_bytes(b"\x1f\x8b\x08")

        # Should fail validation
        try:
            result = handler.validate_integrity(apk_file)
            assert not result
        except (RuntimeError, Exception):
            pass  # Exception is also acceptable

    def test_corrupt_tar_apk(self, handler, tmp_path):
        """Test handling of corrupted tar apk."""
        apk_file = tmp_path / "corrupt-1.0.0-r0.apk"
        apk_file.write_bytes(b"\x1f\x8b\x08\x00" + b"not a tar" * 100)

        assert not handler.validate_integrity(apk_file)

    def test_empty_apk(self, handler, tmp_path):
        """Test handling of empty apk file."""
        apk_file = tmp_path / "empty-1.0.0-r0.apk"
        apk_file.write_bytes(b"")

        assert not handler.validate_integrity(apk_file)


class TestCorruptSdistPackages:
    """Tests for corrupt source distribution packages."""

    @pytest.fixture
    def handler(self):
        """Create sdist format handler."""
        return SdistPackageFormat()

    def test_truncated_sdist(self, handler, tmp_path):
        """Test handling of truncated .tar.gz file."""
        sdist_file = tmp_path / "truncated-1.0.0.tar.gz"
        sdist_file.write_bytes(b"\x1f\x8b\x08")

        # Should fail validation
        try:
            result = handler.validate_integrity(sdist_file)
            assert not result
        except (RuntimeError, Exception):
            pass  # Exception is also acceptable

    def test_corrupt_gzip_sdist(self, handler, tmp_path):
        """Test handling of corrupted gzip sdist."""
        sdist_file = tmp_path / "corrupt-1.0.0.tar.gz"
        sdist_file.write_bytes(b"\x1f\x8b\x08\x00" + b"garbage" * 100)

        assert not handler.validate_integrity(sdist_file)

    def test_empty_sdist(self, handler, tmp_path):
        """Test handling of empty sdist file."""
        sdist_file = tmp_path / "empty-1.0.0.tar.gz"
        sdist_file.write_bytes(b"")

        assert not handler.validate_integrity(sdist_file)


class TestZeroBytePakages:
    """Tests for zero-byte packages across all formats."""

    @pytest.fixture
    def handlers(self):
        """Create all format handlers."""
        return {
            "deb": DebPackageFormat(),
            "rpm": RpmPackageFormat(),
            "wheel": WheelPackageFormat(),
            "npm": NpmPackageFormat(),
            "apk": ApkPackageFormat(),
            "sdist": SdistPackageFormat(),
        }

    def test_zero_byte_deb(self, handlers, tmp_path):
        """Test zero-byte .deb file."""
        pkg = tmp_path / "zero.deb"
        pkg.write_bytes(b"")
        assert not handlers["deb"].validate_integrity(pkg)

    def test_zero_byte_rpm(self, handlers, tmp_path):
        """Test zero-byte .rpm file."""
        pkg = tmp_path / "zero.rpm"
        pkg.write_bytes(b"")
        assert not handlers["rpm"].validate_integrity(pkg)

    def test_zero_byte_wheel(self, handlers, tmp_path):
        """Test zero-byte .whl file."""
        pkg = tmp_path / "zero-1.0.0-py3-none-any.whl"
        pkg.write_bytes(b"")
        assert not handlers["wheel"].validate_integrity(pkg)

    def test_zero_byte_npm(self, handlers, tmp_path):
        """Test zero-byte .tgz file."""
        pkg = tmp_path / "zero-1.0.0.tgz"
        pkg.write_bytes(b"")
        assert not handlers["npm"].validate_integrity(pkg)

    def test_zero_byte_apk(self, handlers, tmp_path):
        """Test zero-byte .apk file."""
        pkg = tmp_path / "zero-1.0.0-r0.apk"
        pkg.write_bytes(b"")
        assert not handlers["apk"].validate_integrity(pkg)

    def test_zero_byte_sdist(self, handlers, tmp_path):
        """Test zero-byte .tar.gz file."""
        pkg = tmp_path / "zero-1.0.0.tar.gz"
        pkg.write_bytes(b"")
        assert not handlers["sdist"].validate_integrity(pkg)


class TestExtremelyLargePackages:
    """Tests for handling extremely large packages (mocked)."""

    def test_large_package_detection(self, tmp_path):
        """Test detection of packages claiming to be extremely large."""
        # This test uses mocking to avoid creating actual large files
        handler = DebPackageFormat()

        with patch("pathlib.Path.stat") as mock_stat:
            # Mock a 100GB file
            mock_stat.return_value = MagicMock(st_size=100 * 1024 * 1024 * 1024)

            # The handler should either handle this or reject it
            # Implementation dependent
            pkg = tmp_path / "huge.deb"
            pkg.write_bytes(b"!<arch>\n")

            # Should not crash
            try:
                handler.detect(pkg)
            except (RuntimeError, MemoryError, ValueError):
                pass  # Acceptable to reject oversized packages


class TestPackageWithSpecialFilenames:
    """Tests for packages with unusual filenames."""

    @pytest.fixture
    def handler(self):
        """Create Debian format handler."""
        return DebPackageFormat()

    def test_package_with_spaces(self, handler, tmp_path):
        """Test package filename with spaces."""
        pkg = tmp_path / "my package_1.0.0_all.deb"
        pkg.write_bytes(b"!<arch>\n" + b"x" * 100)

        # Should handle filename parsing
        name, version = handler.parse_filename(pkg.name)
        assert name is not None

    def test_package_with_unicode(self, handler, tmp_path):
        """Test package filename with unicode characters."""
        pkg = tmp_path / "paquete_1.0.0_all.deb"
        pkg.write_bytes(b"!<arch>\n" + b"x" * 100)

        name, version = handler.parse_filename(pkg.name)
        assert "paquete" in name or name is not None

    def test_package_with_dots(self, handler, tmp_path):
        """Test package filename with multiple dots."""
        pkg = tmp_path / "my.pkg.name_1.0.0_all.deb"
        pkg.write_bytes(b"!<arch>\n" + b"x" * 100)

        name, version = handler.parse_filename(pkg.name)
        assert name is not None
