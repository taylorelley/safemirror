#!/usr/bin/env python3
"""Generate sample package fixtures for testing.

This script creates minimal but valid package files for each supported format.
Run this script to populate the tests/fixtures/packages/ directory.
"""

import gzip
import io
import json
import os
import struct
import tarfile
import zipfile
from pathlib import Path


FIXTURES_DIR = Path(__file__).parent / "packages"


def create_ar_member(name: str, content: bytes) -> bytes:
    """Create an ar archive member."""
    name_padded = name.ljust(16)
    timestamp = "0".ljust(12)
    owner = "0".ljust(6)
    group = "0".ljust(6)
    mode = "100644".ljust(8)
    size_str = str(len(content)).ljust(10)
    header = f"{name_padded}{timestamp}{owner}{group}{mode}{size_str}`\n".encode()
    result = header + content
    if len(content) % 2:
        result += b"\n"  # Padding for even alignment
    return result


def create_tar_gz(files: dict) -> bytes:
    """Create a tar.gz archive with the given files."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            if isinstance(content, str):
                content = content.encode()
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def create_deb_package(name: str, version: str, arch: str = "amd64",
                       scripts: dict = None, files: dict = None) -> bytes:
    """Create a minimal valid .deb package."""
    control_content = f"""Package: {name}
Version: {version}
Architecture: {arch}
Maintainer: Test <test@example.com>
Description: Test package {name}
 This is a test package for SafeMirror testing.
"""

    control_files = {"./control": control_content}
    if scripts:
        control_files.update(scripts)

    data_files = files or {"./usr/share/doc/test/README": "Test file\n"}

    # Build the ar archive
    result = b"!<arch>\n"
    result += create_ar_member("debian-binary", b"2.0\n")
    result += create_ar_member("control.tar.gz", create_tar_gz(control_files))
    result += create_ar_member("data.tar.gz", create_tar_gz(data_files))

    return result


def create_rpm_package(name: str, version: str, release: str = "1",
                       arch: str = "x86_64") -> bytes:
    """Create a minimal RPM-like package structure.

    Note: This creates a simplified structure. Real RPMs require
    proper header signatures which need rpm-build tools.
    """
    # RPM magic + version
    lead = b"\xed\xab\xee\xdb"  # RPM magic
    lead += struct.pack(">B", 3)  # Major version
    lead += struct.pack(">B", 0)  # Minor version
    lead += struct.pack(">H", 0)  # Type (binary)
    lead += struct.pack(">H", 1)  # Arch code
    lead += name.encode().ljust(66, b"\x00")[:66]  # Name
    lead += struct.pack(">H", 1)  # OS
    lead += struct.pack(">H", 5)  # Signature type
    lead += b"\x00" * 16  # Reserved

    # Minimal header structure (this is simplified)
    header = struct.pack(">I", 0x8eade801)  # Header magic
    header += struct.pack(">I", 0)  # Reserved
    header += struct.pack(">I", 1)  # Number of index entries
    header += struct.pack(">I", len(name) + 1)  # Size of store
    # Name tag entry
    header += struct.pack(">I", 1000)  # Tag (NAME)
    header += struct.pack(">I", 6)  # Type (STRING)
    header += struct.pack(">I", 0)  # Offset
    header += struct.pack(">I", 1)  # Count
    header += name.encode() + b"\x00"

    # Payload (empty cpio)
    payload = create_tar_gz({
        f"./usr/share/{name}/README": f"{name} {version}\n"
    })

    return lead + header + payload


def create_wheel_package(name: str, version: str,
                         python_version: str = "py3",
                         has_native: bool = False) -> bytes:
    """Create a minimal wheel package."""
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # METADATA
        metadata = f"""Metadata-Version: 2.1
Name: {name}
Version: {version}
Summary: Test package {name}
License: MIT
"""
        zf.writestr(f"{dist_info}/METADATA", metadata)

        # WHEEL
        wheel_content = f"""Wheel-Version: 1.0
Generator: safemirror-test
Root-Is-Purelib: {'false' if has_native else 'true'}
Tag: {python_version}-none-any
"""
        zf.writestr(f"{dist_info}/WHEEL", wheel_content)

        # RECORD (simplified)
        zf.writestr(f"{dist_info}/RECORD", "")

        # top_level.txt
        pkg_name = name.replace("-", "_")
        zf.writestr(f"{dist_info}/top_level.txt", pkg_name)

        # Package files
        zf.writestr(f"{pkg_name}/__init__.py", f'"""Package {name}."""\n__version__ = "{version}"\n')
        zf.writestr(f"{pkg_name}/main.py", f'"""Main module for {name}."""\n')

    return buffer.getvalue()


def create_npm_package(name: str, version: str,
                       scripts: dict = None,
                       dependencies: dict = None) -> bytes:
    """Create a minimal npm package (.tgz)."""
    package_json = {
        "name": name,
        "version": version,
        "description": f"Test package {name}",
        "main": "index.js",
        "license": "MIT"
    }
    if scripts:
        package_json["scripts"] = scripts
    if dependencies:
        package_json["dependencies"] = dependencies

    files = {
        "package/package.json": json.dumps(package_json, indent=2),
        "package/index.js": f'module.exports = {{name: "{name}", version: "{version}"}};\n',
        "package/README.md": f"# {name}\n\nTest package\n"
    }

    return create_tar_gz(files)


def create_apk_package(name: str, version: str, release: str = "r0",
                       arch: str = "x86_64") -> bytes:
    """Create a minimal APK package."""
    # APK is a tar.gz containing control.tar.gz and data.tar.gz
    pkginfo = f"""pkgname = {name}
pkgver = {version}-{release}
pkgdesc = Test package {name}
url = https://example.com/{name}
arch = {arch}
license = MIT
"""

    control_tar = create_tar_gz({
        ".PKGINFO": pkginfo,
    })

    data_tar = create_tar_gz({
        f"usr/share/{name}/README": f"{name} {version}\n",
    })

    # APK is just a gzipped tar with both
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        # Add control
        control_info = tarfile.TarInfo(name=".SIGN.RSA.rsa.pub")
        control_info.size = 0
        tf.addfile(control_info, io.BytesIO(b""))

        control_info = tarfile.TarInfo(name=".PKGINFO")
        control_info.size = len(pkginfo)
        tf.addfile(control_info, io.BytesIO(pkginfo.encode()))

        # Add data files
        readme = f"{name} {version}\n".encode()
        data_info = tarfile.TarInfo(name=f"usr/share/{name}/README")
        data_info.size = len(readme)
        tf.addfile(data_info, io.BytesIO(readme))

    return buffer.getvalue()


def create_sdist_package(name: str, version: str,
                         has_setup_py: bool = True,
                         dangerous_setup: bool = False) -> bytes:
    """Create a minimal Python sdist package."""
    pkg_name = name.replace("-", "_")
    prefix = f"{name}-{version}"

    files = {
        f"{prefix}/PKG-INFO": f"""Metadata-Version: 1.0
Name: {name}
Version: {version}
Summary: Test package {name}
""",
        f"{prefix}/{pkg_name}/__init__.py": f'__version__ = "{version}"\n',
    }

    if has_setup_py:
        if dangerous_setup:
            setup_content = f'''import os
import subprocess
from setuptools import setup

# Dangerous pattern for testing
os.system("echo 'Running setup'")

setup(
    name="{name}",
    version="{version}",
    packages=["{pkg_name}"],
)
'''
        else:
            setup_content = f'''from setuptools import setup

setup(
    name="{name}",
    version="{version}",
    packages=["{pkg_name}"],
)
'''
        files[f"{prefix}/setup.py"] = setup_content
    else:
        files[f"{prefix}/pyproject.toml"] = f'''[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "{name}"
version = "{version}"
'''

    return create_tar_gz(files)


def generate_all_fixtures():
    """Generate all test fixture packages."""
    # Create directories
    for fmt in ["deb", "rpm", "wheel", "npm", "apk", "sdist"]:
        (FIXTURES_DIR / fmt).mkdir(parents=True, exist_ok=True)

    # DEB packages
    print("Generating DEB packages...")
    (FIXTURES_DIR / "deb" / "clean-package_1.0.0_amd64.deb").write_bytes(
        create_deb_package("clean-package", "1.0.0")
    )
    (FIXTURES_DIR / "deb" / "scripted-package_1.0.0_amd64.deb").write_bytes(
        create_deb_package(
            "scripted-package", "1.0.0",
            scripts={
                "./preinst": "#!/bin/bash\necho 'Pre-install'\nexit 0\n",
                "./postinst": "#!/bin/bash\necho 'Post-install'\nexit 0\n",
            }
        )
    )

    # RPM packages
    print("Generating RPM packages...")
    (FIXTURES_DIR / "rpm" / "clean-package-1.0.0-1.x86_64.rpm").write_bytes(
        create_rpm_package("clean-package", "1.0.0")
    )

    # Wheel packages
    print("Generating wheel packages...")
    (FIXTURES_DIR / "wheel" / "clean_package-1.0.0-py3-none-any.whl").write_bytes(
        create_wheel_package("clean-package", "1.0.0")
    )
    (FIXTURES_DIR / "wheel" / "native_package-1.0.0-py3-none-any.whl").write_bytes(
        create_wheel_package("native-package", "1.0.0", has_native=True)
    )

    # NPM packages
    print("Generating NPM packages...")
    (FIXTURES_DIR / "npm" / "clean-package-1.0.0.tgz").write_bytes(
        create_npm_package("clean-package", "1.0.0")
    )
    (FIXTURES_DIR / "npm" / "scripted-package-1.0.0.tgz").write_bytes(
        create_npm_package(
            "scripted-package", "1.0.0",
            scripts={"postinstall": "echo 'Installed'"}
        )
    )

    # APK packages
    print("Generating APK packages...")
    (FIXTURES_DIR / "apk" / "clean-package-1.0.0-r0.apk").write_bytes(
        create_apk_package("clean-package", "1.0.0")
    )

    # Sdist packages
    print("Generating sdist packages...")
    (FIXTURES_DIR / "sdist" / "clean-package-1.0.0.tar.gz").write_bytes(
        create_sdist_package("clean-package", "1.0.0")
    )
    (FIXTURES_DIR / "sdist" / "setuppy-package-1.0.0.tar.gz").write_bytes(
        create_sdist_package("setuppy-package", "1.0.0", has_setup_py=True)
    )
    (FIXTURES_DIR / "sdist" / "dangerous-package-1.0.0.tar.gz").write_bytes(
        create_sdist_package("dangerous-package", "1.0.0", dangerous_setup=True)
    )

    print(f"Generated fixtures in {FIXTURES_DIR}")


if __name__ == "__main__":
    generate_all_fixtures()
