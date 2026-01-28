"""Python source distribution package format handler.

Implements extraction and metadata parsing for Python sdist (.tar.gz) files.
"""

import email
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional, Dict

from ..common.logger import get_logger
from .base import (
    PackageFormat,
    PackageMetadata,
    ExtractedContent,
    FormatCapabilities,
    ScriptInfo,
    ScriptType,
    FileInfo,
)

logger = get_logger("format.sdist")


class SdistPackageFormat(PackageFormat):
    """Handler for Python source distribution package format (.tar.gz files).

    Source distributions are tar.gz archives containing:
    - PKG-INFO: Package metadata
    - setup.py: Build/install script
    - pyproject.toml: Modern build configuration
    - Package source code
    """

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "sdist"

    @property
    def file_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return [".tar.gz", ".tgz"]

    @property
    def capabilities(self) -> FormatCapabilities:
        """Return format capabilities."""
        return FormatCapabilities(
            supports_vulnerability_scan=True,
            supports_virus_scan=True,
            supports_integrity_check=True,
            supports_script_analysis=True,  # setup.py can execute arbitrary code
            supports_binary_check=False,  # Source only, no binaries
            has_maintainer_scripts=True,  # setup.py is essentially a script
            has_binary_content=False,
            has_signature=False,
            preferred_vulnerability_scanner="pip-audit",
            alternative_scanners=["trivy", "grype"],
            script_types={
                ScriptType.SETUP_PY,
                ScriptType.PYPROJECT_TOML,
            },
        )

    def detect(self, path: Path) -> bool:
        """Detect if file is a Python source distribution.

        Args:
            path: Path to the file

        Returns:
            True if file is a Python sdist
        """
        if not path.exists():
            return False

        # Check extension
        name = path.name.lower()
        if not (name.endswith(".tar.gz") or name.endswith(".tgz")):
            return False

        # Verify it's a valid tar.gz with PKG-INFO or setup.py
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                # Look for PKG-INFO or setup.py at root level
                for n in names:
                    parts = n.split("/", 2)
                    if len(parts) >= 2:
                        if parts[1] == "PKG-INFO" or parts[1] == "setup.py":
                            return True
                return False
        except (tarfile.TarError, IOError, OSError):
            pass

        return False

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract sdist package contents.

        Args:
            path: Path to .tar.gz file
            dest: Optional destination directory

        Returns:
            ExtractedContent with extracted files and metadata

        Raises:
            RuntimeError: If extraction fails
        """
        if not path.exists():
            raise RuntimeError(f"Package file not found: {path}")

        # Create temp directory if dest not provided
        temp_dir = None
        if dest is None:
            temp_dir = tempfile.TemporaryDirectory()
            dest = Path(temp_dir.name)
        else:
            dest.mkdir(parents=True, exist_ok=True)

        try:
            file_list = []
            scripts = []
            metadata = None
            root_dir = None

            with tarfile.open(path, "r:gz") as tar:
                # Validate and find root directory
                for member in tar.getmembers():
                    # Security check
                    if member.name.startswith("/") or ".." in member.name:
                        raise RuntimeError(f"Unsafe path in archive: {member.name}")

                    # Find root directory
                    if root_dir is None and "/" in member.name:
                        root_dir = member.name.split("/", 1)[0]

                # Extract all files
                tar.extractall(dest, filter="data")

                # Build file list
                for member in tar.getmembers():
                    file_list.append(self._member_to_fileinfo(member))

                    # Get relative path within package
                    rel_path = member.name
                    if root_dir and rel_path.startswith(root_dir + "/"):
                        rel_path = rel_path[len(root_dir) + 1:]

                    # Parse metadata
                    if rel_path == "PKG-INFO":
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            metadata = self._parse_pkginfo(content, path.name)

                    # Extract scripts for analysis
                    if rel_path == "setup.py":
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            scripts.append(
                                ScriptInfo(
                                    name="setup.py",
                                    script_type=ScriptType.SETUP_PY,
                                    content=content,
                                    interpreter="python",
                                    source_path=member.name,
                                )
                            )

                    if rel_path == "pyproject.toml":
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            scripts.append(
                                ScriptInfo(
                                    name="pyproject.toml",
                                    script_type=ScriptType.PYPROJECT_TOML,
                                    content=content,
                                    interpreter=None,
                                    source_path=member.name,
                                )
                            )

            if metadata is None:
                metadata = self._metadata_from_filename(path.name)

            data_path = dest / root_dir if root_dir else dest

            return ExtractedContent(
                extract_path=dest,
                data_path=data_path,
                file_list=file_list,
                scripts=scripts,
                metadata=metadata,
                temp_dir=temp_dir,
            )

        except tarfile.TarError as e:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Invalid tar.gz file: {e}") from e
        except Exception as e:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Failed to extract package: {e}") from e

    def _member_to_fileinfo(self, member: tarfile.TarInfo) -> FileInfo:
        """Convert tar member to FileInfo.

        Args:
            member: TarInfo object

        Returns:
            FileInfo object
        """
        perms = self._mode_to_permissions(member.mode, member.isdir())

        file_type = "-"
        if member.isdir():
            file_type = "d"
        elif member.issym():
            file_type = "l"

        return FileInfo(
            path=member.name.lstrip("./"),
            permissions=perms,
            size=member.size,
            owner=member.uname or "root",
            group=member.gname or "root",
            file_type=file_type,
            link_target=member.linkname if member.issym() else None,
        )

    def _mode_to_permissions(self, mode: int, is_dir: bool) -> str:
        """Convert numeric mode to permission string.

        Args:
            mode: Numeric mode (e.g., 0o755)
            is_dir: Whether this is a directory

        Returns:
            Permission string (e.g., "-rwxr-xr-x")
        """
        type_char = "d" if is_dir else "-"

        def triplet(m):
            r = "r" if m & 4 else "-"
            w = "w" if m & 2 else "-"
            x = "x" if m & 1 else "-"
            return r + w + x

        owner = triplet((mode >> 6) & 7)
        group = triplet((mode >> 3) & 7)
        other = triplet(mode & 7)

        return type_char + owner + group + other

    def _parse_pkginfo(self, content: str, filename: str) -> PackageMetadata:
        """Parse PKG-INFO file content.

        Args:
            content: PKG-INFO file content (email format)
            filename: Original filename for fallback

        Returns:
            PackageMetadata
        """
        # PKG-INFO uses email.message format (RFC 822)
        msg = email.message_from_string(content)

        name = msg.get("Name", self._parse_name_from_filename(filename))
        version = msg.get("Version", "unknown")

        # Get dependencies
        dependencies = []
        for dep in msg.get_all("Requires-Dist", []):
            # Strip extras and version specifiers
            dep_name = dep.split(";")[0].split("[")[0].strip()
            for op in [">=", "<=", "==", "!=", ">", "<", "~="]:
                if op in dep_name:
                    dep_name = dep_name.split(op)[0].strip()
                    break
            dependencies.append(dep_name)

        return PackageMetadata(
            name=name,
            version=version,
            format_type="sdist",
            description=msg.get("Summary"),
            maintainer=msg.get("Author") or msg.get("Maintainer"),
            homepage=msg.get("Home-page") or msg.get("Project-URL", "").split(",")[-1].strip(),
            license=msg.get("License"),
            dependencies=dependencies,
            raw_metadata=dict(msg.items()),
        )

    def _metadata_from_filename(self, filename: str) -> PackageMetadata:
        """Create metadata from filename when PKG-INFO is missing.

        Args:
            filename: Package filename

        Returns:
            PackageMetadata
        """
        name, version = self.parse_filename(filename)
        return PackageMetadata(
            name=name,
            version=version,
            format_type="sdist",
        )

    def _parse_name_from_filename(self, filename: str) -> str:
        """Parse package name from filename.

        Args:
            filename: Package filename

        Returns:
            Package name
        """
        name, _ = self.parse_filename(filename)
        return name

    def parse_metadata(self, path: Path) -> PackageMetadata:
        """Parse package metadata from sdist.

        Args:
            path: Path to .tar.gz file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    # PKG-INFO is usually at {name}-{version}/PKG-INFO
                    if member.name.endswith("/PKG-INFO") or member.name == "PKG-INFO":
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            return self._parse_pkginfo(content, path.name)

            # No PKG-INFO found
            logger.warning(f"No PKG-INFO in {path}, using filename")
            return self._metadata_from_filename(path.name)

        except tarfile.TarError as e:
            raise RuntimeError(f"Invalid tar.gz file: {e}") from e

    def validate_integrity(self, path: Path) -> bool:
        """Validate sdist package integrity.

        Args:
            path: Path to .tar.gz file

        Returns:
            True if package passes integrity validation

        Raises:
            RuntimeError: If validation cannot be performed
        """
        if not path.exists():
            raise RuntimeError(f"Package file not found: {path}")

        # Check it's a valid tar.gz
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()

                # Must have PKG-INFO or setup.py/pyproject.toml
                has_metadata = any(
                    n.endswith("/PKG-INFO") or n == "PKG-INFO"
                    for n in names
                )
                has_setup = any(
                    n.endswith("/setup.py") or n == "setup.py"
                    for n in names
                )
                has_pyproject = any(
                    n.endswith("/pyproject.toml") or n == "pyproject.toml"
                    for n in names
                )

                if not (has_metadata or has_setup or has_pyproject):
                    logger.warning("Missing PKG-INFO, setup.py, and pyproject.toml in sdist")
                    return False

                # Check for suspicious paths
                for name in names:
                    if ".." in name or name.startswith("/"):
                        logger.warning(f"Suspicious path in sdist: {name}")
                        return False

                return True

        except tarfile.TarError as e:
            logger.warning(f"Invalid tar.gz file: {e}")
            return False

    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in sdist package.

        Args:
            path: Path to .tar.gz file

        Returns:
            List of FileInfo describing package contents

        Raises:
            RuntimeError: If listing fails
        """
        try:
            file_list = []

            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    file_list.append(self._member_to_fileinfo(member))

            return file_list

        except tarfile.TarError as e:
            raise RuntimeError(f"Invalid tar.gz file: {e}") from e

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from sdist filename.

        Sdist filename format: {name}-{version}.tar.gz

        Args:
            filename: Package filename (e.g., 'requests-2.28.1.tar.gz')

        Returns:
            Tuple of (package_name, version)
        """
        name = filename

        # Remove extensions
        if name.endswith(".tar.gz"):
            name = name[:-7]
        elif name.endswith(".tgz"):
            name = name[:-4]

        # Find version by splitting on last hyphen followed by digit
        # This handles packages like "zope.interface-5.4.0"
        import re
        match = re.match(r"^(.+)-(\d+[\d.]*\w*)$", name)
        if match:
            return match.group(1).lower(), match.group(2)

        # Fallback: split on last hyphen
        if "-" in name:
            parts = name.rsplit("-", 1)
            return parts[0].lower(), parts[1]

        return name.lower(), "unknown"

    def has_setup_py(self, path: Path) -> bool:
        """Check if sdist contains setup.py.

        Args:
            path: Path to .tar.gz file

        Returns:
            True if sdist contains setup.py
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                for name in tar.getnames():
                    if name.endswith("/setup.py") or name == "setup.py":
                        return True
            return False
        except tarfile.TarError:
            return False

    def has_pyproject_toml(self, path: Path) -> bool:
        """Check if sdist contains pyproject.toml.

        Args:
            path: Path to .tar.gz file

        Returns:
            True if sdist contains pyproject.toml
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                for name in tar.getnames():
                    if name.endswith("/pyproject.toml") or name == "pyproject.toml":
                        return True
            return False
        except tarfile.TarError:
            return False
