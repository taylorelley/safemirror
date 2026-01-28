"""Alpine APK package format handler.

Implements extraction and metadata parsing for Alpine Linux packages.
"""

import subprocess
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

logger = get_logger("format.apk")


class ApkPackageFormat(PackageFormat):
    """Handler for Alpine APK package format (.apk files).

    APK packages are tar.gz archives containing:
    - .PKGINFO: Package metadata
    - .SIGN.RSA.*: Signature files
    - .pre-install, .post-install, etc.: Scripts
    - Package files
    """

    # Map of script names to ScriptType
    SCRIPT_TYPE_MAP = {
        ".pre-install": ScriptType.PRE_INSTALL,
        ".post-install": ScriptType.POST_INSTALL,
        ".pre-deinstall": ScriptType.PRE_REMOVE,
        ".post-deinstall": ScriptType.POST_REMOVE,
        ".pre-upgrade": ScriptType.PRE_INSTALL,
        ".post-upgrade": ScriptType.POST_INSTALL,
        ".trigger": ScriptType.TRIGGER,
    }

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "apk"

    @property
    def file_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return [".apk"]

    @property
    def capabilities(self) -> FormatCapabilities:
        """Return format capabilities."""
        return FormatCapabilities(
            supports_vulnerability_scan=True,
            supports_virus_scan=True,
            supports_integrity_check=True,
            supports_script_analysis=True,
            supports_binary_check=True,
            has_maintainer_scripts=True,
            has_binary_content=True,
            has_signature=True,
            preferred_vulnerability_scanner="trivy",
            alternative_scanners=["grype"],
            script_types={
                ScriptType.PRE_INSTALL,
                ScriptType.POST_INSTALL,
                ScriptType.PRE_REMOVE,
                ScriptType.POST_REMOVE,
                ScriptType.TRIGGER,
            },
        )

    def detect(self, path: Path) -> bool:
        """Detect if file is an Alpine APK package.

        APK files are gzip-compressed tar archives.

        Args:
            path: Path to the file

        Returns:
            True if file is an APK package
        """
        if not path.exists():
            return False

        # Check for gzip magic and .apk extension
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
                # Gzip magic: 1f 8b
                if magic == b"\x1f\x8b" and path.suffix.lower() == ".apk":
                    return True
        except (IOError, OSError):
            pass

        # Fall back to extension only
        return path.suffix.lower() == ".apk"

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract APK package contents.

        Args:
            path: Path to .apk file
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
            # Extract tar.gz archive
            data_path = dest / "data"
            data_path.mkdir(exist_ok=True)

            scripts = []
            file_list = []
            metadata_content = None

            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    # Handle metadata and scripts specially
                    if member.name == ".PKGINFO":
                        f = tar.extractfile(member)
                        if f:
                            metadata_content = f.read().decode("utf-8", errors="replace")
                    elif member.name.startswith(".") and member.name in self.SCRIPT_TYPE_MAP:
                        # Script file
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            scripts.append(
                                ScriptInfo(
                                    name=member.name,
                                    script_type=self.SCRIPT_TYPE_MAP[member.name],
                                    content=content,
                                    interpreter=self._detect_interpreter(content),
                                )
                            )
                    elif not member.name.startswith(".SIGN"):
                        # Regular file - extract to data path
                        # Build file info
                        file_list.append(self._member_to_fileinfo(member))

                        # Extract non-metadata files
                        if not member.name.startswith("."):
                            try:
                                tar.extract(member, data_path, filter="data")
                            except (tarfile.TarError, OSError) as e:
                                logger.warning(f"Failed to extract {member.name}: {e}")

            # Parse metadata
            if metadata_content:
                metadata = self._parse_pkginfo(metadata_content, path.name)
            else:
                metadata = self._metadata_from_filename(path.name)

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
            raise RuntimeError(f"Failed to extract APK: {e}") from e
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
        # Build permission string
        perms = self._mode_to_permissions(member.mode, member.isdir())

        file_type = "-"
        if member.isdir():
            file_type = "d"
        elif member.issym():
            file_type = "l"
        elif member.ischr():
            file_type = "c"
        elif member.isblk():
            file_type = "b"

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

        # Handle SUID/SGID/sticky
        if mode & 0o4000:  # SUID
            owner = owner[:2] + ("s" if owner[2] == "x" else "S")
        if mode & 0o2000:  # SGID
            group = group[:2] + ("s" if group[2] == "x" else "S")
        if mode & 0o1000:  # Sticky
            other = other[:2] + ("t" if other[2] == "x" else "T")

        return type_char + owner + group + other

    def _detect_interpreter(self, content: str) -> Optional[str]:
        """Detect script interpreter from shebang.

        Args:
            content: Script content

        Returns:
            Interpreter path or None
        """
        if content.startswith("#!"):
            first_line = content.split("\n", 1)[0]
            return first_line[2:].strip().split()[0]
        return "/bin/sh"  # Default for Alpine

    def _parse_pkginfo(self, content: str, filename: str) -> PackageMetadata:
        """Parse .PKGINFO file content.

        Args:
            content: .PKGINFO file content
            filename: Original filename for fallback

        Returns:
            PackageMetadata
        """
        info: Dict[str, str] = {}
        dependencies = []

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                if key == "depend":
                    dependencies.append(value)
                else:
                    info[key] = value

        # Extract version and release from pkgver (format: version-rN)
        pkgver = info.get("pkgver", "unknown")
        if "-r" in pkgver:
            version, release = pkgver.rsplit("-r", 1)
        else:
            version = pkgver
            release = "0"

        return PackageMetadata(
            name=info.get("pkgname", self._parse_name_from_filename(filename)),
            version=version,
            format_type="apk",
            architecture=info.get("arch", "noarch"),
            description=info.get("pkgdesc"),
            maintainer=info.get("maintainer"),
            homepage=info.get("url"),
            license=info.get("license"),
            dependencies=dependencies,
            release=release,
            raw_metadata=info,
        )

    def _metadata_from_filename(self, filename: str) -> PackageMetadata:
        """Create metadata from filename when .PKGINFO is missing.

        Args:
            filename: Package filename

        Returns:
            PackageMetadata
        """
        name, version = self.parse_filename(filename)
        return PackageMetadata(
            name=name,
            version=version,
            format_type="apk",
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
        """Parse package metadata from .PKGINFO.

        Args:
            path: Path to .apk file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name == ".PKGINFO":
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            return self._parse_pkginfo(content, path.name)

            # No .PKGINFO found, use filename
            logger.warning(f"No .PKGINFO in {path}, using filename")
            return self._metadata_from_filename(path.name)

        except tarfile.TarError as e:
            raise RuntimeError(f"Failed to read APK metadata: {e}") from e

    def validate_integrity(self, path: Path) -> bool:
        """Validate APK package integrity.

        Args:
            path: Path to .apk file

        Returns:
            True if package passes integrity validation

        Raises:
            RuntimeError: If validation cannot be performed
        """
        if not path.exists():
            raise RuntimeError(f"Package file not found: {path}")

        # Check it's a valid gzip
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
                if magic != b"\x1f\x8b":
                    logger.warning("Invalid gzip magic bytes")
                    return False
        except (IOError, OSError) as e:
            raise RuntimeError(f"Cannot read package file: {e}")

        # Try to open as tar.gz
        try:
            with tarfile.open(path, "r:gz") as tar:
                # Check for required .PKGINFO
                names = tar.getnames()
                if ".PKGINFO" not in names:
                    logger.warning("Missing .PKGINFO in APK")
                    return False

                # Check for suspicious paths
                for name in names:
                    if ".." in name or name.startswith("/"):
                        logger.warning(f"Suspicious path in APK: {name}")
                        return False

            return True

        except tarfile.TarError as e:
            logger.warning(f"Invalid APK archive: {e}")
            return False

    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in APK package.

        Args:
            path: Path to .apk file

        Returns:
            List of FileInfo describing package contents

        Raises:
            RuntimeError: If listing fails
        """
        try:
            file_list = []

            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    # Skip signature and metadata files
                    if member.name.startswith(".SIGN") or member.name == ".PKGINFO":
                        continue

                    file_list.append(self._member_to_fileinfo(member))

            return file_list

        except tarfile.TarError as e:
            raise RuntimeError(f"Failed to list APK contents: {e}") from e

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from .apk filename.

        Args:
            filename: Package filename (e.g., 'curl-7.83.1-r0.apk')

        Returns:
            Tuple of (package_name, version)
        """
        name = filename
        if name.endswith(".apk"):
            name = name[:-4]

        # Format: name-version-rN
        # Find the version by looking for pattern like -X.Y.Z-rN
        import re
        match = re.match(r"^(.+)-(\d+[\d.]*\w*)-r(\d+)$", name)
        if match:
            return match.group(1), match.group(2)

        # Fallback: split on last hyphen before -r
        if "-r" in name:
            base, _ = name.rsplit("-r", 1)
            parts = base.rsplit("-", 1)
            if len(parts) == 2:
                return parts[0], parts[1]

        # Simple fallback
        parts = name.rsplit("-", 2)
        if len(parts) >= 2:
            return parts[0], parts[1]

        return name, "unknown"
