"""Python wheel package format handler.

Implements extraction and metadata parsing for Python wheel (.whl) files.
"""

import email
import tempfile
import zipfile
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

logger = get_logger("format.wheel")


class WheelPackageFormat(PackageFormat):
    """Handler for Python wheel package format (.whl files).

    Wheel files are ZIP archives with a specific structure:
    - {distribution}-{version}.dist-info/WHEEL
    - {distribution}-{version}.dist-info/METADATA
    - {distribution}-{version}.dist-info/RECORD
    - {distribution}-{version}.data/ (optional)
    - Package modules
    """

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "wheel"

    @property
    def file_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return [".whl"]

    @property
    def capabilities(self) -> FormatCapabilities:
        """Return format capabilities."""
        return FormatCapabilities(
            supports_vulnerability_scan=True,
            supports_virus_scan=True,
            supports_integrity_check=True,
            supports_script_analysis=False,  # Pure wheels don't have install scripts
            supports_binary_check=True,  # Extension modules
            has_maintainer_scripts=False,
            has_binary_content=True,  # .so/.pyd extension modules
            has_signature=False,  # PEP 427 signatures rarely used
            preferred_vulnerability_scanner="pip-audit",
            alternative_scanners=["trivy", "grype"],
            script_types=set(),  # Wheels don't have install scripts
        )

    def detect(self, path: Path) -> bool:
        """Detect if file is a Python wheel package.

        Wheels are ZIP files with .whl extension.

        Args:
            path: Path to the file

        Returns:
            True if file is a wheel package
        """
        if not path.exists():
            return False

        # Check extension first
        if path.suffix.lower() != ".whl":
            return False

        # Verify it's a valid ZIP file
        try:
            with zipfile.ZipFile(path, "r") as zf:
                # Look for dist-info directory
                names = zf.namelist()
                return any(".dist-info/WHEEL" in name for name in names)
        except (zipfile.BadZipFile, IOError, OSError):
            pass

        return False

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract wheel package contents.

        Args:
            path: Path to .whl file
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

            with zipfile.ZipFile(path, "r") as zf:
                # Extract all files
                zf.extractall(dest)

                for info in zf.infolist():
                    # Build file info
                    file_list.append(self._zipinfo_to_fileinfo(info))

                    # Find metadata
                    if info.filename.endswith(".dist-info/METADATA"):
                        with zf.open(info.filename) as f:
                            metadata = self._parse_metadata(f.read().decode("utf-8", errors="replace"), path.name)

                    # Check for entry points console scripts (closest thing to scripts in wheels)
                    if info.filename.endswith(".dist-info/entry_points.txt"):
                        with zf.open(info.filename) as f:
                            scripts.extend(self._parse_entry_points(f.read().decode("utf-8", errors="replace")))

            if metadata is None:
                metadata = self._metadata_from_filename(path.name)

            return ExtractedContent(
                extract_path=dest,
                data_path=dest,  # Wheels extract directly
                file_list=file_list,
                scripts=scripts,
                metadata=metadata,
                temp_dir=temp_dir,
            )

        except zipfile.BadZipFile as e:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Invalid wheel file: {e}") from e
        except Exception as e:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Failed to extract package: {e}") from e

    def _zipinfo_to_fileinfo(self, info: zipfile.ZipInfo) -> FileInfo:
        """Convert ZipInfo to FileInfo.

        Args:
            info: ZipInfo object

        Returns:
            FileInfo object
        """
        # Determine file type
        is_dir = info.filename.endswith("/")
        file_type = "d" if is_dir else "-"

        # Convert ZIP external attributes to permission string
        perms = self._zip_perms_to_string(info.external_attr >> 16, is_dir)

        return FileInfo(
            path=info.filename.rstrip("/"),
            permissions=perms,
            size=info.file_size,
            owner="root",
            group="root",
            file_type=file_type,
        )

    def _zip_perms_to_string(self, mode: int, is_dir: bool) -> str:
        """Convert ZIP permission mode to string.

        Args:
            mode: Unix mode bits
            is_dir: Whether this is a directory

        Returns:
            Permission string
        """
        if mode == 0:
            # Default permissions if not set
            return "drwxr-xr-x" if is_dir else "-rw-r--r--"

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

    def _parse_metadata(self, content: str, filename: str) -> PackageMetadata:
        """Parse METADATA file content.

        Args:
            content: METADATA file content (email format)
            filename: Original filename for fallback

        Returns:
            PackageMetadata
        """
        # METADATA uses email.message format (RFC 822)
        msg = email.message_from_string(content)

        name = msg.get("Name", self._parse_name_from_filename(filename))
        version = msg.get("Version", "unknown")

        # Get dependencies
        dependencies = []
        for dep in msg.get_all("Requires-Dist", []):
            # Strip extras and version specifiers for simple list
            dep_name = dep.split(";")[0].split("[")[0].strip()
            # Also strip version comparisons
            for op in [">=", "<=", "==", "!=", ">", "<", "~="]:
                if op in dep_name:
                    dep_name = dep_name.split(op)[0].strip()
                    break
            dependencies.append(dep_name)

        return PackageMetadata(
            name=name,
            version=version,
            format_type="wheel",
            architecture=self._parse_platform_from_filename(filename),
            description=msg.get("Summary"),
            maintainer=msg.get("Author") or msg.get("Maintainer"),
            homepage=msg.get("Home-page") or msg.get("Project-URL", "").split(",")[-1].strip(),
            license=msg.get("License"),
            dependencies=dependencies,
            raw_metadata=dict(msg.items()),
        )

    def _parse_entry_points(self, content: str) -> List[ScriptInfo]:
        """Parse entry_points.txt to find console/GUI scripts.

        Args:
            content: entry_points.txt content

        Returns:
            List of ScriptInfo (informational only, not actual scripts)
        """
        scripts = []
        current_section = None

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
                continue

            if current_section in ("console_scripts", "gui_scripts") and "=" in line:
                name, target = line.split("=", 1)
                scripts.append(
                    ScriptInfo(
                        name=name.strip(),
                        script_type=ScriptType.OTHER,
                        content=f"Entry point: {target.strip()}",
                        interpreter="python",
                    )
                )

        return scripts

    def _metadata_from_filename(self, filename: str) -> PackageMetadata:
        """Create metadata from filename when METADATA is missing.

        Args:
            filename: Package filename

        Returns:
            PackageMetadata
        """
        name, version = self.parse_filename(filename)
        return PackageMetadata(
            name=name,
            version=version,
            format_type="wheel",
            architecture=self._parse_platform_from_filename(filename),
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

    def _parse_platform_from_filename(self, filename: str) -> Optional[str]:
        """Parse platform tag from wheel filename.

        Args:
            filename: Wheel filename

        Returns:
            Platform string or None
        """
        # Wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
        parts = filename.rstrip(".whl").rsplit("-", 3)
        if len(parts) >= 4:
            return parts[-1]  # Platform tag
        return None

    def parse_metadata(self, path: Path) -> PackageMetadata:
        """Parse package metadata from wheel.

        Args:
            path: Path to .whl file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dist-info/METADATA"):
                        with zf.open(name) as f:
                            content = f.read().decode("utf-8", errors="replace")
                            return self._parse_metadata(content, path.name)

            # No METADATA found
            logger.warning(f"No METADATA in {path}, using filename")
            return self._metadata_from_filename(path.name)

        except zipfile.BadZipFile as e:
            raise RuntimeError(f"Invalid wheel file: {e}") from e

    def validate_integrity(self, path: Path) -> bool:
        """Validate wheel package integrity.

        Args:
            path: Path to .whl file

        Returns:
            True if package passes integrity validation

        Raises:
            RuntimeError: If validation cannot be performed
        """
        if not path.exists():
            raise RuntimeError(f"Package file not found: {path}")

        # Check it's a valid ZIP
        try:
            with zipfile.ZipFile(path, "r") as zf:
                # Check for required files
                names = zf.namelist()

                # Must have dist-info directory with METADATA
                has_metadata = any(".dist-info/METADATA" in n for n in names)
                if not has_metadata:
                    logger.warning("Missing METADATA in wheel")
                    return False

                # Must have WHEEL file
                has_wheel = any(".dist-info/WHEEL" in n for n in names)
                if not has_wheel:
                    logger.warning("Missing WHEEL file in wheel")
                    return False

                # Test archive integrity
                bad_file = zf.testzip()
                if bad_file is not None:
                    logger.warning(f"Corrupted file in wheel: {bad_file}")
                    return False

                # Check for suspicious paths
                for name in names:
                    if ".." in name or name.startswith("/"):
                        logger.warning(f"Suspicious path in wheel: {name}")
                        return False

                return True

        except zipfile.BadZipFile as e:
            logger.warning(f"Invalid ZIP file: {e}")
            return False

    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in wheel package.

        Args:
            path: Path to .whl file

        Returns:
            List of FileInfo describing package contents

        Raises:
            RuntimeError: If listing fails
        """
        try:
            file_list = []

            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    file_list.append(self._zipinfo_to_fileinfo(info))

            return file_list

        except zipfile.BadZipFile as e:
            raise RuntimeError(f"Invalid wheel file: {e}") from e

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from .whl filename.

        Wheel filename format:
        {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl

        Args:
            filename: Package filename (e.g., 'requests-2.28.1-py3-none-any.whl')

        Returns:
            Tuple of (package_name, version)
        """
        name = filename
        if name.endswith(".whl"):
            name = name[:-4]

        # Split by hyphens, name-version are first two
        parts = name.split("-")

        if len(parts) >= 5:
            # Standard wheel: name-version-pytag-abitag-platform
            # Name can contain underscores (converted from hyphens)
            # Version is the part before py tag
            # Find where version ends by looking for py tag pattern
            for i in range(1, len(parts)):
                if parts[i].startswith("py") or parts[i].startswith("cp"):
                    # Everything before this is name+version
                    name_parts = parts[: i - 1]
                    version = parts[i - 1]
                    pkg_name = "_".join(name_parts) if name_parts else parts[0]
                    return pkg_name.replace("_", "-").lower(), version

        # Simple fallback: assume name-version-...
        if len(parts) >= 2:
            return parts[0].replace("_", "-").lower(), parts[1]

        return name.replace("_", "-").lower(), "unknown"

    def has_native_extensions(self, path: Path) -> bool:
        """Check if wheel contains native extension modules.

        Args:
            path: Path to .whl file

        Returns:
            True if wheel contains .so, .pyd, or .dll files
        """
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    lower_name = name.lower()
                    if lower_name.endswith((".so", ".pyd", ".dll")):
                        return True
            return False
        except zipfile.BadZipFile:
            return False
