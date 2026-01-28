"""NPM package format handler.

Implements extraction and metadata parsing for NPM packages (.tgz files).
"""

import json
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

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

logger = get_logger("format.npm")


class NpmPackageFormat(PackageFormat):
    """Handler for NPM package format (.tgz files).

    NPM packages are tar.gz archives containing:
    - package/package.json: Package metadata and scripts
    - package/: Package files
    """

    # Map of npm script names to ScriptType
    SCRIPT_TYPE_MAP = {
        "preinstall": ScriptType.NPM_PREINSTALL,
        "install": ScriptType.NPM_INSTALL,
        "postinstall": ScriptType.NPM_POSTINSTALL,
        "preuninstall": ScriptType.NPM_PREUNINSTALL,
        "postuninstall": ScriptType.NPM_POSTUNINSTALL,
        "prepare": ScriptType.NPM_INSTALL,  # Runs after install
        "prepublish": ScriptType.OTHER,
        "prepublishOnly": ScriptType.OTHER,
    }

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "npm"

    @property
    def file_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return [".tgz"]

    @property
    def capabilities(self) -> FormatCapabilities:
        """Return format capabilities."""
        return FormatCapabilities(
            supports_vulnerability_scan=True,
            supports_virus_scan=True,
            supports_integrity_check=True,
            supports_script_analysis=True,  # npm scripts can execute arbitrary code
            supports_binary_check=True,  # Native addons
            has_maintainer_scripts=True,  # npm lifecycle scripts
            has_binary_content=True,  # Native addons possible
            has_signature=False,
            preferred_vulnerability_scanner="npm-audit",
            alternative_scanners=["trivy", "grype"],
            script_types={
                ScriptType.NPM_PREINSTALL,
                ScriptType.NPM_INSTALL,
                ScriptType.NPM_POSTINSTALL,
                ScriptType.NPM_PREUNINSTALL,
                ScriptType.NPM_POSTUNINSTALL,
            },
        )

    def detect(self, path: Path) -> bool:
        """Detect if file is an NPM package.

        NPM packages are tar.gz files with package/package.json.

        Args:
            path: Path to the file

        Returns:
            True if file is an NPM package
        """
        if not path.exists():
            return False

        # Check extension
        if path.suffix.lower() != ".tgz":
            return False

        # Verify it's a valid tar.gz with package/package.json
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                return "package/package.json" in names
        except (tarfile.TarError, IOError, OSError):
            pass

        return False

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract NPM package contents.

        Args:
            path: Path to .tgz file
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

            with tarfile.open(path, "r:gz") as tar:
                # Validate paths first
                for member in tar.getmembers():
                    if member.name.startswith("/") or ".." in member.name:
                        raise RuntimeError(f"Unsafe path in archive: {member.name}")

                # Extract all files
                tar.extractall(dest, filter="data")

                # Build file list
                for member in tar.getmembers():
                    file_list.append(self._member_to_fileinfo(member))

                # Parse package.json
                try:
                    pkg_json_member = tar.getmember("package/package.json")
                    f = tar.extractfile(pkg_json_member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        pkg_json = json.loads(content)
                        metadata = self._parse_package_json(pkg_json, path.name)
                        scripts = self._extract_scripts(pkg_json)
                except KeyError:
                    logger.warning(f"No package/package.json in {path}")

            if metadata is None:
                metadata = self._metadata_from_filename(path.name)

            return ExtractedContent(
                extract_path=dest,
                data_path=dest / "package",
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
        except json.JSONDecodeError as e:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Invalid package.json: {e}") from e
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

    def _parse_package_json(self, pkg_json: Dict[str, Any], filename: str) -> PackageMetadata:
        """Parse package.json content.

        Args:
            pkg_json: Parsed package.json dict
            filename: Original filename for fallback

        Returns:
            PackageMetadata
        """
        name = pkg_json.get("name", self._parse_name_from_filename(filename))
        version = pkg_json.get("version", "unknown")

        # Parse scoped package name
        scope = None
        if name.startswith("@") and "/" in name:
            scope, name = name[1:].split("/", 1)

        # Get dependencies (all types)
        dependencies = []
        for dep_key in ["dependencies", "peerDependencies", "optionalDependencies"]:
            if dep_key in pkg_json and isinstance(pkg_json[dep_key], dict):
                dependencies.extend(pkg_json[dep_key].keys())

        # Get maintainer (can be string or object)
        maintainer = None
        author = pkg_json.get("author")
        if isinstance(author, str):
            maintainer = author
        elif isinstance(author, dict):
            maintainer = author.get("name", "")
            if author.get("email"):
                maintainer += f" <{author.get('email')}>"

        return PackageMetadata(
            name=name,
            version=version,
            format_type="npm",
            description=pkg_json.get("description"),
            maintainer=maintainer,
            homepage=pkg_json.get("homepage"),
            license=pkg_json.get("license"),
            dependencies=dependencies,
            scope=scope,
            raw_metadata=pkg_json,
        )

    def _extract_scripts(self, pkg_json: Dict[str, Any]) -> List[ScriptInfo]:
        """Extract lifecycle scripts from package.json.

        Args:
            pkg_json: Parsed package.json dict

        Returns:
            List of ScriptInfo
        """
        scripts = []
        scripts_section = pkg_json.get("scripts", {})

        if not isinstance(scripts_section, dict):
            return scripts

        for script_name, script_content in scripts_section.items():
            if not isinstance(script_content, str):
                continue

            script_type = self.SCRIPT_TYPE_MAP.get(script_name, ScriptType.OTHER)

            scripts.append(
                ScriptInfo(
                    name=script_name,
                    script_type=script_type,
                    content=script_content,
                    interpreter="sh",  # npm scripts run in shell
                    source_path="package/package.json",
                )
            )

        return scripts

    def _metadata_from_filename(self, filename: str) -> PackageMetadata:
        """Create metadata from filename when package.json is missing.

        Args:
            filename: Package filename

        Returns:
            PackageMetadata
        """
        name, version = self.parse_filename(filename)
        return PackageMetadata(
            name=name,
            version=version,
            format_type="npm",
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
        """Parse package metadata from NPM package.

        Args:
            path: Path to .tgz file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                try:
                    member = tar.getmember("package/package.json")
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        pkg_json = json.loads(content)
                        return self._parse_package_json(pkg_json, path.name)
                except KeyError:
                    pass

            # No package.json found
            logger.warning(f"No package.json in {path}, using filename")
            return self._metadata_from_filename(path.name)

        except tarfile.TarError as e:
            raise RuntimeError(f"Invalid tar.gz file: {e}") from e
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid package.json: {e}") from e

    def validate_integrity(self, path: Path) -> bool:
        """Validate NPM package integrity.

        Args:
            path: Path to .tgz file

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

                # Must have package/package.json
                if "package/package.json" not in names:
                    logger.warning("Missing package/package.json in NPM package")
                    return False

                # Validate package.json is valid JSON
                try:
                    member = tar.getmember("package/package.json")
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        pkg_json = json.loads(content)
                        if "name" not in pkg_json or "version" not in pkg_json:
                            logger.warning("Invalid package.json: missing name or version")
                            return False
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid package.json: {e}")
                    return False

                # Check for suspicious paths
                for name in names:
                    if ".." in name or name.startswith("/"):
                        logger.warning(f"Suspicious path in NPM package: {name}")
                        return False

                return True

        except tarfile.TarError as e:
            logger.warning(f"Invalid tar.gz file: {e}")
            return False

    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in NPM package.

        Args:
            path: Path to .tgz file

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
        """Parse package name and version from .tgz filename.

        NPM filename format: {name}-{version}.tgz or {scope}-{name}-{version}.tgz

        Args:
            filename: Package filename (e.g., 'lodash-4.17.21.tgz')

        Returns:
            Tuple of (package_name, version)
        """
        name = filename
        if name.endswith(".tgz"):
            name = name[:-4]

        # Find version by splitting on last hyphen followed by digit
        import re
        match = re.match(r"^(.+)-(\d+[\d.]*[-\w]*)$", name)
        if match:
            return match.group(1), match.group(2)

        # Fallback: split on last hyphen
        if "-" in name:
            parts = name.rsplit("-", 1)
            return parts[0], parts[1]

        return name, "unknown"

    def has_install_scripts(self, path: Path) -> bool:
        """Check if NPM package has install lifecycle scripts.

        Args:
            path: Path to .tgz file

        Returns:
            True if package has preinstall, install, or postinstall scripts
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                try:
                    member = tar.getmember("package/package.json")
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        pkg_json = json.loads(content)
                        scripts = pkg_json.get("scripts", {})
                        return any(
                            s in scripts
                            for s in ["preinstall", "install", "postinstall", "prepare"]
                        )
                except (KeyError, json.JSONDecodeError):
                    pass
            return False
        except tarfile.TarError:
            return False

    def has_native_addons(self, path: Path) -> bool:
        """Check if NPM package has native addons.

        Args:
            path: Path to .tgz file

        Returns:
            True if package likely has native addons (.node, binding.gyp)
        """
        try:
            with tarfile.open(path, "r:gz") as tar:
                for name in tar.getnames():
                    lower_name = name.lower()
                    # Check for native addon indicators
                    if lower_name.endswith(".node"):
                        return True
                    if lower_name.endswith("/binding.gyp") or lower_name == "package/binding.gyp":
                        return True
            return False
        except tarfile.TarError:
            return False
