"""Debian package (.deb) format handler.

Implements extraction and metadata parsing for Debian packages using dpkg-deb.
"""

import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Set

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

logger = get_logger("format.deb")


class DebPackageFormat(PackageFormat):
    """Handler for Debian package format (.deb files).

    Debian packages are ar archives containing:
    - debian-binary: Version information
    - control.tar.gz/xz: Control files and maintainer scripts
    - data.tar.gz/xz/zst: Package contents
    """

    # Map of script names to ScriptType
    SCRIPT_TYPE_MAP = {
        "preinst": ScriptType.PRE_INSTALL,
        "postinst": ScriptType.POST_INSTALL,
        "prerm": ScriptType.PRE_REMOVE,
        "postrm": ScriptType.POST_REMOVE,
        "config": ScriptType.CONFIG,
        "templates": ScriptType.OTHER,
        "triggers": ScriptType.TRIGGER,
    }

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "deb"

    @property
    def file_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return [".deb", ".udeb"]

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
            has_signature=False,  # .deb files themselves aren't signed
            preferred_vulnerability_scanner="trivy",
            alternative_scanners=["grype"],
            script_types={
                ScriptType.PRE_INSTALL,
                ScriptType.POST_INSTALL,
                ScriptType.PRE_REMOVE,
                ScriptType.POST_REMOVE,
                ScriptType.CONFIG,
                ScriptType.TRIGGER,
            },
        )

    def detect(self, path: Path) -> bool:
        """Detect if file is a Debian package.

        Checks for ar archive magic bytes and .deb extension.

        Args:
            path: Path to the file

        Returns:
            True if file is a Debian package
        """
        if not path.exists():
            return False

        # Check magic bytes (ar archive: "!<arch>\n")
        try:
            with open(path, "rb") as f:
                magic = f.read(8)
                if magic.startswith(b"!<arch>"):
                    return True
        except (IOError, OSError):
            pass

        # Fall back to extension check
        return path.suffix.lower() in [".deb", ".udeb"]

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract Debian package contents.

        Args:
            path: Path to .deb file
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
            # Extract data files
            data_path = dest / "data"
            data_path.mkdir(exist_ok=True)
            self._extract_data(path, data_path)

            # Get file list
            file_list = self.get_file_list(path)

            # Extract and parse scripts
            scripts = self._extract_scripts(path)

            # Parse metadata
            metadata = self.parse_metadata(path)

            return ExtractedContent(
                extract_path=dest,
                data_path=data_path,
                file_list=file_list,
                scripts=scripts,
                metadata=metadata,
                temp_dir=temp_dir,
            )

        except Exception as e:
            # Clean up on failure
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Failed to extract package: {e}") from e

    def _extract_data(self, path: Path, dest: Path) -> None:
        """Extract data.tar.* from package.

        Args:
            path: Path to .deb file
            dest: Destination directory

        Raises:
            RuntimeError: If extraction fails
        """
        try:
            result = subprocess.run(
                ["dpkg-deb", "-x", str(path), str(dest)],
                capture_output=True,
                check=True,
                timeout=60,
            )
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else str(e)
            raise RuntimeError(f"dpkg-deb extraction failed: {stderr}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("Package extraction timed out") from e

    def _extract_scripts(self, path: Path) -> List[ScriptInfo]:
        """Extract maintainer scripts from package.

        Args:
            path: Path to .deb file

        Returns:
            List of ScriptInfo objects

        Raises:
            RuntimeError: If extraction fails
        """
        scripts = []

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract control archive
                subprocess.run(
                    ["dpkg-deb", "-e", str(path), temp_dir],
                    capture_output=True,
                    check=True,
                    timeout=30,
                )

                # Read each script file
                for script_name, script_type in self.SCRIPT_TYPE_MAP.items():
                    script_path = Path(temp_dir) / script_name
                    if script_path.exists():
                        try:
                            content = script_path.read_text(
                                encoding="utf-8", errors="replace"
                            )
                            # Parse shebang
                            interpreter = None
                            if content.startswith("#!"):
                                first_line = content.split("\n", 1)[0]
                                interpreter = first_line[2:].strip().split()[0]

                            scripts.append(
                                ScriptInfo(
                                    name=script_name,
                                    script_type=script_type,
                                    content=content,
                                    interpreter=interpreter,
                                    source_path=f"DEBIAN/{script_name}",
                                )
                            )
                        except (IOError, OSError) as e:
                            logger.warning(f"Failed to read script {script_name}: {e}")

        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else str(e)
            raise RuntimeError(f"Failed to extract control files: {stderr}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("Control extraction timed out") from e

        return scripts

    def parse_metadata(self, path: Path) -> PackageMetadata:
        """Parse package metadata from control file.

        Args:
            path: Path to .deb file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        try:
            result = subprocess.run(
                ["dpkg-deb", "-f", str(path)],
                capture_output=True,
                check=True,
                timeout=30,
            )

            control_content = result.stdout.decode("utf-8", errors="replace")
            return self._parse_control_content(control_content, path.name)

        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else str(e)
            raise RuntimeError(f"Failed to read control file: {stderr}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("Metadata parsing timed out") from e

    def _parse_control_content(
        self, content: str, filename: str
    ) -> PackageMetadata:
        """Parse control file content into PackageMetadata.

        Args:
            content: Control file content
            filename: Original package filename (for fallback)

        Returns:
            PackageMetadata instance
        """
        # Parse RFC822-style control file
        raw_metadata = {}
        current_key = None
        current_value = []

        for line in content.split("\n"):
            if line.startswith(" ") or line.startswith("\t"):
                # Continuation of previous field
                if current_key:
                    current_value.append(line.strip())
            elif ":" in line:
                # Save previous field
                if current_key:
                    raw_metadata[current_key] = "\n".join(current_value)

                # Parse new field
                key, value = line.split(":", 1)
                current_key = key.strip()
                current_value = [value.strip()]
            else:
                # Empty line or end
                if current_key:
                    raw_metadata[current_key] = "\n".join(current_value)
                current_key = None
                current_value = []

        # Save last field
        if current_key:
            raw_metadata[current_key] = "\n".join(current_value)

        # Extract standard fields
        name = raw_metadata.get("Package", self._parse_name_from_filename(filename))
        version = raw_metadata.get("Version", "unknown")
        architecture = raw_metadata.get("Architecture", "all")

        # Parse dependencies
        dependencies = []
        for dep_field in ["Depends", "Pre-Depends", "Recommends"]:
            if dep_field in raw_metadata:
                deps = raw_metadata[dep_field].replace("\n", " ").split(",")
                dependencies.extend([d.strip() for d in deps if d.strip()])

        return PackageMetadata(
            name=name,
            version=version,
            format_type="deb",
            architecture=architecture,
            description=raw_metadata.get("Description"),
            maintainer=raw_metadata.get("Maintainer"),
            homepage=raw_metadata.get("Homepage"),
            license=raw_metadata.get("License"),
            dependencies=dependencies,
            raw_metadata=raw_metadata,
        )

    def _parse_name_from_filename(self, filename: str) -> str:
        """Parse package name from filename as fallback.

        Args:
            filename: Package filename

        Returns:
            Package name
        """
        # Format: package-name_version_architecture.deb
        name = filename
        for ext in self.file_extensions:
            if name.endswith(ext):
                name = name[: -len(ext)]
        parts = name.split("_")
        return parts[0] if parts else name

    def validate_integrity(self, path: Path) -> bool:
        """Validate package format integrity.

        Args:
            path: Path to .deb file

        Returns:
            True if package passes integrity validation

        Raises:
            RuntimeError: If validation cannot be performed
        """
        if not path.exists():
            raise RuntimeError(f"Package file not found: {path}")

        # Check file is not empty
        if path.stat().st_size == 0:
            logger.warning("Package file is empty")
            return False

        # Check ar archive magic
        try:
            with open(path, "rb") as f:
                magic = f.read(8)
                if not magic.startswith(b"!<arch>"):
                    logger.warning("Invalid package file header (not ar archive)")
                    return False
        except (IOError, OSError) as e:
            raise RuntimeError(f"Cannot read package file: {e}") from e

        # Validate with dpkg-deb
        try:
            result = subprocess.run(
                ["dpkg-deb", "--info", str(path)],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode() if result.stderr else "Unknown error"
                logger.warning(f"dpkg-deb validation failed: {stderr}")
                return False

            return True

        except subprocess.TimeoutExpired:
            raise RuntimeError("Package validation timed out")

    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in package.

        Args:
            path: Path to .deb file

        Returns:
            List of FileInfo describing package contents

        Raises:
            RuntimeError: If listing fails
        """
        try:
            result = subprocess.run(
                ["dpkg-deb", "-c", str(path)],
                capture_output=True,
                check=True,
                timeout=60,
            )

            output = result.stdout.decode("utf-8", errors="replace")
            return self._parse_file_list(output)

        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else str(e)
            raise RuntimeError(f"Failed to list package contents: {stderr}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("File listing timed out") from e

    def _parse_file_list(self, output: str) -> List[FileInfo]:
        """Parse dpkg-deb -c output into FileInfo list.

        Args:
            output: dpkg-deb -c output

        Returns:
            List of FileInfo objects
        """
        file_list = []

        for line in output.splitlines():
            # Format: -rwxr-xr-x root/root      12345 2023-04-18 12:34 ./usr/bin/foo
            # Or:     lrwxrwxrwx root/root          0 2023-04-18 12:34 ./usr/bin/bar -> baz
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue

            permissions = parts[0]
            owner_group = parts[1]
            size_str = parts[2]
            # parts[3] is date, parts[4] is time
            path_part = parts[5]

            # Parse file type from permissions
            file_type = permissions[0] if permissions else "-"

            # Parse owner/group
            if "/" in owner_group:
                owner, group = owner_group.split("/", 1)
            else:
                owner, group = owner_group, owner_group

            # Parse size
            try:
                size = int(size_str)
            except ValueError:
                size = 0

            # Parse path and link target
            file_path = path_part.lstrip("./")
            link_target = None
            if " -> " in path_part:
                file_path, link_target = path_part.split(" -> ", 1)
                file_path = file_path.lstrip("./")

            file_list.append(
                FileInfo(
                    path=file_path,
                    permissions=permissions,
                    size=size,
                    owner=owner,
                    group=group,
                    file_type=file_type,
                    link_target=link_target,
                )
            )

        return file_list

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from .deb filename.

        Args:
            filename: Package filename (e.g., 'curl_7.81.0-1ubuntu1.16_amd64.deb')

        Returns:
            Tuple of (package_name, version)
        """
        # Remove extension
        name = filename
        for ext in self.file_extensions:
            if name.endswith(ext):
                name = name[: -len(ext)]
                break

        # Split by underscore: name_version_arch
        parts = name.split("_")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return name, "unknown"
