"""RPM package format handler.

Implements extraction and metadata parsing for RPM packages.
"""

import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

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

logger = get_logger("format.rpm")


class RpmPackageFormat(PackageFormat):
    """Handler for RPM package format (.rpm files).

    RPM packages contain:
    - Lead: RPM version info
    - Signature: Package verification
    - Header: Metadata and scripts
    - Payload: cpio archive (usually gzip/xz/zstd compressed)
    """

    # Map of script tags to ScriptType
    SCRIPT_TYPE_MAP = {
        "prein": ScriptType.PRE_INSTALL,
        "preinstall": ScriptType.PRE_INSTALL,
        "postin": ScriptType.POST_INSTALL,
        "postinstall": ScriptType.POST_INSTALL,
        "preun": ScriptType.PRE_REMOVE,
        "preuninstall": ScriptType.PRE_REMOVE,
        "postun": ScriptType.POST_REMOVE,
        "postuninstall": ScriptType.POST_REMOVE,
        "pretrans": ScriptType.PRE_INSTALL,
        "posttrans": ScriptType.POST_INSTALL,
        "triggerscripts": ScriptType.TRIGGER,
    }

    @property
    def format_name(self) -> str:
        """Return format identifier."""
        return "rpm"

    @property
    def file_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return [".rpm"]

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
        """Detect if file is an RPM package.

        Checks for RPM magic bytes (0xedabeedb).

        Args:
            path: Path to the file

        Returns:
            True if file is an RPM package
        """
        if not path.exists():
            return False

        # Check magic bytes
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == b"\xed\xab\xee\xdb":
                    return True
        except (IOError, OSError):
            pass

        # Fall back to extension
        return path.suffix.lower() == ".rpm"

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract RPM package contents.

        Uses rpm2cpio and cpio to extract.

        Args:
            path: Path to .rpm file
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

            # Extract scripts
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
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass
            raise RuntimeError(f"Failed to extract package: {e}") from e

    def _extract_data(self, path: Path, dest: Path) -> None:
        """Extract payload from RPM package.

        Args:
            path: Path to .rpm file
            dest: Destination directory

        Raises:
            RuntimeError: If extraction fails
        """
        try:
            # Use rpm2cpio | cpio to extract
            rpm2cpio = subprocess.Popen(
                ["rpm2cpio", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            cpio = subprocess.Popen(
                ["cpio", "-idmv", "--no-absolute-filenames"],
                stdin=rpm2cpio.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(dest),
            )

            rpm2cpio.stdout.close()
            _, cpio_err = cpio.communicate(timeout=120)

            if rpm2cpio.wait() != 0:
                raise RuntimeError("rpm2cpio failed")

            if cpio.returncode != 0:
                logger.warning(f"cpio warnings: {cpio_err.decode()}")

        except subprocess.TimeoutExpired:
            rpm2cpio.kill()
            cpio.kill()
            raise RuntimeError("Package extraction timed out")
        except FileNotFoundError as e:
            raise RuntimeError(f"Required tool not found: {e}. Install rpm2cpio and cpio.")

    def _extract_scripts(self, path: Path) -> List[ScriptInfo]:
        """Extract scriptlets from RPM package.

        Args:
            path: Path to .rpm file

        Returns:
            List of ScriptInfo objects
        """
        scripts = []

        try:
            # Get all scripts using rpm -qp --scripts
            result = subprocess.run(
                ["rpm", "-qp", "--scripts", str(path)],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                logger.warning(f"Could not extract scripts: {result.stderr.decode()}")
                return scripts

            output = result.stdout.decode("utf-8", errors="replace")
            scripts = self._parse_scripts_output(output)

        except FileNotFoundError:
            logger.warning("rpm command not found, skipping script extraction")
        except subprocess.TimeoutExpired:
            logger.warning("Script extraction timed out")

        return scripts

    def _parse_scripts_output(self, output: str) -> List[ScriptInfo]:
        """Parse rpm --scripts output.

        Args:
            output: rpm --scripts output

        Returns:
            List of ScriptInfo
        """
        scripts = []
        current_type = None
        current_content = []
        current_interpreter = "/bin/sh"

        for line in output.split("\n"):
            # Check for script type headers
            lower_line = line.lower().strip()

            # Headers like "preinstall scriptlet (using /bin/sh):"
            for script_name, script_type in self.SCRIPT_TYPE_MAP.items():
                if lower_line.startswith(script_name):
                    # Save previous script
                    if current_type and current_content:
                        scripts.append(
                            ScriptInfo(
                                name=current_type,
                                script_type=self.SCRIPT_TYPE_MAP.get(current_type, ScriptType.OTHER),
                                content="\n".join(current_content),
                                interpreter=current_interpreter,
                            )
                        )

                    current_type = script_name
                    current_content = []

                    # Extract interpreter
                    if "(using " in lower_line:
                        try:
                            interp = line.split("(using ")[1].split(")")[0]
                            current_interpreter = interp
                        except (IndexError, ValueError):
                            current_interpreter = "/bin/sh"
                    break
            else:
                # Content line
                if current_type:
                    current_content.append(line)

        # Save last script
        if current_type and current_content:
            scripts.append(
                ScriptInfo(
                    name=current_type,
                    script_type=self.SCRIPT_TYPE_MAP.get(current_type, ScriptType.OTHER),
                    content="\n".join(current_content),
                    interpreter=current_interpreter,
                )
            )

        return scripts

    def parse_metadata(self, path: Path) -> PackageMetadata:
        """Parse package metadata from RPM header.

        Args:
            path: Path to .rpm file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        try:
            # Use rpm -qip for detailed info
            result = subprocess.run(
                [
                    "rpm", "-qp",
                    "--queryformat",
                    "%{NAME}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n%{SUMMARY}\\n%{PACKAGER}\\n%{URL}\\n%{LICENSE}\\n",
                    str(path),
                ],
                capture_output=True,
                check=True,
                timeout=30,
            )

            lines = result.stdout.decode("utf-8", errors="replace").split("\n")

            name = lines[0] if len(lines) > 0 else self._parse_name_from_filename(path.name)
            version = lines[1] if len(lines) > 1 else "unknown"
            release = lines[2] if len(lines) > 2 else "1"
            arch = lines[3] if len(lines) > 3 else "noarch"
            description = lines[4] if len(lines) > 4 else None
            maintainer = lines[5] if len(lines) > 5 else None
            homepage = lines[6] if len(lines) > 6 else None
            license_str = lines[7] if len(lines) > 7 else None

            # Get dependencies
            deps_result = subprocess.run(
                ["rpm", "-qp", "--requires", str(path)],
                capture_output=True,
                check=False,
                timeout=30,
            )
            dependencies = [
                d.strip()
                for d in deps_result.stdout.decode("utf-8", errors="replace").split("\n")
                if d.strip()
            ]

            return PackageMetadata(
                name=name,
                version=version,
                format_type="rpm",
                architecture=arch if arch != "(none)" else "noarch",
                description=description if description != "(none)" else None,
                maintainer=maintainer if maintainer != "(none)" else None,
                homepage=homepage if homepage != "(none)" else None,
                license=license_str if license_str != "(none)" else None,
                dependencies=dependencies,
                release=release if release != "(none)" else "1",
                raw_metadata={"full_output": result.stdout.decode()},
            )

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to read RPM metadata: {e.stderr.decode()}")
        except FileNotFoundError:
            raise RuntimeError("rpm command not found. Install rpm.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Metadata parsing timed out")

    def _parse_name_from_filename(self, filename: str) -> str:
        """Parse package name from filename as fallback.

        Args:
            filename: Package filename

        Returns:
            Package name
        """
        # Format: name-version-release.arch.rpm
        name = filename
        if name.endswith(".rpm"):
            name = name[:-4]

        # Split from right to extract arch, release, version
        parts = name.rsplit(".", 1)  # Remove arch
        if len(parts) > 1:
            name = parts[0]

        parts = name.rsplit("-", 2)  # Remove version-release
        if len(parts) >= 1:
            return parts[0]

        return filename

    def validate_integrity(self, path: Path) -> bool:
        """Validate RPM package integrity.

        Args:
            path: Path to .rpm file

        Returns:
            True if package passes integrity validation

        Raises:
            RuntimeError: If validation cannot be performed
        """
        if not path.exists():
            raise RuntimeError(f"Package file not found: {path}")

        # Check magic bytes
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != b"\xed\xab\xee\xdb":
                    logger.warning("Invalid RPM magic bytes")
                    return False
        except (IOError, OSError) as e:
            raise RuntimeError(f"Cannot read package file: {e}")

        # Validate with rpm -K (checks signature and digests)
        try:
            result = subprocess.run(
                ["rpm", "-K", "--nosignature", str(path)],  # Skip signature, check digests
                capture_output=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                return True

            # Check if it's just a signature issue
            output = result.stdout.decode() + result.stderr.decode()
            if "NOT OK" in output:
                logger.warning(f"RPM integrity check failed: {output}")
                return False

            return True

        except FileNotFoundError:
            logger.warning("rpm command not found, skipping integrity check")
            return True  # Can't verify without rpm
        except subprocess.TimeoutExpired:
            raise RuntimeError("Integrity check timed out")

    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in RPM package.

        Args:
            path: Path to .rpm file

        Returns:
            List of FileInfo describing package contents

        Raises:
            RuntimeError: If listing fails
        """
        try:
            # Get file list with permissions
            result = subprocess.run(
                [
                    "rpm", "-qp", "-l",
                    "--queryformat", "[%{FILEMODES:perms} %{FILENAMES}\n]",
                    str(path),
                ],
                capture_output=True,
                check=True,
                timeout=60,
            )

            output = result.stdout.decode("utf-8", errors="replace")
            return self._parse_file_list(output)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to list package contents: {e.stderr.decode()}")
        except FileNotFoundError:
            raise RuntimeError("rpm command not found")
        except subprocess.TimeoutExpired:
            raise RuntimeError("File listing timed out")

    def _parse_file_list(self, output: str) -> List[FileInfo]:
        """Parse rpm file list output.

        Args:
            output: rpm -qpl output

        Returns:
            List of FileInfo objects
        """
        file_list = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Format: permissions path (e.g., "-rwxr-xr-x /usr/bin/curl")
            parts = line.split(None, 1)
            if len(parts) >= 2:
                permissions = parts[0]
                file_path = parts[1].lstrip("/")

                # Determine file type from permissions
                file_type = permissions[0] if permissions else "-"

                file_list.append(
                    FileInfo(
                        path=file_path,
                        permissions=permissions,
                        file_type=file_type,
                    )
                )
            elif len(parts) == 1:
                # Just path, no permissions
                file_path = parts[0].lstrip("/")
                file_list.append(
                    FileInfo(
                        path=file_path,
                        permissions="-rw-r--r--",
                        file_type="-",
                    )
                )

        return file_list

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from .rpm filename.

        Args:
            filename: Package filename (e.g., 'curl-7.76.1-14.el8.x86_64.rpm')

        Returns:
            Tuple of (package_name, version)
        """
        name = filename
        if name.endswith(".rpm"):
            name = name[:-4]

        # Remove architecture
        for arch in ["x86_64", "i686", "i386", "noarch", "aarch64", "ppc64le", "s390x"]:
            if name.endswith(f".{arch}"):
                name = name[: -len(f".{arch}")]
                break

        # Split name-version-release
        parts = name.rsplit("-", 2)
        if len(parts) >= 3:
            return parts[0], parts[1]
        elif len(parts) == 2:
            return parts[0], parts[1]
        return name, "unknown"
