"""Base classes and protocols for package format handlers.

Defines the interface that all package format handlers must implement,
along with common data structures for metadata and extracted content.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Set, Any


class ScriptType(Enum):
    """Types of package scripts across different formats."""

    # Debian/RPM/APK style
    PRE_INSTALL = auto()
    POST_INSTALL = auto()
    PRE_REMOVE = auto()
    POST_REMOVE = auto()
    CONFIG = auto()
    TRIGGER = auto()

    # Python specific
    SETUP_PY = auto()
    PYPROJECT_TOML = auto()

    # NPM specific
    NPM_PREINSTALL = auto()
    NPM_INSTALL = auto()
    NPM_POSTINSTALL = auto()
    NPM_PREUNINSTALL = auto()
    NPM_POSTUNINSTALL = auto()

    # Generic
    OTHER = auto()


@dataclass
class ScriptInfo:
    """Information about a package script."""

    name: str
    script_type: ScriptType
    content: str
    interpreter: Optional[str] = None  # e.g., "/bin/bash", "node"
    source_path: Optional[str] = None  # Path within package


@dataclass
class FileInfo:
    """Information about a file in the package."""

    path: str  # Relative path within package
    permissions: str  # Permission string (e.g., "-rwxr-xr-x")
    size: int = 0
    owner: str = "root"
    group: str = "root"
    file_type: str = "-"  # d=directory, l=symlink, -=regular, etc.
    link_target: Optional[str] = None  # For symlinks

    @property
    def is_suid(self) -> bool:
        """Check if file has SUID bit set."""
        return len(self.permissions) >= 4 and self.permissions[3] in "sS"

    @property
    def is_sgid(self) -> bool:
        """Check if file has SGID bit set."""
        return len(self.permissions) >= 7 and self.permissions[6] in "sS"

    @property
    def is_world_writable(self) -> bool:
        """Check if file is world-writable."""
        return len(self.permissions) >= 9 and self.permissions[8] == "w"

    @property
    def is_directory(self) -> bool:
        """Check if entry is a directory."""
        return self.file_type == "d"

    @property
    def is_device(self) -> bool:
        """Check if entry is a device file."""
        return self.file_type in ("b", "c")


@dataclass
class PackageMetadata:
    """Standardized package metadata across all formats."""

    name: str
    version: str
    format_type: str  # deb, rpm, wheel, sdist, npm, apk
    architecture: Optional[str] = None
    description: Optional[str] = None
    maintainer: Optional[str] = None
    homepage: Optional[str] = None
    license: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    # Format-specific identifiers
    release: Optional[str] = None  # RPM release number
    epoch: Optional[int] = None  # RPM/DEB epoch
    scope: Optional[str] = None  # NPM scope (@org/package)

    def get_package_key(self) -> str:
        """Get a unique key for this package.

        Returns:
            Format-appropriate package key string
        """
        if self.format_type == "deb":
            arch = self.architecture or "all"
            return f"{self.name}_{self.version}_{arch}"
        elif self.format_type == "rpm":
            arch = self.architecture or "noarch"
            release = self.release or "1"
            return f"{self.name}-{self.version}-{release}.{arch}"
        elif self.format_type in ("wheel", "sdist"):
            return f"{self.name}-{self.version}"
        elif self.format_type == "npm":
            if self.scope:
                return f"@{self.scope}/{self.name}@{self.version}"
            return f"{self.name}@{self.version}"
        elif self.format_type == "apk":
            release = self.release or "0"
            return f"{self.name}-{self.version}-r{release}"
        else:
            return f"{self.name}-{self.version}"


@dataclass
class ExtractedContent:
    """Result of extracting a package."""

    extract_path: Path  # Root directory of extracted content
    file_list: List[FileInfo]  # List of all files with metadata
    scripts: List[ScriptInfo]  # Maintainer/lifecycle scripts
    metadata: PackageMetadata
    data_path: Optional[Path] = None  # Path to extracted data files (vs control/metadata)
    temp_dir: Optional[Any] = None  # TemporaryDirectory handle for cleanup

    def get_files_by_type(self, file_type: str) -> List[FileInfo]:
        """Get files filtered by type."""
        return [f for f in self.file_list if f.file_type == file_type]

    def get_files_in_path(self, path_prefix: str) -> List[FileInfo]:
        """Get files under a specific path prefix."""
        return [f for f in self.file_list if f.path.startswith(path_prefix)]

    def get_suid_files(self) -> List[FileInfo]:
        """Get all SUID files."""
        return [f for f in self.file_list if f.is_suid]

    def get_sgid_files(self) -> List[FileInfo]:
        """Get all SGID files."""
        return [f for f in self.file_list if f.is_sgid]

    def get_world_writable_files(self) -> List[FileInfo]:
        """Get all world-writable files."""
        return [f for f in self.file_list if f.is_world_writable]

    def cleanup(self) -> None:
        """Clean up temporary extraction directory."""
        if self.temp_dir is not None:
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass


@dataclass
class FormatCapabilities:
    """Describes what security checks are applicable for a format."""

    supports_vulnerability_scan: bool = True
    supports_virus_scan: bool = True
    supports_integrity_check: bool = True
    supports_script_analysis: bool = True
    supports_binary_check: bool = True

    # More detailed capabilities
    has_maintainer_scripts: bool = True
    has_binary_content: bool = True
    has_signature: bool = False

    # Recommended scanner for this format
    preferred_vulnerability_scanner: str = "trivy"
    alternative_scanners: List[str] = field(default_factory=list)

    # Script types this format uses
    script_types: Set[ScriptType] = field(default_factory=set)


class PackageFormat(ABC):
    """Abstract base class for package format handlers.

    Each format handler must implement methods for:
    - Detecting if a file is of this format
    - Extracting package contents
    - Parsing package metadata
    - Validating package integrity
    - Generating package keys
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format identifier (e.g., 'deb', 'rpm', 'wheel')."""
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """Return supported file extensions (e.g., ['.deb'], ['.whl'])."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> FormatCapabilities:
        """Return capabilities describing what checks are applicable."""
        pass

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """Detect if a file is of this format.

        Uses magic bytes and/or file extension to determine format.

        Args:
            path: Path to the package file

        Returns:
            True if file is of this format
        """
        pass

    @abstractmethod
    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent:
        """Extract package contents.

        Args:
            path: Path to the package file
            dest: Optional destination directory. If None, creates temp directory.

        Returns:
            ExtractedContent with extracted files and metadata

        Raises:
            RuntimeError: If extraction fails
        """
        pass

    @abstractmethod
    def parse_metadata(self, path: Path) -> PackageMetadata:
        """Parse package metadata without full extraction.

        Args:
            path: Path to the package file

        Returns:
            PackageMetadata with parsed information

        Raises:
            RuntimeError: If parsing fails
        """
        pass

    @abstractmethod
    def validate_integrity(self, path: Path) -> bool:
        """Validate package format integrity.

        Performs format-specific validation (e.g., ar archive for .deb,
        rpm signature check for .rpm).

        Args:
            path: Path to the package file

        Returns:
            True if package passes integrity validation

        Raises:
            RuntimeError: If validation cannot be performed
        """
        pass

    @abstractmethod
    def get_file_list(self, path: Path) -> List[FileInfo]:
        """Get list of files in package without full extraction.

        Args:
            path: Path to the package file

        Returns:
            List of FileInfo describing package contents

        Raises:
            RuntimeError: If listing fails
        """
        pass

    def get_package_key(self, metadata: PackageMetadata) -> str:
        """Get unique package key from metadata.

        Default implementation delegates to PackageMetadata.get_package_key().

        Args:
            metadata: Package metadata

        Returns:
            Unique package key string
        """
        return metadata.get_package_key()

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from filename.

        Args:
            filename: Package filename

        Returns:
            Tuple of (name, version)
        """
        # Default implementation - subclasses should override
        name = Path(filename).stem
        for ext in self.file_extensions:
            if name.endswith(ext.lstrip(".")):
                name = name[: -len(ext.lstrip("."))]
        return name, "unknown"


class PackageFormatProtocol(Protocol):
    """Protocol for type checking package format handlers.

    This protocol defines the minimal interface required for a format handler.
    """

    @property
    def format_name(self) -> str: ...

    @property
    def file_extensions(self) -> List[str]: ...

    @property
    def capabilities(self) -> FormatCapabilities: ...

    def detect(self, path: Path) -> bool: ...

    def extract(self, path: Path, dest: Optional[Path] = None) -> ExtractedContent: ...

    def parse_metadata(self, path: Path) -> PackageMetadata: ...

    def validate_integrity(self, path: Path) -> bool: ...

    def get_file_list(self, path: Path) -> List[FileInfo]: ...
