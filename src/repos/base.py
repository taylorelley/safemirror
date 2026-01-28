"""Base classes and protocols for repository managers.

Defines the interface that all repository managers must implement,
along with common data structures for sync and diff operations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Set, Any


class SyncStatus(Enum):
    """Status of a sync operation."""

    SUCCESS = auto()
    PARTIAL = auto()  # Some packages failed
    FAILED = auto()
    NO_CHANGES = auto()


class DiffType(Enum):
    """Type of change detected in diff."""

    ADDED = auto()
    REMOVED = auto()
    UPGRADED = auto()
    DOWNGRADED = auto()


@dataclass
class PackageRef:
    """Reference to a package in a repository."""

    name: str
    version: str
    architecture: Optional[str] = None
    format_type: Optional[str] = None  # deb, rpm, wheel, npm, apk
    checksum: Optional[str] = None
    size: Optional[int] = None
    path: Optional[str] = None  # Path within repository

    def get_key(self) -> str:
        """Get unique key for this package reference."""
        if self.format_type == "deb":
            arch = self.architecture or "all"
            return f"{self.name}_{self.version}_{arch}"
        elif self.format_type == "rpm":
            arch = self.architecture or "noarch"
            return f"{self.name}-{self.version}.{arch}"
        elif self.format_type in ("wheel", "sdist"):
            return f"{self.name}-{self.version}"
        elif self.format_type == "npm":
            return f"{self.name}@{self.version}"
        elif self.format_type == "apk":
            return f"{self.name}-{self.version}"
        else:
            return f"{self.name}-{self.version}"


@dataclass
class DiffEntry:
    """Entry in a diff result."""

    package: PackageRef
    diff_type: DiffType
    old_version: Optional[str] = None  # For upgrades/downgrades


@dataclass
class SyncResult:
    """Result of a repository sync operation."""

    status: SyncStatus
    mirror_name: str
    packages_synced: int
    packages_failed: int
    sync_date: str
    snapshot_name: Optional[str] = None
    error_message: Optional[str] = None
    failed_packages: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def is_success(self) -> bool:
        """Check if sync was successful."""
        return self.status in (SyncStatus.SUCCESS, SyncStatus.NO_CHANGES)


@dataclass
class DiffResult:
    """Result of comparing two snapshots."""

    old_snapshot: str
    new_snapshot: str
    entries: List[DiffEntry]
    diff_date: str
    error_message: Optional[str] = None

    @property
    def added_packages(self) -> List[PackageRef]:
        """Get list of added packages."""
        return [e.package for e in self.entries if e.diff_type == DiffType.ADDED]

    @property
    def removed_packages(self) -> List[PackageRef]:
        """Get list of removed packages."""
        return [e.package for e in self.entries if e.diff_type == DiffType.REMOVED]

    @property
    def upgraded_packages(self) -> List[PackageRef]:
        """Get list of upgraded packages."""
        return [e.package for e in self.entries if e.diff_type == DiffType.UPGRADED]

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return len(self.entries) > 0

    def get_changed_package_keys(self) -> Set[str]:
        """Get set of all changed package keys."""
        return {e.package.get_key() for e in self.entries}


@dataclass
class RepoConfig:
    """Configuration for a repository mirror."""

    name: str
    upstream_url: str
    format_type: str  # deb, rpm, pypi, npm, apk
    distributions: List[str] = field(default_factory=list)  # e.g., ["jammy", "jammy-updates"]
    components: List[str] = field(default_factory=list)  # e.g., ["main", "universe"]
    architectures: List[str] = field(default_factory=list)  # e.g., ["amd64", "arm64"]
    gpg_key_url: Optional[str] = None
    gpg_key_id: Optional[str] = None
    extra_options: Dict[str, Any] = field(default_factory=dict)


class RepositoryManager(ABC):
    """Abstract base class for repository managers.

    Each repository manager must implement methods for:
    - Syncing from upstream
    - Creating and managing snapshots
    - Diffing snapshots
    - Filtering and publishing packages
    """

    @property
    @abstractmethod
    def manager_name(self) -> str:
        """Return the manager identifier (e.g., 'aptly', 'createrepo')."""
        pass

    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """Return list of supported package formats."""
        pass

    @abstractmethod
    def sync(self, config: RepoConfig) -> SyncResult:
        """Sync repository from upstream.

        Args:
            config: Repository configuration

        Returns:
            SyncResult with sync status

        Raises:
            RuntimeError: If sync fails critically
        """
        pass

    @abstractmethod
    def create_snapshot(self, mirror_name: str, snapshot_name: Optional[str] = None) -> str:
        """Create a snapshot from current mirror state.

        Args:
            mirror_name: Name of the mirror to snapshot
            snapshot_name: Optional specific snapshot name (auto-generated if None)

        Returns:
            Name of created snapshot

        Raises:
            RuntimeError: If snapshot creation fails
        """
        pass

    @abstractmethod
    def diff_snapshots(self, old_snapshot: str, new_snapshot: str) -> DiffResult:
        """Compare two snapshots and return differences.

        Args:
            old_snapshot: Name of older snapshot
            new_snapshot: Name of newer snapshot

        Returns:
            DiffResult with list of changes

        Raises:
            RuntimeError: If diff fails
        """
        pass

    @abstractmethod
    def filter_packages(
        self,
        source_snapshot: str,
        dest_snapshot: str,
        approved_packages: List[str],
    ) -> bool:
        """Filter snapshot to only include approved packages.

        Args:
            source_snapshot: Source snapshot name
            dest_snapshot: Destination snapshot name
            approved_packages: List of approved package keys

        Returns:
            True if filtering succeeded

        Raises:
            RuntimeError: If filtering fails
        """
        pass

    @abstractmethod
    def publish(
        self,
        snapshot_name: str,
        distribution: str,
        prefix: str = "",
    ) -> bool:
        """Publish a snapshot to make it available.

        Args:
            snapshot_name: Snapshot to publish
            distribution: Distribution name (e.g., "jammy")
            prefix: Optional prefix for publishing

        Returns:
            True if publishing succeeded

        Raises:
            RuntimeError: If publishing fails
        """
        pass

    @abstractmethod
    def get_package_path(self, package_key: str, mirror_name: str) -> Optional[Path]:
        """Get filesystem path to a package file.

        Args:
            package_key: Package identifier
            mirror_name: Name of the mirror

        Returns:
            Path to package file or None if not found
        """
        pass

    @abstractmethod
    def list_snapshots(self, mirror_name: Optional[str] = None) -> List[str]:
        """List available snapshots.

        Args:
            mirror_name: Optional filter by mirror name

        Returns:
            List of snapshot names
        """
        pass

    @abstractmethod
    def list_mirrors(self) -> List[str]:
        """List configured mirrors.

        Returns:
            List of mirror names
        """
        pass

    def generate_snapshot_name(self, prefix: str = "staging") -> str:
        """Generate a timestamped snapshot name.

        Args:
            prefix: Prefix for snapshot name

        Returns:
            Generated snapshot name
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"{prefix}-{timestamp}"


class RepositoryManagerProtocol(Protocol):
    """Protocol for type checking repository managers."""

    @property
    def manager_name(self) -> str: ...

    @property
    def supported_formats(self) -> List[str]: ...

    def sync(self, config: RepoConfig) -> SyncResult: ...

    def create_snapshot(self, mirror_name: str, snapshot_name: Optional[str] = None) -> str: ...

    def diff_snapshots(self, old_snapshot: str, new_snapshot: str) -> DiffResult: ...

    def filter_packages(
        self,
        source_snapshot: str,
        dest_snapshot: str,
        approved_packages: List[str],
    ) -> bool: ...

    def publish(
        self,
        snapshot_name: str,
        distribution: str,
        prefix: str = "",
    ) -> bool: ...
