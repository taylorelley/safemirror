"""Aptly repository manager for Debian packages.

Wraps the aptly command-line tool for mirror management, snapshots,
filtering, and publishing.
"""

import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..common.logger import get_logger
from .base import (
    RepositoryManager,
    RepoConfig,
    SyncResult,
    SyncStatus,
    DiffResult,
    DiffEntry,
    DiffType,
    PackageRef,
)

logger = get_logger("aptly_manager")


class AptlyManager(RepositoryManager):
    """Repository manager using Aptly for Debian packages.

    Aptly is a Debian repository management tool that handles:
    - Mirroring from upstream repositories
    - Snapshot creation and management
    - Package filtering
    - Repository publishing with GPG signing
    """

    def __init__(
        self,
        aptly_root: str = "/var/lib/aptly",
        timeout: int = 600,
        max_retries: int = 4,
        retry_delay: int = 2,
    ):
        """Initialize Aptly manager.

        Args:
            aptly_root: Root directory for aptly data
            timeout: Command timeout in seconds
            max_retries: Maximum retry attempts for operations
            retry_delay: Initial delay between retries (doubles each retry)
        """
        self.aptly_root = Path(aptly_root)
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Validate aptly is available
        self._validate_aptly()

    @property
    def manager_name(self) -> str:
        """Return manager identifier."""
        return "aptly"

    @property
    def supported_formats(self) -> List[str]:
        """Return supported package formats."""
        return ["deb"]

    def _validate_aptly(self) -> None:
        """Validate that aptly is installed and available."""
        try:
            subprocess.run(
                ["aptly", "version"],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise RuntimeError("aptly not available - install with: apt-get install aptly") from e

    def _run_aptly(
        self,
        args: List[str],
        timeout: Optional[int] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run an aptly command with retry logic.

        Args:
            args: Command arguments (without 'aptly' prefix)
            timeout: Optional timeout override
            check: Whether to raise on non-zero exit

        Returns:
            CompletedProcess result

        Raises:
            RuntimeError: If command fails after all retries
        """
        cmd = ["aptly"] + args
        timeout = timeout or self.timeout

        delay = self.retry_delay
        last_error = None

        for attempt in range(self.max_retries):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout,
                    check=check,
                )
                return result
            except subprocess.CalledProcessError as e:
                last_error = e
                stderr = e.stderr.decode() if e.stderr else str(e)
                logger.warning(
                    f"Aptly command failed (attempt {attempt + 1}/{self.max_retries}): {stderr}"
                )
            except subprocess.TimeoutExpired as e:
                last_error = e
                logger.warning(
                    f"Aptly command timed out (attempt {attempt + 1}/{self.max_retries})"
                )

            # Exponential backoff
            if attempt < self.max_retries - 1:
                import time
                time.sleep(delay)
                delay *= 2

        stderr = last_error.stderr.decode() if hasattr(last_error, 'stderr') and last_error.stderr else str(last_error)
        raise RuntimeError(f"Aptly command failed after {self.max_retries} attempts: {stderr}")

    def sync(self, config: RepoConfig) -> SyncResult:
        """Sync repository from upstream.

        Args:
            config: Repository configuration

        Returns:
            SyncResult with sync status
        """
        start_time = datetime.now()
        mirror_name = config.name

        logger.info(f"Starting mirror sync for {mirror_name}")

        try:
            # Check if mirror exists, create if not
            if not self._mirror_exists(mirror_name):
                self._create_mirror(config)

            # Update mirror
            result = self._run_aptly(["mirror", "update", mirror_name])

            # Parse output to count packages
            output = result.stdout.decode()
            packages_synced = self._parse_sync_count(output)

            # Create snapshot
            snapshot_name = self.create_snapshot(mirror_name)

            duration = (datetime.now() - start_time).total_seconds()

            logger.info(f"Mirror sync completed: {packages_synced} packages synced")

            return SyncResult(
                status=SyncStatus.SUCCESS,
                mirror_name=mirror_name,
                packages_synced=packages_synced,
                packages_failed=0,
                sync_date=datetime.now().isoformat(),
                snapshot_name=snapshot_name,
                duration_seconds=duration,
            )

        except RuntimeError as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"Mirror sync failed: {e}")

            return SyncResult(
                status=SyncStatus.FAILED,
                mirror_name=mirror_name,
                packages_synced=0,
                packages_failed=0,
                sync_date=datetime.now().isoformat(),
                error_message=str(e),
                duration_seconds=duration,
            )

    def _mirror_exists(self, mirror_name: str) -> bool:
        """Check if a mirror exists.

        Args:
            mirror_name: Name of the mirror

        Returns:
            True if mirror exists
        """
        try:
            result = subprocess.run(
                ["aptly", "mirror", "show", mirror_name],
                capture_output=True,
                timeout=30,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _create_mirror(self, config: RepoConfig) -> None:
        """Create a new mirror from config.

        Args:
            config: Repository configuration

        Raises:
            RuntimeError: If mirror creation fails
        """
        # Build aptly mirror create command
        args = ["mirror", "create"]

        # Add architectures if specified
        if config.architectures:
            args.extend(["-architectures", ",".join(config.architectures)])

        # Add filter-with-deps if specified
        if config.extra_options.get("filter_with_deps"):
            args.append("-filter-with-deps")

        args.append(config.name)
        args.append(config.upstream_url)

        # Add distribution
        if config.distributions:
            args.append(config.distributions[0])

        # Add components
        if config.components:
            args.extend(config.components)

        self._run_aptly(args)
        logger.info(f"Created mirror {config.name}")

    def _parse_sync_count(self, output: str) -> int:
        """Parse package count from aptly mirror update output.

        Args:
            output: aptly command output

        Returns:
            Number of packages synced
        """
        # Look for patterns like "Downloaded 1234 packages"
        match = re.search(r"Downloaded\s+(\d+)\s+packages?", output)
        if match:
            return int(match.group(1))

        # Look for "Mirror contains 1234 packages"
        match = re.search(r"contains\s+(\d+)\s+packages?", output)
        if match:
            return int(match.group(1))

        return 0

    def create_snapshot(self, mirror_name: str, snapshot_name: Optional[str] = None) -> str:
        """Create a snapshot from current mirror state.

        Args:
            mirror_name: Name of the mirror
            snapshot_name: Optional snapshot name

        Returns:
            Name of created snapshot
        """
        if snapshot_name is None:
            snapshot_name = self.generate_snapshot_name("staging")

        self._run_aptly([
            "snapshot", "create", snapshot_name, "from", "mirror", mirror_name
        ])

        logger.info(f"Created snapshot {snapshot_name}")
        return snapshot_name

    def diff_snapshots(self, old_snapshot: str, new_snapshot: str) -> DiffResult:
        """Compare two snapshots.

        Args:
            old_snapshot: Older snapshot name
            new_snapshot: Newer snapshot name

        Returns:
            DiffResult with differences
        """
        logger.info(f"Diffing snapshots: {old_snapshot} -> {new_snapshot}")

        try:
            result = self._run_aptly(
                ["snapshot", "diff", old_snapshot, new_snapshot],
                check=False,  # Diff returns non-zero if snapshots identical
            )

            output = result.stdout.decode()
            entries = self._parse_diff_output(output)

            return DiffResult(
                old_snapshot=old_snapshot,
                new_snapshot=new_snapshot,
                entries=entries,
                diff_date=datetime.now().isoformat(),
            )

        except RuntimeError as e:
            return DiffResult(
                old_snapshot=old_snapshot,
                new_snapshot=new_snapshot,
                entries=[],
                diff_date=datetime.now().isoformat(),
                error_message=str(e),
            )

    def _parse_diff_output(self, output: str) -> List[DiffEntry]:
        """Parse aptly snapshot diff output.

        Args:
            output: aptly diff output

        Returns:
            List of DiffEntry objects
        """
        entries = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Format: "+ package_name_version_arch" or "- package_name_version_arch"
            if line.startswith("+ "):
                pkg_info = line[2:].strip()
                package = self._parse_package_ref(pkg_info)
                entries.append(DiffEntry(
                    package=package,
                    diff_type=DiffType.ADDED,
                ))
            elif line.startswith("- "):
                pkg_info = line[2:].strip()
                package = self._parse_package_ref(pkg_info)
                entries.append(DiffEntry(
                    package=package,
                    diff_type=DiffType.REMOVED,
                ))

        return entries

    def _parse_package_ref(self, pkg_str: str) -> PackageRef:
        """Parse package reference from string.

        Args:
            pkg_str: Package string (e.g., "curl_7.81.0-1ubuntu1.16_amd64")

        Returns:
            PackageRef object
        """
        # Format: name_version_arch
        parts = pkg_str.split("_")
        if len(parts) >= 3:
            return PackageRef(
                name=parts[0],
                version=parts[1],
                architecture=parts[2],
                format_type="deb",
            )
        elif len(parts) == 2:
            return PackageRef(
                name=parts[0],
                version=parts[1],
                format_type="deb",
            )
        else:
            return PackageRef(
                name=pkg_str,
                version="unknown",
                format_type="deb",
            )

    def filter_packages(
        self,
        source_snapshot: str,
        dest_snapshot: str,
        approved_packages: List[str],
    ) -> bool:
        """Filter snapshot to include only approved packages.

        Args:
            source_snapshot: Source snapshot name
            dest_snapshot: Destination snapshot name
            approved_packages: List of approved package keys

        Returns:
            True if filtering succeeded
        """
        logger.info(
            f"Filtering {source_snapshot} -> {dest_snapshot} "
            f"({len(approved_packages)} approved packages)"
        )

        if not approved_packages:
            logger.warning("No approved packages - creating empty snapshot")
            # Create empty snapshot using filter with impossible condition
            self._run_aptly([
                "snapshot", "filter",
                source_snapshot,
                dest_snapshot,
                "Name (= __impossible__)",
            ])
            return True

        # Build filter query
        # Format: Name (= pkg1) | Name (= pkg2) | ...
        # For large lists, use -filter-with-file instead
        if len(approved_packages) > 100:
            return self._filter_with_file(source_snapshot, dest_snapshot, approved_packages)

        filter_parts = []
        for pkg_key in approved_packages:
            # Extract package name from key (name_version_arch -> name)
            name = pkg_key.split("_")[0] if "_" in pkg_key else pkg_key
            filter_parts.append(f"Name (= {name})")

        filter_query = " | ".join(filter_parts)

        self._run_aptly([
            "snapshot", "filter",
            source_snapshot,
            dest_snapshot,
            filter_query,
        ])

        logger.info(f"Created filtered snapshot {dest_snapshot}")
        return True

    def _filter_with_file(
        self,
        source_snapshot: str,
        dest_snapshot: str,
        approved_packages: List[str],
    ) -> bool:
        """Filter using package list file for large lists.

        Args:
            source_snapshot: Source snapshot name
            dest_snapshot: Destination snapshot name
            approved_packages: List of approved package keys

        Returns:
            True if filtering succeeded
        """
        import tempfile

        # Write approved packages to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for pkg_key in approved_packages:
                # Write package key in aptly format
                f.write(f"{pkg_key}\n")
            filter_file = f.name

        try:
            self._run_aptly([
                "snapshot", "filter",
                "-include-file", filter_file,
                source_snapshot,
                dest_snapshot,
            ])
            return True
        finally:
            Path(filter_file).unlink(missing_ok=True)

    def publish(
        self,
        snapshot_name: str,
        distribution: str,
        prefix: str = "",
    ) -> bool:
        """Publish a snapshot.

        Args:
            snapshot_name: Snapshot to publish
            distribution: Distribution name
            prefix: Optional publish prefix

        Returns:
            True if publishing succeeded
        """
        logger.info(f"Publishing {snapshot_name} to {distribution}")

        # Check if already published - use switch instead
        if self._is_published(distribution, prefix):
            # Switch to new snapshot
            args = ["publish", "switch", distribution]
            if prefix:
                args.insert(2, prefix)
            args.append(snapshot_name)
        else:
            # Initial publish
            args = ["publish", "snapshot", snapshot_name]
            if prefix:
                args.extend(["prefix=" + prefix])
            args.append(distribution)

        self._run_aptly(args)
        logger.info(f"Published {snapshot_name} as {distribution}")
        return True

    def _is_published(self, distribution: str, prefix: str = "") -> bool:
        """Check if a distribution is already published.

        Args:
            distribution: Distribution name
            prefix: Publish prefix

        Returns:
            True if already published
        """
        try:
            result = subprocess.run(
                ["aptly", "publish", "list"],
                capture_output=True,
                timeout=30,
                check=False,
            )
            output = result.stdout.decode()

            # Look for distribution in output
            search_str = f"{prefix}/{distribution}" if prefix else distribution
            return search_str in output
        except Exception:
            return False

    def get_package_path(self, package_key: str, mirror_name: str) -> Optional[Path]:
        """Get filesystem path to a package.

        Args:
            package_key: Package identifier
            mirror_name: Mirror name

        Returns:
            Path to package file or None
        """
        # Aptly stores packages in pool directory
        # Format: /var/lib/aptly/pool/main/c/curl/curl_7.81.0-1ubuntu1.16_amd64.deb

        # Extract package name
        parts = package_key.split("_")
        if len(parts) < 2:
            return None

        name = parts[0]
        first_char = name[0]

        # Search in pool
        pool_base = self.aptly_root / "pool"
        if pool_base.exists():
            for component in ["main", "universe", "multiverse", "restricted"]:
                pool_path = pool_base / component / first_char / name
                if pool_path.exists():
                    # Look for matching .deb file
                    for deb_file in pool_path.glob(f"{package_key}.deb"):
                        return deb_file

        return None

    def list_snapshots(self, mirror_name: Optional[str] = None) -> List[str]:
        """List available snapshots.

        Args:
            mirror_name: Optional filter by mirror

        Returns:
            List of snapshot names
        """
        try:
            result = self._run_aptly(["snapshot", "list", "-raw"], check=False)
            output = result.stdout.decode()

            snapshots = [line.strip() for line in output.splitlines() if line.strip()]

            if mirror_name:
                # Filter to snapshots from this mirror
                # This is approximate - aptly doesn't track source mirror in snapshot name
                snapshots = [s for s in snapshots if mirror_name in s.lower()]

            return snapshots
        except Exception:
            return []

    def list_mirrors(self) -> List[str]:
        """List configured mirrors.

        Returns:
            List of mirror names
        """
        try:
            result = self._run_aptly(["mirror", "list", "-raw"], check=False)
            output = result.stdout.decode()
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception:
            return []
