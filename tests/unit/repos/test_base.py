"""Tests for repository manager base classes."""

import pytest

from src.repos.base import (
    PackageRef,
    DiffEntry,
    DiffType,
    SyncResult,
    SyncStatus,
    DiffResult,
    RepoConfig,
)


class TestPackageRef:
    """Tests for PackageRef class."""

    def test_deb_package_key(self):
        """Test key generation for Debian package."""
        ref = PackageRef(
            name="curl",
            version="7.81.0-1ubuntu1.16",
            architecture="amd64",
            format_type="deb",
        )
        assert ref.get_key() == "curl_7.81.0-1ubuntu1.16_amd64"

    def test_deb_package_key_default_arch(self):
        """Test key with default architecture."""
        ref = PackageRef(
            name="python3-pip",
            version="22.0.2",
            format_type="deb",
        )
        assert ref.get_key() == "python3-pip_22.0.2_all"

    def test_rpm_package_key(self):
        """Test key generation for RPM package."""
        ref = PackageRef(
            name="curl",
            version="7.76.1-14.el8",
            architecture="x86_64",
            format_type="rpm",
        )
        assert ref.get_key() == "curl-7.76.1-14.el8.x86_64"

    def test_wheel_package_key(self):
        """Test key generation for Python wheel."""
        ref = PackageRef(
            name="requests",
            version="2.28.1",
            format_type="wheel",
        )
        assert ref.get_key() == "requests-2.28.1"

    def test_npm_package_key(self):
        """Test key generation for NPM package."""
        ref = PackageRef(
            name="lodash",
            version="4.17.21",
            format_type="npm",
        )
        assert ref.get_key() == "lodash@4.17.21"


class TestSyncResult:
    """Tests for SyncResult class."""

    def test_is_success_true(self):
        """Test is_success for successful sync."""
        result = SyncResult(
            status=SyncStatus.SUCCESS,
            mirror_name="test",
            packages_synced=100,
            packages_failed=0,
            sync_date="2025-01-01T00:00:00",
        )
        assert result.is_success

    def test_is_success_no_changes(self):
        """Test is_success when no changes."""
        result = SyncResult(
            status=SyncStatus.NO_CHANGES,
            mirror_name="test",
            packages_synced=0,
            packages_failed=0,
            sync_date="2025-01-01T00:00:00",
        )
        assert result.is_success

    def test_is_success_false_on_failure(self):
        """Test is_success returns false on failure."""
        result = SyncResult(
            status=SyncStatus.FAILED,
            mirror_name="test",
            packages_synced=0,
            packages_failed=0,
            sync_date="2025-01-01T00:00:00",
            error_message="Connection failed",
        )
        assert not result.is_success


class TestDiffResult:
    """Tests for DiffResult class."""

    def test_added_packages(self):
        """Test filtering added packages."""
        result = DiffResult(
            old_snapshot="old",
            new_snapshot="new",
            entries=[
                DiffEntry(
                    package=PackageRef(name="pkg1", version="1.0", format_type="deb"),
                    diff_type=DiffType.ADDED,
                ),
                DiffEntry(
                    package=PackageRef(name="pkg2", version="1.0", format_type="deb"),
                    diff_type=DiffType.REMOVED,
                ),
                DiffEntry(
                    package=PackageRef(name="pkg3", version="2.0", format_type="deb"),
                    diff_type=DiffType.ADDED,
                ),
            ],
            diff_date="2025-01-01T00:00:00",
        )

        added = result.added_packages
        assert len(added) == 2
        assert added[0].name == "pkg1"
        assert added[1].name == "pkg3"

    def test_removed_packages(self):
        """Test filtering removed packages."""
        result = DiffResult(
            old_snapshot="old",
            new_snapshot="new",
            entries=[
                DiffEntry(
                    package=PackageRef(name="pkg1", version="1.0", format_type="deb"),
                    diff_type=DiffType.ADDED,
                ),
                DiffEntry(
                    package=PackageRef(name="pkg2", version="1.0", format_type="deb"),
                    diff_type=DiffType.REMOVED,
                ),
            ],
            diff_date="2025-01-01T00:00:00",
        )

        removed = result.removed_packages
        assert len(removed) == 1
        assert removed[0].name == "pkg2"

    def test_has_changes(self):
        """Test has_changes property."""
        with_changes = DiffResult(
            old_snapshot="old",
            new_snapshot="new",
            entries=[
                DiffEntry(
                    package=PackageRef(name="pkg1", version="1.0", format_type="deb"),
                    diff_type=DiffType.ADDED,
                ),
            ],
            diff_date="2025-01-01T00:00:00",
        )
        assert with_changes.has_changes

        no_changes = DiffResult(
            old_snapshot="old",
            new_snapshot="new",
            entries=[],
            diff_date="2025-01-01T00:00:00",
        )
        assert not no_changes.has_changes

    def test_get_changed_package_keys(self):
        """Test getting all changed package keys."""
        result = DiffResult(
            old_snapshot="old",
            new_snapshot="new",
            entries=[
                DiffEntry(
                    package=PackageRef(name="pkg1", version="1.0", architecture="amd64", format_type="deb"),
                    diff_type=DiffType.ADDED,
                ),
                DiffEntry(
                    package=PackageRef(name="pkg2", version="2.0", architecture="amd64", format_type="deb"),
                    diff_type=DiffType.REMOVED,
                ),
            ],
            diff_date="2025-01-01T00:00:00",
        )

        keys = result.get_changed_package_keys()
        assert len(keys) == 2
        assert "pkg1_1.0_amd64" in keys
        assert "pkg2_2.0_amd64" in keys


class TestRepoConfig:
    """Tests for RepoConfig class."""

    def test_basic_config(self):
        """Test basic configuration creation."""
        config = RepoConfig(
            name="ubuntu-jammy",
            upstream_url="http://archive.ubuntu.com/ubuntu",
            format_type="deb",
            distributions=["jammy", "jammy-updates"],
            components=["main", "universe"],
            architectures=["amd64"],
        )

        assert config.name == "ubuntu-jammy"
        assert config.format_type == "deb"
        assert "jammy" in config.distributions
        assert "main" in config.components

    def test_config_defaults(self):
        """Test default values in config."""
        config = RepoConfig(
            name="test",
            upstream_url="http://example.com",
            format_type="deb",
        )

        assert config.distributions == []
        assert config.components == []
        assert config.architectures == []
        assert config.gpg_key_url is None
        assert config.extra_options == {}
