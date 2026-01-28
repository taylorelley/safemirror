"""Tests for repository manager registry."""

import pytest
from unittest.mock import MagicMock

from src.repos.registry import (
    RepoRegistry,
    get_registry,
    register_manager,
    get_repo_manager,
)
from src.repos.base import (
    RepositoryManager,
    RepoConfig,
    SyncResult,
    SyncStatus,
    DiffResult,
)


class MockRepoManager(RepositoryManager):
    """Mock repository manager for testing."""

    def __init__(self, name: str = "mock", formats: list = None):
        self._name = name
        self._formats = formats or ["mock"]

    @property
    def manager_name(self) -> str:
        return self._name

    @property
    def supported_formats(self) -> list:
        return self._formats

    def sync(self, config):
        return SyncResult(
            status=SyncStatus.SUCCESS,
            mirror_name=config.name,
            packages_synced=0,
            packages_failed=0,
            sync_date="2025-01-01T00:00:00",
        )

    def create_snapshot(self, mirror_name, snapshot_name=None):
        return snapshot_name or f"{mirror_name}-snapshot"

    def diff_snapshots(self, old_snapshot, new_snapshot):
        return DiffResult(
            old_snapshot=old_snapshot,
            new_snapshot=new_snapshot,
            entries=[],
            diff_date="2025-01-01T00:00:00",
        )

    def filter_packages(self, source, dest, approved):
        return True

    def publish(self, snapshot, distribution, prefix=""):
        return True

    def get_package_path(self, package_key, mirror_name):
        return None

    def list_snapshots(self, mirror_name=None):
        return []

    def list_mirrors(self):
        return []


class TestRepoRegistry:
    """Tests for RepoRegistry class."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create a fresh registry for each test
        self.registry = RepoRegistry.__new__(RepoRegistry)
        self.registry._managers = {}
        self.registry._format_to_manager = {}

    def test_register_manager(self):
        """Test manager registration."""
        manager = MockRepoManager("test", ["deb"])
        self.registry.register(manager)

        assert "test" in self.registry.list_managers()
        assert "deb" in self.registry.list_supported_formats()

    def test_register_overwrites(self):
        """Test that registering same name overwrites."""
        manager1 = MockRepoManager("test", ["deb"])
        manager2 = MockRepoManager("test", ["rpm"])

        self.registry.register(manager1)
        self.registry.register(manager2)

        assert self.registry.get_manager("test") == manager2
        assert "rpm" in self.registry.list_supported_formats()

    def test_unregister_manager(self):
        """Test manager unregistration."""
        manager = MockRepoManager("test", ["deb"])
        self.registry.register(manager)
        self.registry.unregister("test")

        assert "test" not in self.registry.list_managers()
        assert "deb" not in self.registry.list_supported_formats()

    def test_get_manager(self):
        """Test getting manager by name."""
        manager = MockRepoManager("test")
        self.registry.register(manager)

        assert self.registry.get_manager("test") == manager
        assert self.registry.get_manager("nonexistent") is None

    def test_get_manager_for_format(self):
        """Test getting manager by format type."""
        manager = MockRepoManager("aptly", ["deb"])
        self.registry.register(manager)

        result = self.registry.get_manager_for_format("deb")
        assert result == manager
        assert self.registry.get_manager_for_format("rpm") is None

    def test_multiple_formats(self):
        """Test manager supporting multiple formats."""
        manager = MockRepoManager("multi", ["deb", "udeb"])
        self.registry.register(manager)

        assert self.registry.get_manager_for_format("deb") == manager
        assert self.registry.get_manager_for_format("udeb") == manager

    def test_format_manager_mapping(self):
        """Test getting format to manager mapping."""
        manager1 = MockRepoManager("aptly", ["deb"])
        manager2 = MockRepoManager("createrepo", ["rpm"])

        self.registry.register(manager1)
        self.registry.register(manager2)

        mapping = self.registry.get_format_manager_mapping()
        assert mapping["deb"] == "aptly"
        assert mapping["rpm"] == "createrepo"

    def test_clear(self):
        """Test clearing all managers."""
        manager = MockRepoManager("test", ["deb"])
        self.registry.register(manager)
        self.registry.clear()

        assert len(self.registry.list_managers()) == 0
        assert len(self.registry.list_supported_formats()) == 0


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def setup_method(self):
        """Clear global registry before each test."""
        get_registry().clear()

    def teardown_method(self):
        """Clear global registry after each test."""
        get_registry().clear()

    def test_register_manager_global(self):
        """Test global register_manager function."""
        manager = MockRepoManager("global_test", ["deb"])
        register_manager(manager)

        assert get_repo_manager("global_test") == manager

    def test_get_repo_manager_by_name(self):
        """Test getting manager by name."""
        manager = MockRepoManager("test_manager", ["deb"])
        register_manager(manager)

        assert get_repo_manager("test_manager") == manager

    def test_get_repo_manager_by_format(self):
        """Test getting manager by format type."""
        manager = MockRepoManager("aptly", ["deb"])
        register_manager(manager)

        # Should find by format when name doesn't match
        assert get_repo_manager("deb") == manager

    def test_get_repo_manager_not_found(self):
        """Test getting nonexistent manager."""
        assert get_repo_manager("nonexistent") is None
