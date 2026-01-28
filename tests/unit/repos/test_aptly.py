"""Tests for Aptly repository manager."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
import subprocess

from src.repos.aptly import AptlyManager
from src.repos.base import RepoConfig, SyncStatus, DiffType


class TestAptlyManager:
    """Tests for AptlyManager class."""

    @pytest.fixture
    def mock_aptly(self):
        """Mock aptly subprocess calls."""
        with patch("subprocess.run") as mock_run:
            # Default success for version check
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            yield mock_run

    def test_manager_name(self, mock_aptly):
        """Test manager name property."""
        manager = AptlyManager()
        assert manager.manager_name == "aptly"

    def test_supported_formats(self, mock_aptly):
        """Test supported formats."""
        manager = AptlyManager()
        assert "deb" in manager.supported_formats

    def test_generate_snapshot_name(self, mock_aptly):
        """Test snapshot name generation."""
        manager = AptlyManager()
        name = manager.generate_snapshot_name("staging")

        assert name.startswith("staging-")
        assert len(name) > len("staging-")

    def test_parse_package_ref_full(self, mock_aptly):
        """Test parsing full package reference."""
        manager = AptlyManager()
        ref = manager._parse_package_ref("curl_7.81.0-1ubuntu1.16_amd64")

        assert ref.name == "curl"
        assert ref.version == "7.81.0-1ubuntu1.16"
        assert ref.architecture == "amd64"
        assert ref.format_type == "deb"

    def test_parse_package_ref_no_arch(self, mock_aptly):
        """Test parsing package reference without architecture."""
        manager = AptlyManager()
        ref = manager._parse_package_ref("python3-pip_22.0.2")

        assert ref.name == "python3-pip"
        assert ref.version == "22.0.2"

    def test_parse_sync_count(self, mock_aptly):
        """Test parsing sync count from output."""
        manager = AptlyManager()

        # Test "Downloaded X packages" format
        output1 = "Downloading packages...\nDownloaded 1234 packages in 5m30s"
        assert manager._parse_sync_count(output1) == 1234

        # Test "contains X packages" format
        output2 = "Mirror ubuntu-jammy contains 45678 packages"
        assert manager._parse_sync_count(output2) == 45678

        # Test no match
        output3 = "Sync completed successfully"
        assert manager._parse_sync_count(output3) == 0

    def test_parse_diff_output(self, mock_aptly):
        """Test parsing aptly snapshot diff output."""
        manager = AptlyManager()

        output = """
+ curl_7.82.0-1_amd64
- curl_7.81.0-1_amd64
+ wget_1.21.0-1_amd64
"""
        entries = manager._parse_diff_output(output)

        assert len(entries) == 3

        # First entry: added
        assert entries[0].diff_type == DiffType.ADDED
        assert entries[0].package.name == "curl"
        assert entries[0].package.version == "7.82.0-1"

        # Second entry: removed
        assert entries[1].diff_type == DiffType.REMOVED
        assert entries[1].package.name == "curl"
        assert entries[1].package.version == "7.81.0-1"

        # Third entry: added
        assert entries[2].diff_type == DiffType.ADDED
        assert entries[2].package.name == "wget"


class TestAptlyManagerIntegration:
    """Integration tests for AptlyManager (mocked subprocess)."""

    @pytest.fixture
    def manager(self):
        """Create manager with mocked validation."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            return AptlyManager()

    @pytest.fixture
    def mock_run(self):
        """Mock subprocess.run."""
        with patch("subprocess.run") as mock:
            yield mock

    def test_mirror_exists_true(self, manager, mock_run):
        """Test mirror existence check - exists."""
        mock_run.return_value = MagicMock(returncode=0)

        assert manager._mirror_exists("test-mirror")
        mock_run.assert_called_once()

    def test_mirror_exists_false(self, manager, mock_run):
        """Test mirror existence check - does not exist."""
        mock_run.return_value = MagicMock(returncode=1)

        assert not manager._mirror_exists("test-mirror")

    def test_create_snapshot_default_name(self, manager, mock_run):
        """Test snapshot creation with default name."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

        name = manager.create_snapshot("test-mirror")

        assert name.startswith("staging-")
        mock_run.assert_called()

    def test_create_snapshot_custom_name(self, manager, mock_run):
        """Test snapshot creation with custom name."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

        name = manager.create_snapshot("test-mirror", "my-snapshot")

        assert name == "my-snapshot"

    def test_diff_snapshots_success(self, manager, mock_run):
        """Test successful snapshot diff."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"+ pkg1_1.0_amd64\n- pkg2_2.0_amd64\n",
            stderr=b"",
        )

        result = manager.diff_snapshots("old", "new")

        assert result.old_snapshot == "old"
        assert result.new_snapshot == "new"
        assert len(result.entries) == 2
        assert result.has_changes

    def test_diff_snapshots_no_changes(self, manager, mock_run):
        """Test diff with no changes."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"",
            stderr=b"",
        )

        result = manager.diff_snapshots("old", "new")

        assert not result.has_changes
        assert len(result.entries) == 0

    def test_filter_packages_small_list(self, manager, mock_run):
        """Test filtering with small package list."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

        approved = ["pkg1_1.0_amd64", "pkg2_2.0_amd64"]
        result = manager.filter_packages("source", "dest", approved)

        assert result
        # Should call aptly snapshot filter
        call_args = mock_run.call_args[0][0]
        assert "snapshot" in call_args
        assert "filter" in call_args

    def test_filter_packages_empty(self, manager, mock_run):
        """Test filtering with empty package list."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

        result = manager.filter_packages("source", "dest", [])

        assert result

    def test_list_snapshots(self, manager, mock_run):
        """Test listing snapshots."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"staging-20250101\napproved-20250101\n",
            stderr=b"",
        )

        snapshots = manager.list_snapshots()

        assert len(snapshots) == 2
        assert "staging-20250101" in snapshots

    def test_list_mirrors(self, manager, mock_run):
        """Test listing mirrors."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"ubuntu-jammy\nubuntu-noble\n",
            stderr=b"",
        )

        mirrors = manager.list_mirrors()

        assert len(mirrors) == 2
        assert "ubuntu-jammy" in mirrors

    def test_sync_success(self, manager, mock_run):
        """Test successful sync."""
        # Mock mirror exists check
        def run_side_effect(*args, **kwargs):
            cmd = args[0]
            if "mirror" in cmd and "show" in cmd:
                return MagicMock(returncode=0)
            elif "mirror" in cmd and "update" in cmd:
                return MagicMock(returncode=0, stdout=b"Downloaded 100 packages", stderr=b"")
            elif "snapshot" in cmd and "create" in cmd:
                return MagicMock(returncode=0, stdout=b"", stderr=b"")
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = run_side_effect

        config = RepoConfig(
            name="test-mirror",
            upstream_url="http://example.com",
            format_type="deb",
        )

        result = manager.sync(config)

        assert result.status == SyncStatus.SUCCESS
        assert result.mirror_name == "test-mirror"
        assert result.packages_synced == 100
