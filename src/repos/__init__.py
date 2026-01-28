"""Repository manager abstraction for multi-format package mirroring.

This module provides abstraction for different repository management tools
(Aptly, createrepo, bandersnatch, verdaccio, apk-tools) allowing the
pipeline to work with any supported format transparently.
"""

from .base import (
    RepositoryManager,
    SyncResult,
    DiffResult,
    PackageRef,
    RepoConfig,
)
from .registry import (
    RepoRegistry,
    get_registry,
    register_manager,
    get_repo_manager,
)

__all__ = [
    "RepositoryManager",
    "SyncResult",
    "DiffResult",
    "PackageRef",
    "RepoConfig",
    "RepoRegistry",
    "get_registry",
    "register_manager",
    "get_repo_manager",
]
