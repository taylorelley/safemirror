"""Registry for repository managers.

Manages registration and lookup of repository managers for different
package formats.
"""

from typing import Dict, List, Optional

from ..common.logger import get_logger
from .base import RepositoryManager, RepoConfig

logger = get_logger("repo_registry")


class RepoRegistry:
    """Registry for repository managers.

    Maps format types to their repository managers.
    """

    _instance: Optional["RepoRegistry"] = None
    _managers: Dict[str, RepositoryManager]
    _format_to_manager: Dict[str, str]

    def __new__(cls) -> "RepoRegistry":
        """Singleton pattern for global registry."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._managers = {}
            cls._instance._format_to_manager = {}
        return cls._instance

    def register(self, manager: RepositoryManager) -> None:
        """Register a repository manager.

        Args:
            manager: RepositoryManager instance to register
        """
        name = manager.manager_name
        if name in self._managers:
            logger.warning(f"Overwriting existing manager: {name}")

        self._managers[name] = manager

        # Map supported formats to this manager
        for fmt in manager.supported_formats:
            if fmt in self._format_to_manager:
                logger.warning(
                    f"Format {fmt} already handled by {self._format_to_manager[fmt]}, "
                    f"overwriting with {name}"
                )
            self._format_to_manager[fmt] = name

        logger.debug(f"Registered repository manager: {name}")

    def unregister(self, manager_name: str) -> None:
        """Unregister a repository manager.

        Args:
            manager_name: Name of manager to unregister
        """
        if manager_name in self._managers:
            manager = self._managers[manager_name]
            # Remove format mappings
            for fmt in manager.supported_formats:
                if self._format_to_manager.get(fmt) == manager_name:
                    del self._format_to_manager[fmt]
            del self._managers[manager_name]
            logger.debug(f"Unregistered repository manager: {manager_name}")

    def get_manager(self, manager_name: str) -> Optional[RepositoryManager]:
        """Get manager by name.

        Args:
            manager_name: Name of the manager

        Returns:
            RepositoryManager or None if not found
        """
        return self._managers.get(manager_name)

    def get_manager_for_format(self, format_type: str) -> Optional[RepositoryManager]:
        """Get manager for a specific package format.

        Args:
            format_type: Package format (e.g., 'deb', 'rpm')

        Returns:
            RepositoryManager or None if no manager handles this format
        """
        manager_name = self._format_to_manager.get(format_type)
        if manager_name:
            return self._managers.get(manager_name)
        return None

    def list_managers(self) -> List[str]:
        """List all registered manager names.

        Returns:
            List of manager names
        """
        return list(self._managers.keys())

    def list_supported_formats(self) -> List[str]:
        """List all supported package formats.

        Returns:
            List of format names
        """
        return list(self._format_to_manager.keys())

    def get_format_manager_mapping(self) -> Dict[str, str]:
        """Get mapping of formats to manager names.

        Returns:
            Dictionary mapping format -> manager_name
        """
        return dict(self._format_to_manager)

    def clear(self) -> None:
        """Clear all registered managers (mainly for testing)."""
        self._managers.clear()
        self._format_to_manager.clear()


# Global registry instance
_registry = RepoRegistry()


def get_registry() -> RepoRegistry:
    """Get the global repository registry.

    Returns:
        Global RepoRegistry instance
    """
    return _registry


def register_manager(manager: RepositoryManager) -> None:
    """Register a repository manager with the global registry.

    Args:
        manager: RepositoryManager instance to register
    """
    _registry.register(manager)


def get_repo_manager(name_or_format: str) -> Optional[RepositoryManager]:
    """Get a repository manager by name or format.

    First tries to find by manager name, then by format type.

    Args:
        name_or_format: Manager name or format type

    Returns:
        RepositoryManager or None if not found
    """
    # Try by name first
    manager = _registry.get_manager(name_or_format)
    if manager:
        return manager

    # Try by format
    return _registry.get_manager_for_format(name_or_format)


def auto_register_managers() -> None:
    """Auto-register all available repository managers.

    This function imports and registers all built-in managers.
    """
    # Aptly for Debian packages
    try:
        from .aptly import AptlyManager

        register_manager(AptlyManager())
        logger.info("Registered Aptly repository manager")
    except ImportError as e:
        logger.warning(f"Could not load Aptly manager: {e}")

    # createrepo for RPM packages
    try:
        from .createrepo import CreaterepoManager

        register_manager(CreaterepoManager())
        logger.info("Registered Createrepo repository manager")
    except ImportError:
        pass  # Not yet implemented

    # bandersnatch for PyPI
    try:
        from .bandersnatch import BandersnatchManager

        register_manager(BandersnatchManager())
        logger.info("Registered Bandersnatch repository manager")
    except ImportError:
        pass  # Not yet implemented

    # verdaccio for NPM
    try:
        from .verdaccio import VerdaccioManager

        register_manager(VerdaccioManager())
        logger.info("Registered Verdaccio repository manager")
    except ImportError:
        pass  # Not yet implemented

    # apk-tools for Alpine
    try:
        from .apk_mirror import ApkMirrorManager

        register_manager(ApkMirrorManager())
        logger.info("Registered APK Mirror repository manager")
    except ImportError:
        pass  # Not yet implemented
