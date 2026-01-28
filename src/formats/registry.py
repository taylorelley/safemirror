"""Format registry for package format detection and handler management.

Provides automatic format detection based on magic bytes and file extensions,
and manages registration of format handlers.
"""

from pathlib import Path
from typing import Dict, List, Optional, Type

from ..common.logger import get_logger
from .base import PackageFormat, PackageMetadata, ExtractedContent

logger = get_logger("format_registry")


# Magic byte signatures for different package formats
MAGIC_SIGNATURES: Dict[str, bytes] = {
    "deb": b"!<arch>",  # ar archive
    "rpm": b"\xed\xab\xee\xdb",  # RPM magic
    "gzip": b"\x1f\x8b",  # gzip compressed (used by many formats)
    "xz": b"\xfd7zXZ",  # xz compressed
    "zip": b"PK\x03\x04",  # ZIP archive (wheels, jars)
    "tar": b"ustar",  # tar archive (at offset 257)
}


class FormatRegistry:
    """Registry for package format handlers.

    Manages format handler registration and provides format detection
    based on magic bytes and file extensions.
    """

    _instance: Optional["FormatRegistry"] = None
    _handlers: Dict[str, PackageFormat]

    def __new__(cls) -> "FormatRegistry":
        """Singleton pattern for global registry."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._handlers = {}
        return cls._instance

    def register(self, handler: PackageFormat) -> None:
        """Register a format handler.

        Args:
            handler: PackageFormat instance to register
        """
        format_name = handler.format_name
        if format_name in self._handlers:
            logger.warning(f"Overwriting existing handler for format: {format_name}")
        self._handlers[format_name] = handler
        logger.debug(f"Registered format handler: {format_name}")

    def unregister(self, format_name: str) -> None:
        """Unregister a format handler.

        Args:
            format_name: Name of format to unregister
        """
        if format_name in self._handlers:
            del self._handlers[format_name]
            logger.debug(f"Unregistered format handler: {format_name}")

    def get_handler(self, format_name: str) -> Optional[PackageFormat]:
        """Get handler by format name.

        Args:
            format_name: Name of the format (e.g., 'deb', 'rpm')

        Returns:
            PackageFormat handler or None if not found
        """
        return self._handlers.get(format_name)

    def detect_format(self, path: Path) -> Optional[PackageFormat]:
        """Detect format and return appropriate handler.

        Uses magic bytes first, then falls back to file extension.

        Args:
            path: Path to the package file

        Returns:
            PackageFormat handler or None if format not recognized
        """
        if not path.exists():
            logger.error(f"File does not exist: {path}")
            return None

        # First, try each registered handler's detect method
        for handler in self._handlers.values():
            try:
                if handler.detect(path):
                    logger.debug(f"Detected format '{handler.format_name}' for {path.name}")
                    return handler
            except Exception as e:
                logger.debug(f"Handler {handler.format_name} detection failed: {e}")
                continue

        # Fall back to extension-based detection
        suffix = path.suffix.lower()
        for handler in self._handlers.values():
            if suffix in [ext.lower() for ext in handler.file_extensions]:
                logger.debug(
                    f"Detected format '{handler.format_name}' for {path.name} by extension"
                )
                return handler

        logger.warning(f"Could not detect format for: {path}")
        return None

    def list_formats(self) -> List[str]:
        """List all registered format names.

        Returns:
            List of registered format names
        """
        return list(self._handlers.keys())

    def list_extensions(self) -> Dict[str, List[str]]:
        """List all supported extensions by format.

        Returns:
            Dictionary mapping format names to their extensions
        """
        return {
            name: handler.file_extensions for name, handler in self._handlers.items()
        }

    def clear(self) -> None:
        """Clear all registered handlers (mainly for testing)."""
        self._handlers.clear()


# Global registry instance
_registry = FormatRegistry()


def get_registry() -> FormatRegistry:
    """Get the global format registry.

    Returns:
        Global FormatRegistry instance
    """
    return _registry


def register_handler(handler: PackageFormat) -> None:
    """Register a format handler with the global registry.

    Args:
        handler: PackageFormat instance to register
    """
    _registry.register(handler)


def detect_format(path: Path) -> Optional[PackageFormat]:
    """Detect package format and return handler.

    Convenience function that uses the global registry.

    Args:
        path: Path to the package file

    Returns:
        PackageFormat handler or None if not recognized
    """
    return _registry.detect_format(path)


def get_format_handler(format_name: str) -> Optional[PackageFormat]:
    """Get a format handler by name.

    Convenience function that uses the global registry.

    Args:
        format_name: Name of the format (e.g., 'deb', 'rpm')

    Returns:
        PackageFormat handler or None if not found
    """
    return _registry.get_handler(format_name)


def read_magic_bytes(path: Path, num_bytes: int = 8) -> bytes:
    """Read magic bytes from file.

    Args:
        path: Path to file
        num_bytes: Number of bytes to read

    Returns:
        First num_bytes bytes of the file
    """
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except (IOError, OSError):
        return b""


def check_tar_magic(path: Path) -> bool:
    """Check if file is a tar archive.

    Tar magic is at offset 257, not at start.

    Args:
        path: Path to file

    Returns:
        True if file appears to be a tar archive
    """
    try:
        with open(path, "rb") as f:
            f.seek(257)
            magic = f.read(5)
            return magic == b"ustar"
    except (IOError, OSError):
        return False


def is_gzip_compressed(path: Path) -> bool:
    """Check if file is gzip compressed.

    Args:
        path: Path to file

    Returns:
        True if file is gzip compressed
    """
    magic = read_magic_bytes(path, 2)
    return magic == MAGIC_SIGNATURES["gzip"]


def is_xz_compressed(path: Path) -> bool:
    """Check if file is xz compressed.

    Args:
        path: Path to file

    Returns:
        True if file is xz compressed
    """
    magic = read_magic_bytes(path, 6)
    return magic.startswith(MAGIC_SIGNATURES["xz"])


def is_zip_archive(path: Path) -> bool:
    """Check if file is a ZIP archive.

    Args:
        path: Path to file

    Returns:
        True if file is a ZIP archive
    """
    magic = read_magic_bytes(path, 4)
    return magic == MAGIC_SIGNATURES["zip"]


def auto_register_formats() -> None:
    """Auto-register all available format handlers.

    This function imports and registers all built-in format handlers.
    It should be called during module initialization.
    """
    # Import handlers here to avoid circular imports
    try:
        from .deb import DebPackageFormat

        register_handler(DebPackageFormat())
        logger.info("Registered DEB format handler")
    except ImportError as e:
        logger.warning(f"Could not load DEB format handler: {e}")

    # RPM handler (when implemented)
    try:
        from .rpm import RpmPackageFormat

        register_handler(RpmPackageFormat())
        logger.info("Registered RPM format handler")
    except ImportError:
        pass  # Not yet implemented

    # Wheel handler (when implemented)
    try:
        from .wheel import WheelPackageFormat

        register_handler(WheelPackageFormat())
        logger.info("Registered Wheel format handler")
    except ImportError:
        pass  # Not yet implemented

    # Sdist handler (when implemented)
    try:
        from .sdist import SdistPackageFormat

        register_handler(SdistPackageFormat())
        logger.info("Registered Sdist format handler")
    except ImportError:
        pass  # Not yet implemented

    # NPM handler (when implemented)
    try:
        from .npm import NpmPackageFormat

        register_handler(NpmPackageFormat())
        logger.info("Registered NPM format handler")
    except ImportError:
        pass  # Not yet implemented

    # APK handler (when implemented)
    try:
        from .apk import ApkPackageFormat

        register_handler(ApkPackageFormat())
        logger.info("Registered APK format handler")
    except ImportError:
        pass  # Not yet implemented
