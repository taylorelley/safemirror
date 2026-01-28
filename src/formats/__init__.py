"""Package format handlers for multi-format security scanning.

This module provides abstraction for different package formats (DEB, RPM, PyPI, NPM, APK)
allowing the scanner to work with any supported format transparently.
"""

from .base import (
    PackageFormat,
    PackageMetadata,
    ExtractedContent,
    FormatCapabilities,
    ScriptInfo,
    ScriptType,
    FileInfo,
)
from .registry import (
    FormatRegistry,
    detect_format,
    get_format_handler,
    auto_register_formats,
    get_registry,
)

__all__ = [
    "PackageFormat",
    "PackageMetadata",
    "ExtractedContent",
    "FormatCapabilities",
    "ScriptInfo",
    "ScriptType",
    "FileInfo",
    "FormatRegistry",
    "detect_format",
    "get_format_handler",
    "auto_register_formats",
    "get_registry",
]
