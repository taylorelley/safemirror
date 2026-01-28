"""Configuration management for safemirror.

Handles loading and validation of YAML configuration files.
Supports multi-format package mirror configuration.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# Default format-specific scanner configurations
DEFAULT_SCANNER_CONFIG = {
    "deb": {
        "vulnerability_scanner": "trivy",
        "fallback_scanner": "grype",
    },
    "rpm": {
        "vulnerability_scanner": "trivy",
        "fallback_scanner": "grype",
    },
    "apk": {
        "vulnerability_scanner": "trivy",
        "fallback_scanner": "grype",
    },
    "wheel": {
        "vulnerability_scanner": "pip-audit",
        "fallback_scanner": "trivy",
    },
    "sdist": {
        "vulnerability_scanner": "pip-audit",
        "fallback_scanner": "trivy",
    },
    "npm": {
        "vulnerability_scanner": "npm-audit",
        "fallback_scanner": "trivy",
    },
}


@dataclass
class MirrorConfig:
    """Configuration for a single mirror."""

    name: str
    upstream_url: str
    distributions: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    architectures: List[str] = field(default_factory=list)
    gpg_key_url: Optional[str] = None
    extra_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FormatConfig:
    """Configuration for a package format."""

    enabled: bool = True
    repo_manager: str = ""
    vulnerability_scanner: str = ""
    fallback_scanner: str = ""
    mirrors: List[MirrorConfig] = field(default_factory=list)


@dataclass
class ScannerConfig:
    """Configuration for the security scanner."""

    virus_scan_enabled: bool = True
    integrity_check_enabled: bool = True
    script_analysis_enabled: bool = True
    binary_check_enabled: bool = True
    severity_threshold: str = "high"
    max_parallel_scans: int = 4
    scan_timeout: int = 300


@dataclass
class SafeMirrorConfig:
    """Top-level configuration for safemirror."""

    formats: Dict[str, FormatConfig] = field(default_factory=dict)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    data_dir: str = "/opt/safemirror/data"
    log_dir: str = "/var/log/safemirror"
    scan_results_dir: str = "/opt/safemirror/scans"
    approvals_dir: str = "/opt/safemirror/approvals"


def parse_mirror_config(mirror_dict: Dict[str, Any]) -> MirrorConfig:
    """Parse a mirror configuration dictionary.

    Args:
        mirror_dict: Mirror configuration dictionary

    Returns:
        MirrorConfig instance
    """
    return MirrorConfig(
        name=mirror_dict.get("name", ""),
        upstream_url=mirror_dict.get("upstream_url", ""),
        distributions=mirror_dict.get("distributions", []),
        components=mirror_dict.get("components", []),
        architectures=mirror_dict.get("architectures", []),
        gpg_key_url=mirror_dict.get("gpg_key_url"),
        extra_options=mirror_dict.get("extra_options", {}),
    )


def parse_format_config(
    format_name: str, format_dict: Dict[str, Any]
) -> FormatConfig:
    """Parse a format configuration dictionary.

    Args:
        format_name: Name of the format
        format_dict: Format configuration dictionary

    Returns:
        FormatConfig instance
    """
    # Get default scanner config for this format
    default_scanner = DEFAULT_SCANNER_CONFIG.get(format_name, {})

    mirrors = []
    for mirror_dict in format_dict.get("mirrors", []):
        mirrors.append(parse_mirror_config(mirror_dict))

    return FormatConfig(
        enabled=format_dict.get("enabled", True),
        repo_manager=format_dict.get("repo_manager", ""),
        vulnerability_scanner=format_dict.get(
            "vulnerability_scanner",
            default_scanner.get("vulnerability_scanner", "trivy"),
        ),
        fallback_scanner=format_dict.get(
            "fallback_scanner",
            default_scanner.get("fallback_scanner", "grype"),
        ),
        mirrors=mirrors,
    )


def parse_scanner_config(scanner_dict: Dict[str, Any]) -> ScannerConfig:
    """Parse scanner configuration dictionary.

    Args:
        scanner_dict: Scanner configuration dictionary

    Returns:
        ScannerConfig instance
    """
    return ScannerConfig(
        virus_scan_enabled=scanner_dict.get("virus_scan_enabled", True),
        integrity_check_enabled=scanner_dict.get("integrity_check_enabled", True),
        script_analysis_enabled=scanner_dict.get("script_analysis_enabled", True),
        binary_check_enabled=scanner_dict.get("binary_check_enabled", True),
        severity_threshold=scanner_dict.get("severity_threshold", "high"),
        max_parallel_scans=scanner_dict.get("max_parallel_scans", 4),
        scan_timeout=scanner_dict.get("scan_timeout", 300),
    )


def parse_config(config_dict: Dict[str, Any]) -> SafeMirrorConfig:
    """Parse the full configuration dictionary.

    Args:
        config_dict: Full configuration dictionary

    Returns:
        SafeMirrorConfig instance
    """
    formats = {}
    for format_name, format_dict in config_dict.get("formats", {}).items():
        formats[format_name] = parse_format_config(format_name, format_dict)

    scanner = ScannerConfig()
    if "scanner" in config_dict:
        scanner = parse_scanner_config(config_dict["scanner"])

    return SafeMirrorConfig(
        formats=formats,
        scanner=scanner,
        data_dir=config_dict.get("data_dir", "/opt/safemirror/data"),
        log_dir=config_dict.get("log_dir", "/var/log/safemirror"),
        scan_results_dir=config_dict.get("scan_results_dir", "/opt/safemirror/scans"),
        approvals_dir=config_dict.get("approvals_dir", "/opt/safemirror/approvals"),
    )


def get_enabled_formats(config: SafeMirrorConfig) -> List[str]:
    """Get list of enabled format names.

    Args:
        config: SafeMirrorConfig instance

    Returns:
        List of enabled format names
    """
    return [name for name, fmt in config.formats.items() if fmt.enabled]


def get_scanner_for_format(config: SafeMirrorConfig, format_name: str) -> str:
    """Get the preferred vulnerability scanner for a format.

    Args:
        config: SafeMirrorConfig instance
        format_name: Name of the format

    Returns:
        Scanner name
    """
    if format_name in config.formats:
        return config.formats[format_name].vulnerability_scanner

    # Fall back to default
    return DEFAULT_SCANNER_CONFIG.get(format_name, {}).get(
        "vulnerability_scanner", "trivy"
    )


def load_config(config_path: str = "/opt/apt-mirror-system/config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_file.open("r") as f:
        config = yaml.safe_load(f)

    # Validate config structure
    if config is None:
        config = {}

    if not isinstance(config, dict):
        raise TypeError(
            f"Configuration root must be a mapping, got {type(config).__name__}"
        )

    # Expand environment variables
    config = _expand_env_vars(config)

    return config


def _expand_env_vars(obj: Any) -> Any:
    """Recursively expand environment variables in configuration.

    Args:
        obj: Configuration object (dict, list, str, etc.)

    Returns:
        Configuration with expanded environment variables
    """
    if isinstance(obj, dict):
        return {key: _expand_env_vars(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        return os.path.expandvars(obj)
    else:
        return obj


def load_typed_config(
    config_path: str = "/opt/safemirror/config.yaml",
) -> SafeMirrorConfig:
    """Load and parse configuration into typed dataclass.

    Args:
        config_path: Path to configuration file

    Returns:
        SafeMirrorConfig instance

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    config_dict = load_config(config_path)
    return parse_config(config_dict)
