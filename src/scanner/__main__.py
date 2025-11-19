"""CLI interface for package scanner."""

import sys
from pathlib import Path

from .scan_packages import PackageScanner
from ..common.logger import setup_logger
from ..common.config import load_config


def main():
    """Main entry point for scanner CLI."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.scanner <package.deb>", file=sys.stderr)
        sys.exit(1)

    package_path = sys.argv[1]

    # Load configuration
    try:
        config = load_config()
    except FileNotFoundError:
        # Use defaults if config not found
        config = {
            "scanner": {"type": "trivy", "timeout": 300},
            "policy": {"min_cvss_score": 7.0, "block_severities": ["CRITICAL", "HIGH"]},
            "system": {"scans_dir": "/opt/apt-mirror-system/scans"},
        }

    # Setup logging infrastructure (configures logger used by scanner module)
    setup_logger(
        "scanner",
        log_dir=config.get("system", {}).get("logs_dir", "/opt/apt-mirror-system/logs"),
        level=config.get("logging", {}).get("level", "INFO"),
    )

    # Initialize scanner
    scanner_config = config.get("scanner", {})
    policy_config = config.get("policy", {})

    scanner = PackageScanner(
        scanner_type=scanner_config.get("type", "trivy"),
        timeout=scanner_config.get("timeout", 300),
        scans_dir=config.get("system", {}).get("scans_dir", "/opt/apt-mirror-system/scans"),
        min_cvss_score=policy_config.get("min_cvss_score", 7.0),
        block_severities=policy_config.get("block_severities", ["CRITICAL", "HIGH"]),
    )

    # Scan package
    result = scanner.scan_package(package_path)

    # Output result
    print(f"Package: {result.package_name}")
    print(f"Version: {result.package_version}")
    print(f"Status: {result.status.value}")
    print(f"CVE Count: {result.cve_count}")
    print(f"Max CVSS: {result.cvss_max:.1f}")

    if result.error_message:
        print(f"Error: {result.error_message}")

    # Exit with appropriate code
    if result.status.value == "approved":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
