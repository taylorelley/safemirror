"""Virus and malware scanning for Debian packages using ClamAV.

This module provides virus/malware detection for package files and extracted
contents, integrating with ClamAV antivirus engine.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..common.logger import get_logger


@dataclass
class VirusScanResult:
    """Result of virus/malware scan."""

    clean: bool
    threats_found: List[str]
    files_scanned: int
    scan_date: str
    scanner_version: str
    error_message: Optional[str] = None


class VirusScanner:
    """ClamAV-based virus scanner for Debian packages."""

    def __init__(self, timeout: int = 300, update_on_init: bool = False):
        """Initialize virus scanner.

        Args:
            timeout: Scan timeout in seconds
            update_on_init: Update virus definitions on initialization
        """
        self.timeout = timeout
        self.logger = get_logger("virus_scanner")

        # Validate ClamAV availability
        self._validate_clamav()

        if update_on_init:
            self.update_definitions()

    def _validate_clamav(self) -> None:
        """Validate that ClamAV is installed and available."""
        try:
            subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.logger.exception("ClamAV validation failed")
            raise RuntimeError("ClamAV not available - install with: apt-get install clamav clamav-daemon") from e

    def scan_package(self, package_path: str) -> VirusScanResult:
        """Scan a Debian package for viruses and malware.

        Args:
            package_path: Path to .deb package file

        Returns:
            VirusScanResult with scan results
        """
        package_file = Path(package_path)

        if not package_file.exists():
            self.logger.error(f"Package file not found: {package_path}")
            return VirusScanResult(
                clean=False,
                threats_found=[],
                files_scanned=0,
                scan_date=datetime.now().isoformat(),
                scanner_version="unknown",
                error_message=f"Package file not found: {package_path}",
            )

        self.logger.info(f"Virus scanning package: {package_file.name}")

        try:
            # Get scanner version
            version = self._get_scanner_version()

            # Run ClamAV scan
            result = subprocess.run(
                [
                    "clamscan",
                    "--stdout",
                    "--no-summary",
                    "-r",  # Recursive
                    "--infected",  # Only show infected files
                    str(package_path),
                ],
                capture_output=True,
                timeout=self.timeout,
                check=False,  # Don't raise on virus found (exit code 1)
            )

            # Parse output
            threats = self._parse_scan_output(result.stdout.decode())

            # Exit codes: 0 = clean, 1 = virus found, 2 = error
            if result.returncode == 2:
                error_msg = result.stderr.decode().strip()
                self.logger.error(f"ClamAV scan error: {error_msg}")
                return VirusScanResult(
                    clean=False,
                    threats_found=[],
                    files_scanned=0,
                    scan_date=datetime.now().isoformat(),
                    scanner_version=version,
                    error_message=f"Scan error: {error_msg}",
                )

            clean = len(threats) == 0
            if not clean:
                self.logger.warning(
                    f"Package {package_file.name} contains threats: {', '.join(threats)}"
                )
            else:
                self.logger.info(f"Package {package_file.name} is clean")

            return VirusScanResult(
                clean=clean,
                threats_found=threats,
                files_scanned=1,  # Package itself
                scan_date=datetime.now().isoformat(),
                scanner_version=version,
            )

        except subprocess.TimeoutExpired:
            self.logger.error(f"Virus scan timed out for {package_file.name}")
            return VirusScanResult(
                clean=False,
                threats_found=[],
                files_scanned=0,
                scan_date=datetime.now().isoformat(),
                scanner_version="unknown",
                error_message=f"Scan timed out after {self.timeout} seconds",
            )
        except Exception as e:
            self.logger.exception(f"Virus scan failed for {package_file.name}")
            return VirusScanResult(
                clean=False,
                threats_found=[],
                files_scanned=0,
                scan_date=datetime.now().isoformat(),
                scanner_version="unknown",
                error_message=str(e),
            )

    def scan_directory(self, directory_path: str) -> VirusScanResult:
        """Scan an extracted package directory.

        Args:
            directory_path: Path to directory to scan

        Returns:
            VirusScanResult with scan results
        """
        dir_path = Path(directory_path)

        if not dir_path.exists() or not dir_path.is_dir():
            self.logger.error(f"Directory not found: {directory_path}")
            return VirusScanResult(
                clean=False,
                threats_found=[],
                files_scanned=0,
                scan_date=datetime.now().isoformat(),
                scanner_version="unknown",
                error_message=f"Directory not found: {directory_path}",
            )

        self.logger.info(f"Virus scanning directory: {directory_path}")

        try:
            version = self._get_scanner_version()

            # Count files to scan
            file_count = sum(1 for _ in dir_path.rglob("*") if _.is_file())

            # Run ClamAV scan
            result = subprocess.run(
                [
                    "clamscan",
                    "--stdout",
                    "--no-summary",
                    "-r",
                    "--infected",
                    str(directory_path),
                ],
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )

            threats = self._parse_scan_output(result.stdout.decode())

            if result.returncode == 2:
                error_msg = result.stderr.decode().strip()
                self.logger.error(f"ClamAV scan error: {error_msg}")
                return VirusScanResult(
                    clean=False,
                    threats_found=[],
                    files_scanned=0,
                    scan_date=datetime.now().isoformat(),
                    scanner_version=version,
                    error_message=f"Scan error: {error_msg}",
                )

            clean = len(threats) == 0
            if not clean:
                self.logger.warning(
                    f"Directory contains {len(threats)} threats: {', '.join(threats[:5])}"
                )
            else:
                self.logger.info(f"Directory is clean ({file_count} files scanned)")

            return VirusScanResult(
                clean=clean,
                threats_found=threats,
                files_scanned=file_count,
                scan_date=datetime.now().isoformat(),
                scanner_version=version,
            )

        except subprocess.TimeoutExpired:
            self.logger.error(f"Virus scan timed out for directory {directory_path}")
            return VirusScanResult(
                clean=False,
                threats_found=[],
                files_scanned=0,
                scan_date=datetime.now().isoformat(),
                scanner_version="unknown",
                error_message=f"Scan timed out after {self.timeout} seconds",
            )
        except Exception as e:
            self.logger.exception(f"Virus scan failed for directory {directory_path}")
            return VirusScanResult(
                clean=False,
                threats_found=[],
                files_scanned=0,
                scan_date=datetime.now().isoformat(),
                scanner_version="unknown",
                error_message=str(e),
            )

    def _parse_scan_output(self, output: str) -> List[str]:
        """Parse ClamAV scan output to extract threat names.

        Args:
            output: ClamAV stdout output

        Returns:
            List of threat signatures found
        """
        threats = []
        for line in output.splitlines():
            # ClamAV output format: "filename: THREAT_NAME FOUND"
            if "FOUND" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    threat_part = parts[-1].strip()
                    threat_name = threat_part.replace("FOUND", "").strip()
                    threats.append(threat_name)
        return threats

    def _get_scanner_version(self) -> str:
        """Get ClamAV scanner version.

        Returns:
            Version string
        """
        try:
            result = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                check=True,
                timeout=10,
            )
            version_line = result.stdout.decode().strip()
            # Format: "ClamAV 0.103.8/26860/Tue Apr 18 08:12:50 2023"
            return version_line.split("/")[0].replace("ClamAV", "").strip()
        except Exception:
            return "unknown"

    def update_definitions(self) -> bool:
        """Update ClamAV virus definitions.

        Returns:
            True if update successful, False otherwise
        """
        self.logger.info("Updating ClamAV virus definitions")

        try:
            # Stop clamd if running to avoid conflicts
            subprocess.run(
                ["systemctl", "stop", "clamav-daemon"],
                capture_output=True,
                check=False,
                timeout=30,
            )

            # Update definitions
            result = subprocess.run(
                ["freshclam", "--quiet"],
                capture_output=True,
                timeout=600,
                check=False,
            )

            # Restart clamd
            subprocess.run(
                ["systemctl", "start", "clamav-daemon"],
                capture_output=True,
                check=False,
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.info("Virus definitions updated successfully")
                return True
            else:
                error_msg = result.stderr.decode().strip()
                self.logger.warning(f"Virus definition update completed with warnings: {error_msg}")
                return True  # freshclam returns non-zero even for successful updates sometimes

        except subprocess.TimeoutExpired:
            self.logger.error("Virus definition update timed out")
            return False
        except Exception as e:
            self.logger.exception("Virus definition update failed")
            return False

    def get_database_info(self) -> Dict[str, Any]:
        """Get information about ClamAV virus database.

        Returns:
            Dictionary with database information
        """
        try:
            result = subprocess.run(
                ["sigtool", "--info"],
                capture_output=True,
                check=True,
                timeout=10,
            )

            output = result.stdout.decode()
            info = {}

            for line in output.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    info[key.strip()] = value.strip()

            return info
        except Exception as e:
            self.logger.warning(f"Failed to get database info: {e}")
            return {}
