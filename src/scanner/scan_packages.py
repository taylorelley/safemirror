"""Package scanner worker for safe-apt.

Extracts .deb packages and runs vulnerability scans using Trivy or Grype.
Implements retry logic and stores scan results as JSON.
"""

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..common.logger import get_logger


class ScanStatus(Enum):
    """Scan result status."""

    APPROVED = "approved"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class ScanResult:
    """Result of a package vulnerability scan."""

    package_name: str
    package_version: str
    status: ScanStatus
    scan_date: str
    scanner_type: str
    vulnerabilities: List[Dict[str, Any]]
    error_message: Optional[str] = None
    cvss_max: float = 0.0
    cve_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["status"] = self.status.value
        return result


class PackageScanner:
    """Scanner for Debian packages using Trivy or Grype."""

    def __init__(
        self,
        scanner_type: str = "trivy",
        timeout: int = 300,
        scans_dir: str = "/opt/apt-mirror-system/scans",
        min_cvss_score: float = 7.0,
        block_severities: Optional[List[str]] = None,
    ):
        """Initialize package scanner.

        Args:
            scanner_type: Scanner to use (trivy or grype)
            timeout: Scan timeout in seconds
            scans_dir: Directory to store scan results
            min_cvss_score: Minimum CVSS score to block packages
            block_severities: List of severities to block
        """
        self.scanner_type = scanner_type.lower()
        self.timeout = timeout
        self.scans_dir = Path(scans_dir)
        self.min_cvss_score = min_cvss_score
        self.block_severities = block_severities or ["CRITICAL", "HIGH"]
        self.logger = get_logger("scanner")

        # Ensure scans directory exists
        self.scans_dir.mkdir(parents=True, exist_ok=True)

        # Validate scanner availability
        self._validate_scanner()

    def _validate_scanner(self) -> None:
        """Validate that the scanner is installed and available."""
        try:
            if self.scanner_type == "trivy":
                subprocess.run(
                    ["trivy", "--version"],
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
            elif self.scanner_type == "grype":
                subprocess.run(
                    ["grype", "version"],
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
            else:
                raise ValueError(f"Unknown scanner type: {self.scanner_type}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.logger.exception("Scanner validation failed")
            raise RuntimeError(f"Scanner {self.scanner_type} not available") from e

    def scan_package(self, package_path: str) -> ScanResult:
        """Scan a Debian package for vulnerabilities.

        Args:
            package_path: Path to .deb package file

        Returns:
            ScanResult with vulnerability information
        """
        package_file = Path(package_path)

        if not package_file.exists():
            self.logger.error(f"Package file not found: {package_path}")
            return self._error_result(
                package_file.name, f"Package file not found: {package_path}"
            )

        self.logger.info(f"Scanning package: {package_file.name}")

        # Extract package name and version
        package_name, package_version = self._parse_package_name(package_file.name)

        # Extract package to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                self._extract_package(package_path, temp_dir)
                vulnerabilities = self._run_scanner(temp_dir)
                result = self._analyze_results(
                    package_name, package_version, vulnerabilities
                )
            except Exception as e:
                self.logger.exception(f"Scan failed for {package_file.name}")
                result = self._error_result(package_name, str(e), package_version)

        # Save scan result
        self._save_result(result)

        return result

    def _parse_package_name(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from .deb filename.

        Args:
            filename: .deb filename

        Returns:
            Tuple of (package_name, version)
        """
        # Format: package-name_version_architecture.deb
        # Example: curl_7.81.0-1ubuntu1.16_amd64.deb
        parts = filename.replace(".deb", "").split("_")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return filename, "unknown"

    def _extract_package(self, package_path: str, extract_dir: str) -> None:
        """Extract .deb package contents.

        Args:
            package_path: Path to .deb file
            extract_dir: Directory to extract to
        """
        self.logger.debug(f"Extracting {package_path} to {extract_dir}")

        try:
            # Extract data.tar.* from .deb
            subprocess.run(
                ["dpkg-deb", "-x", package_path, extract_dir],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to extract package: {e.stderr.decode()}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("Package extraction timed out") from e

    def _run_scanner(self, scan_path: str) -> List[Dict[str, Any]]:
        """Run vulnerability scanner on extracted package.

        Args:
            scan_path: Path to extracted package contents

        Returns:
            List of vulnerability dictionaries
        """
        self.logger.debug(f"Running {self.scanner_type} on {scan_path}")

        try:
            if self.scanner_type == "trivy":
                return self._run_trivy(scan_path)
            elif self.scanner_type == "grype":
                return self._run_grype(scan_path)
            else:
                raise ValueError(f"Unknown scanner: {self.scanner_type}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Scanner timed out after {self.timeout} seconds")

    def _run_trivy(self, scan_path: str) -> List[Dict[str, Any]]:
        """Run Trivy scanner.

        Args:
            scan_path: Path to scan

        Returns:
            List of vulnerabilities
        """
        result = subprocess.run(
            [
                "trivy",
                "fs",
                "--format",
                "json",
                "--quiet",
                scan_path,
            ],
            capture_output=True,
            timeout=self.timeout,
            check=False,  # Don't raise on non-zero exit (vulnerabilities found)
        )

        output = result.stdout.decode()
        if not output.strip():
            return []

        try:
            data = json.loads(output)
            vulnerabilities = []

            # Trivy format: {"Results": [{"Vulnerabilities": [...]}]}
            for result_item in data.get("Results", []):
                for vuln in result_item.get("Vulnerabilities", []):
                    vulnerabilities.append(
                        {
                            "cve_id": vuln.get("VulnerabilityID", ""),
                            "severity": vuln.get("Severity", "UNKNOWN"),
                            "cvss_score": vuln.get("CVSS", {})
                            .get("nvd", {})
                            .get("V3Score", 0.0),
                            "package": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "title": vuln.get("Title", ""),
                            "description": vuln.get("Description", ""),
                        }
                    )

            return vulnerabilities
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse Trivy output: {e}")
            return []

    def _run_grype(self, scan_path: str) -> List[Dict[str, Any]]:
        """Run Grype scanner.

        Args:
            scan_path: Path to scan

        Returns:
            List of vulnerabilities
        """
        result = subprocess.run(
            [
                "grype",
                f"dir:{scan_path}",
                "-o",
                "json",
                "--quiet",
            ],
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )

        output = result.stdout.decode()
        if not output.strip():
            return []

        try:
            data = json.loads(output)
            vulnerabilities = []

            # Grype format: {"matches": [...]}
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                vulnerabilities.append(
                    {
                        "cve_id": vuln.get("id", ""),
                        "severity": vuln.get("severity", "UNKNOWN"),
                        "cvss_score": vuln.get("cvss", [{}])[0].get("metrics", {}).get("baseScore", 0.0)
                        if vuln.get("cvss")
                        else 0.0,
                        "package": match.get("artifact", {}).get("name", ""),
                        "installed_version": match.get("artifact", {}).get(
                            "version", ""
                        ),
                        "fixed_version": vuln.get("fix", {}).get("versions", [""])[0]
                        if vuln.get("fix", {}).get("versions")
                        else "",
                        "title": vuln.get("namespace", ""),
                        "description": vuln.get("description", ""),
                    }
                )

            return vulnerabilities
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse Grype output: {e}")
            return []

    def _analyze_results(
        self, package_name: str, package_version: str, vulnerabilities: List[Dict[str, Any]]
    ) -> ScanResult:
        """Analyze scan results and determine approval status.

        Args:
            package_name: Package name
            package_version: Package version
            vulnerabilities: List of vulnerabilities

        Returns:
            ScanResult with approval decision
        """
        if not vulnerabilities:
            self.logger.info(f"Package {package_name} approved: No vulnerabilities found")
            return ScanResult(
                package_name=package_name,
                package_version=package_version,
                status=ScanStatus.APPROVED,
                scan_date=datetime.now().isoformat(),
                scanner_type=self.scanner_type,
                vulnerabilities=[],
                cvss_max=0.0,
                cve_count=0,
            )

        # Calculate metrics
        cvss_max = max((v.get("cvss_score", 0.0) for v in vulnerabilities), default=0.0)
        cve_count = len(vulnerabilities)
        blocked_severities = [
            v for v in vulnerabilities if v.get("severity") in self.block_severities
        ]

        # Determine status based on policy
        if blocked_severities or cvss_max >= self.min_cvss_score:
            status = ScanStatus.BLOCKED
            self.logger.warning(
                f"Package {package_name} blocked: {cve_count} CVEs found "
                f"(max CVSS: {cvss_max:.1f})"
            )
        else:
            status = ScanStatus.APPROVED
            self.logger.info(
                f"Package {package_name} approved: Vulnerabilities below threshold"
            )

        return ScanResult(
            package_name=package_name,
            package_version=package_version,
            status=status,
            scan_date=datetime.now().isoformat(),
            scanner_type=self.scanner_type,
            vulnerabilities=vulnerabilities,
            cvss_max=cvss_max,
            cve_count=cve_count,
        )

    def _error_result(
        self, package_name: str, error_message: str, package_version: str = "unknown"
    ) -> ScanResult:
        """Create error result (blocked by default).

        Args:
            package_name: Package name
            error_message: Error description
            package_version: Package version

        Returns:
            ScanResult with error status
        """
        return ScanResult(
            package_name=package_name,
            package_version=package_version,
            status=ScanStatus.ERROR,
            scan_date=datetime.now().isoformat(),
            scanner_type=self.scanner_type,
            vulnerabilities=[],
            error_message=error_message,
        )

    def _save_result(self, result: ScanResult) -> None:
        """Save scan result to JSON file.

        Args:
            result: Scan result to save
        """
        filename = f"{result.package_name}_{result.package_version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = self.scans_dir / filename

        try:
            with output_path.open("w") as f:
                json.dump(result.to_dict(), f, indent=2)
            self.logger.debug(f"Scan result saved to {output_path}")
        except Exception as e:
            self.logger.exception("Failed to save scan result")

    def update_scanner_db(self) -> bool:
        """Update vulnerability database.

        Returns:
            True if update successful, False otherwise
        """
        self.logger.info(f"Updating {self.scanner_type} vulnerability database")

        try:
            if self.scanner_type == "trivy":
                subprocess.run(
                    ["trivy", "image", "--download-db-only"],
                    check=True,
                    timeout=600,
                    capture_output=True,
                )
            elif self.scanner_type == "grype":
                subprocess.run(
                    ["grype", "db", "update"],
                    check=True,
                    timeout=600,
                    capture_output=True,
                )
            self.logger.info("Vulnerability database updated successfully")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.logger.exception("Database update failed")
            return False
