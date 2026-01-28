"""Enhanced security scanner integrating multiple security checks.

This module combines vulnerability scanning, virus scanning, integrity checking,
script analysis, and binary safety checks into a comprehensive security scanner.
Supports multiple package formats through the formats abstraction layer.
"""

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, TYPE_CHECKING

from ..common.logger import get_logger
from .scan_packages import PackageScanner, ScanStatus
from .virus_scanner import VirusScanner
from .integrity_checker import IntegrityChecker
from .script_analyzer import ScriptAnalyzer
from .binary_checker import BinaryChecker

if TYPE_CHECKING:
    from ..formats.base import PackageFormat, FormatCapabilities


@dataclass
class EnhancedScanResult:
    """Comprehensive security scan result."""

    package_name: str
    package_version: str
    overall_status: ScanStatus
    scan_date: str

    # Vulnerability scanning
    vulnerability_scan_status: str
    vulnerabilities: List[Dict[str, Any]]
    cvss_max: float
    cve_count: int

    # Virus scanning
    virus_scan_status: str
    viruses_found: List[str]

    # Integrity checking
    integrity_status: str
    integrity_issues: List[str]

    # Script analysis
    script_analysis_status: str
    script_issues: List[Dict[str, Any]]
    scripts_analyzed: List[str]

    # Binary safety
    binary_safety_status: str
    binary_issues: List[Dict[str, Any]]
    suid_binaries: List[str]
    world_writable_files: List[str]

    # Summary
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    warnings: List[str]

    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["overall_status"] = self.overall_status.value
        return result


class EnhancedSecurityScanner:
    """Comprehensive security scanner for packages.

    Supports multiple package formats through the formats abstraction layer.
    Adapts security checks based on format capabilities.
    """

    def __init__(
        self,
        scanner_type: str = "trivy",
        timeout: int = 300,
        scans_dir: str = "/opt/apt-mirror-system/scans",
        min_cvss_score: float = 7.0,
        block_severities: Optional[List[str]] = None,
        enable_virus_scan: bool = True,
        enable_integrity_check: bool = True,
        enable_script_analysis: bool = True,
        enable_binary_check: bool = True,
        format_handler: Optional["PackageFormat"] = None,
    ):
        """Initialize enhanced security scanner.

        Args:
            scanner_type: Vulnerability scanner to use (trivy, grype, pip-audit, npm-audit)
            timeout: Scan timeout in seconds
            scans_dir: Directory to store scan results
            min_cvss_score: Minimum CVSS score to block packages
            block_severities: List of severities to block
            enable_virus_scan: Enable ClamAV virus scanning
            enable_integrity_check: Enable package integrity verification
            enable_script_analysis: Enable maintainer script analysis
            enable_binary_check: Enable binary safety checks
            format_handler: Optional format handler for package extraction
        """
        self.logger = get_logger("enhanced_scanner")
        self.scans_dir = Path(scans_dir)
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.format_handler = format_handler
        self.timeout = timeout

        # Store enable flags (may be overridden by format capabilities)
        self._enable_virus_scan = enable_virus_scan
        self._enable_integrity_check = enable_integrity_check
        self._enable_script_analysis = enable_script_analysis
        self._enable_binary_check = enable_binary_check

        # Initialize component scanners
        self.vuln_scanner = PackageScanner(
            scanner_type=scanner_type,
            timeout=timeout,
            scans_dir=str(scans_dir),
            min_cvss_score=min_cvss_score,
            block_severities=block_severities,
            format_handler=format_handler,
        )

        self.virus_scanner = None
        if enable_virus_scan:
            try:
                self.virus_scanner = VirusScanner(timeout=timeout)
                self.logger.info("Virus scanning enabled")
            except RuntimeError as e:
                self.logger.warning(f"Virus scanning disabled: {e}")

        self.integrity_checker = None
        if enable_integrity_check:
            self.integrity_checker = IntegrityChecker()
            self.logger.info("Integrity checking enabled")

        self.script_analyzer = None
        if enable_script_analysis:
            self.script_analyzer = ScriptAnalyzer()
            self.logger.info("Script analysis enabled")

        self.binary_checker = None
        if enable_binary_check:
            self.binary_checker = BinaryChecker()
            self.logger.info("Binary safety checking enabled")

    def scan_package(self, package_path: str) -> EnhancedScanResult:
        """Perform comprehensive security scan on a package.

        Adapts security checks based on package format capabilities.

        Args:
            package_path: Path to package file

        Returns:
            EnhancedScanResult with all scan results
        """
        package_file = Path(package_path)

        # Get format handler and capabilities
        handler = self._get_format_handler(package_file)
        capabilities = self._get_capabilities(handler)

        # Parse metadata
        if handler:
            try:
                metadata = handler.parse_metadata(package_file)
                package_name = metadata.name
                package_version = metadata.version
            except Exception as e:
                self.logger.warning(f"Metadata parsing failed, using filename: {e}")
                package_name, package_version = self._parse_package_name(package_file.name)
        else:
            package_name, package_version = self._parse_package_name(package_file.name)

        self.logger.info(f"Starting enhanced security scan: {package_file.name}")

        warnings = []
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        low_issues = 0

        # 1. Vulnerability Scanning
        self.logger.info("Running vulnerability scan...")
        vuln_result = self.vuln_scanner.scan_package(package_path)

        vulnerability_scan_status = vuln_result.status.value
        vulnerabilities = vuln_result.vulnerabilities
        cvss_max = vuln_result.cvss_max
        cve_count = vuln_result.cve_count

        # Count vulnerability issues
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").upper()
            if severity == "CRITICAL":
                critical_issues += 1
            elif severity == "HIGH":
                high_issues += 1
            elif severity == "MEDIUM":
                medium_issues += 1
            elif severity == "LOW":
                low_issues += 1

        # 2. Virus Scanning (always applicable)
        virus_scan_status = "skipped"
        viruses_found = []

        if self.virus_scanner and capabilities.supports_virus_scan:
            self.logger.info("Running virus scan...")
            virus_result = self.virus_scanner.scan_package(package_path)
            virus_scan_status = "clean" if virus_result.clean else "infected"
            viruses_found = virus_result.threats_found

            if viruses_found:
                critical_issues += len(viruses_found)
                warnings.append(f"Viruses/malware detected: {', '.join(viruses_found)}")

        # 3. Integrity Checking
        integrity_status = "skipped"
        integrity_issues = []

        if self.integrity_checker and capabilities.supports_integrity_check:
            self.logger.info("Running integrity checks...")
            # Use format handler for integrity if available
            if handler:
                try:
                    is_valid = handler.validate_integrity(package_file)
                    integrity_status = "valid" if is_valid else "invalid"
                    if not is_valid:
                        integrity_issues = ["format_validation_failed"]
                        high_issues += 1
                except Exception as e:
                    self.logger.warning(f"Format integrity check failed: {e}")
                    integrity_status = "invalid"
                    integrity_issues = [str(e)]
                    high_issues += 1
            else:
                # Fall back to legacy integrity checker for .deb
                integrity_result = self.integrity_checker.check_package(package_path)
                integrity_status = "valid" if integrity_result.valid else "invalid"
                integrity_issues = integrity_result.checks_failed
                warnings.extend(integrity_result.warnings)

                if not integrity_result.valid:
                    high_issues += len(integrity_issues)
        elif not capabilities.supports_integrity_check:
            self.logger.debug("Integrity check not applicable for this format")

        # 4. Script Analysis
        script_analysis_status = "skipped"
        script_issues = []
        scripts_analyzed = []

        if self.script_analyzer and capabilities.supports_script_analysis:
            self.logger.info("Running script analysis...")
            # Use format handler to extract scripts if available
            if handler and capabilities.has_maintainer_scripts:
                try:
                    extracted = handler.extract(package_file)
                    try:
                        # Analyze scripts from extracted content
                        for script_info in extracted.scripts:
                            scripts_analyzed.append(script_info.name)
                            issues, warns = self.script_analyzer._analyze_script(
                                script_info.name, script_info.content
                            )
                            for issue in issues:
                                script_issues.append({
                                    "severity": issue.severity,
                                    "type": issue.issue_type,
                                    "description": issue.description,
                                    "line_number": issue.line_number,
                                    "code_snippet": issue.code_snippet,
                                })
                                if issue.severity == "critical":
                                    critical_issues += 1
                                elif issue.severity == "high":
                                    high_issues += 1
                                elif issue.severity == "medium":
                                    medium_issues += 1
                                elif issue.severity == "low":
                                    low_issues += 1
                            warnings.extend(warns)
                        script_analysis_status = "safe" if not any(
                            i["severity"] in ("critical", "high") for i in script_issues
                        ) else "unsafe"
                    finally:
                        extracted.cleanup()
                except Exception as e:
                    self.logger.warning(f"Script extraction failed, using legacy: {e}")
                    script_result = self.script_analyzer.analyze_package(package_path)
                    script_analysis_status = "safe" if script_result.safe else "unsafe"
                    scripts_analyzed = script_result.scripts_analyzed
                    warnings.extend(script_result.warnings)
                    for issue in script_result.issues_found:
                        script_issues.append({
                            "severity": issue.severity,
                            "type": issue.issue_type,
                            "description": issue.description,
                            "line_number": issue.line_number,
                            "code_snippet": issue.code_snippet,
                        })
                        if issue.severity == "critical":
                            critical_issues += 1
                        elif issue.severity == "high":
                            high_issues += 1
                        elif issue.severity == "medium":
                            medium_issues += 1
                        elif issue.severity == "low":
                            low_issues += 1
            else:
                # Fall back to legacy script analyzer for .deb
                script_result = self.script_analyzer.analyze_package(package_path)
                script_analysis_status = "safe" if script_result.safe else "unsafe"
                scripts_analyzed = script_result.scripts_analyzed
                warnings.extend(script_result.warnings)

                for issue in script_result.issues_found:
                    script_issues.append({
                        "severity": issue.severity,
                        "type": issue.issue_type,
                        "description": issue.description,
                        "line_number": issue.line_number,
                        "code_snippet": issue.code_snippet,
                    })
                    if issue.severity == "critical":
                        critical_issues += 1
                    elif issue.severity == "high":
                        high_issues += 1
                    elif issue.severity == "medium":
                        medium_issues += 1
                    elif issue.severity == "low":
                        low_issues += 1
        elif not capabilities.supports_script_analysis:
            self.logger.debug("Script analysis not applicable for this format")
            script_analysis_status = "not_applicable"

        # 5. Binary Safety Checks
        binary_safety_status = "skipped"
        binary_issues = []
        suid_binaries = []
        world_writable_files = []

        if self.binary_checker and capabilities.supports_binary_check:
            self.logger.info("Running binary safety checks...")
            # Use format handler for file list if available
            if handler:
                try:
                    file_list = handler.get_file_list(package_file)
                    # Analyze files using binary checker's logic
                    for file_info in file_list:
                        file_dict = {
                            "permissions": file_info.permissions,
                            "path": file_info.path,
                            "raw": f"{file_info.permissions} {file_info.path}",
                        }
                        issues, warns, flags = self.binary_checker._analyze_file(file_dict)
                        for issue in issues:
                            binary_issues.append({
                                "severity": issue.severity,
                                "type": issue.issue_type,
                                "file_path": issue.file_path,
                                "description": issue.description,
                                "permissions": issue.permissions,
                            })
                            if issue.severity == "critical":
                                critical_issues += 1
                            elif issue.severity == "high":
                                high_issues += 1
                            elif issue.severity == "medium":
                                medium_issues += 1
                            elif issue.severity == "low":
                                low_issues += 1
                        warnings.extend(warns)
                        if "suid" in flags:
                            suid_binaries.append(file_info.path)
                        if "world_writable" in flags:
                            world_writable_files.append(file_info.path)

                    binary_safety_status = "safe" if not any(
                        i["severity"] in ("critical", "high") for i in binary_issues
                    ) else "unsafe"
                except Exception as e:
                    self.logger.warning(f"Format file listing failed, using legacy: {e}")
                    binary_result = self.binary_checker.analyze_package(package_path)
                    binary_safety_status = "safe" if binary_result.safe else "unsafe"
                    suid_binaries = binary_result.suid_binaries
                    world_writable_files = binary_result.world_writable_files
                    warnings.extend(binary_result.warnings)
                    for issue in binary_result.issues_found:
                        binary_issues.append({
                            "severity": issue.severity,
                            "type": issue.issue_type,
                            "file_path": issue.file_path,
                            "description": issue.description,
                            "permissions": issue.permissions,
                        })
                        if issue.severity == "critical":
                            critical_issues += 1
                        elif issue.severity == "high":
                            high_issues += 1
                        elif issue.severity == "medium":
                            medium_issues += 1
                        elif issue.severity == "low":
                            low_issues += 1
            else:
                # Fall back to legacy binary checker for .deb
                binary_result = self.binary_checker.analyze_package(package_path)
                binary_safety_status = "safe" if binary_result.safe else "unsafe"
                suid_binaries = binary_result.suid_binaries
                world_writable_files = binary_result.world_writable_files
                warnings.extend(binary_result.warnings)

                for issue in binary_result.issues_found:
                    binary_issues.append({
                        "severity": issue.severity,
                        "type": issue.issue_type,
                        "file_path": issue.file_path,
                        "description": issue.description,
                        "permissions": issue.permissions,
                    })
                    if issue.severity == "critical":
                        critical_issues += 1
                    elif issue.severity == "high":
                        high_issues += 1
                    elif issue.severity == "medium":
                        medium_issues += 1
                    elif issue.severity == "low":
                        low_issues += 1
        elif not capabilities.supports_binary_check:
            self.logger.debug("Binary check not applicable for this format")
            binary_safety_status = "not_applicable"

        # Determine overall status
        overall_status = self._determine_overall_status(
            vuln_result.status,
            virus_scan_status,
            integrity_status,
            script_analysis_status,
            binary_safety_status,
            critical_issues,
            high_issues,
        )

        # Log summary
        if overall_status == ScanStatus.APPROVED:
            self.logger.info(
                f"Package {package_file.name} APPROVED - passed all security checks"
            )
        elif overall_status == ScanStatus.BLOCKED:
            self.logger.warning(
                f"Package {package_file.name} BLOCKED - {critical_issues} critical, "
                f"{high_issues} high issues found"
            )
        else:
            self.logger.error(
                f"Package {package_file.name} ERROR during scanning"
            )

        # Create comprehensive result
        result = EnhancedScanResult(
            package_name=package_name,
            package_version=package_version,
            overall_status=overall_status,
            scan_date=datetime.now().isoformat(),
            vulnerability_scan_status=vulnerability_scan_status,
            vulnerabilities=vulnerabilities,
            cvss_max=cvss_max,
            cve_count=cve_count,
            virus_scan_status=virus_scan_status,
            viruses_found=viruses_found,
            integrity_status=integrity_status,
            integrity_issues=integrity_issues,
            script_analysis_status=script_analysis_status,
            script_issues=script_issues,
            scripts_analyzed=scripts_analyzed,
            binary_safety_status=binary_safety_status,
            binary_issues=binary_issues,
            suid_binaries=suid_binaries,
            world_writable_files=world_writable_files,
            critical_issues=critical_issues,
            high_issues=high_issues,
            medium_issues=medium_issues,
            low_issues=low_issues,
            warnings=warnings,
        )

        # Save result
        self._save_result(result)

        return result

    def _determine_overall_status(
        self,
        vuln_status: ScanStatus,
        virus_status: str,
        integrity_status: str,
        script_status: str,
        binary_status: str,
        critical_issues: int,
        high_issues: int,
    ) -> ScanStatus:
        """Determine overall package approval status.

        Args:
            vuln_status: Vulnerability scan status
            virus_status: Virus scan status
            integrity_status: Integrity check status
            script_status: Script analysis status
            binary_status: Binary safety status
            critical_issues: Number of critical issues
            high_issues: Number of high issues

        Returns:
            Overall ScanStatus
        """
        # Any error results in blocking
        if vuln_status == ScanStatus.ERROR:
            return ScanStatus.ERROR

        # Any virus detection blocks the package
        if virus_status == "infected":
            return ScanStatus.BLOCKED

        # Invalid integrity blocks the package
        if integrity_status == "invalid":
            return ScanStatus.BLOCKED

        # Unsafe scripts block the package
        if script_status == "unsafe":
            return ScanStatus.BLOCKED

        # Unsafe binaries block the package
        if binary_status == "unsafe":
            return ScanStatus.BLOCKED

        # Critical or high vulnerabilities block the package
        if vuln_status == ScanStatus.BLOCKED:
            return ScanStatus.BLOCKED

        # Any critical issues block the package
        if critical_issues > 0:
            return ScanStatus.BLOCKED

        # Multiple high issues block the package (threshold: 3+)
        if high_issues >= 3:
            return ScanStatus.BLOCKED

        # Otherwise, approve
        return ScanStatus.APPROVED

    def _parse_package_name(self, filename: str) -> tuple[str, str]:
        """Parse package name and version from filename.

        Args:
            filename: Package filename

        Returns:
            Tuple of (package_name, version)
        """
        # Try format handler first
        if self.format_handler:
            return self.format_handler.parse_filename(filename)

        # Fall back to .deb format
        parts = filename.replace(".deb", "").split("_")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return filename, "unknown"

    def _get_format_handler(self, package_file: Path) -> Optional["PackageFormat"]:
        """Get format handler for package.

        Args:
            package_file: Path to package file

        Returns:
            PackageFormat handler or None
        """
        if self.format_handler:
            return self.format_handler

        # Try to auto-detect format
        try:
            from ..formats.registry import detect_format
            return detect_format(package_file)
        except ImportError:
            return None

    def _get_capabilities(self, handler: Optional["PackageFormat"]) -> "FormatCapabilities":
        """Get capabilities for format handler.

        Args:
            handler: PackageFormat handler or None

        Returns:
            FormatCapabilities (defaults if no handler)
        """
        if handler:
            return handler.capabilities

        # Default capabilities for legacy .deb handling
        from ..formats.base import FormatCapabilities
        return FormatCapabilities(
            supports_vulnerability_scan=True,
            supports_virus_scan=True,
            supports_integrity_check=True,
            supports_script_analysis=True,
            supports_binary_check=True,
            has_maintainer_scripts=True,
            has_binary_content=True,
        )

    def _save_result(self, result: EnhancedScanResult) -> None:
        """Save enhanced scan result to JSON file.

        Args:
            result: Enhanced scan result to save
        """
        filename = (
            f"{result.package_name}_{result.package_version}_"
            f"enhanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        output_path = self.scans_dir / filename

        try:
            with output_path.open("w") as f:
                json.dump(result.to_dict(), f, indent=2)
            self.logger.debug(f"Enhanced scan result saved to {output_path}")
        except (IOError, OSError):
            self.logger.exception("Failed to save enhanced scan result")

    def update_all_databases(self) -> Dict[str, bool]:
        """Update all scanner databases.

        Returns:
            Dictionary of scanner -> success status
        """
        results = {}

        # Update vulnerability database
        self.logger.info("Updating vulnerability database...")
        results["vulnerability"] = self.vuln_scanner.update_scanner_db()

        # Update virus definitions
        if self.virus_scanner:
            self.logger.info("Updating virus definitions...")
            results["virus"] = self.virus_scanner.update_definitions()

        return results
