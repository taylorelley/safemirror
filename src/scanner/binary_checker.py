"""Binary safety checker for Debian packages.

This module analyzes binary files in packages for security risks including
SUID/SGID bits, suspicious file permissions, and potentially dangerous binaries.
"""

import os
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Set

from ..common.logger import get_logger


@dataclass
class BinaryIssue:
    """Security issue found in binary file."""

    severity: str  # critical, high, medium, low
    issue_type: str
    file_path: str
    description: str
    permissions: Optional[str] = None


@dataclass
class BinarySafetyResult:
    """Result of binary safety analysis."""

    safe: bool
    files_analyzed: int
    issues_found: List[BinaryIssue]
    warnings: List[str]
    suid_binaries: List[str]
    sgid_binaries: List[str]
    world_writable_files: List[str]
    analysis_date: str
    error_message: Optional[str] = None


class BinaryChecker:
    """Safety checker for binary files in Debian packages."""

    # Binaries that should never have SUID/SGID
    SUSPICIOUS_SUID_BINARIES: ClassVar[Set[str]] = {
        "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh",  # Shells
        "python", "python2", "python3", "perl", "ruby", "php",  # Interpreters
        "nc", "ncat", "netcat", "socat",  # Network tools
        "wget", "curl", "ftp", "telnet",  # Download tools
        "vim", "vi", "nano", "emacs", "ed",  # Editors
        "find", "locate", "xargs",  # File search
        "tar", "gzip", "gunzip", "bzip2", "unzip", "zip",  # Archivers
    }

    # Paths where SUID is commonly legitimate
    LEGITIMATE_SUID_PATHS: ClassVar[Set[str]] = {
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/bin/su",
        "/usr/bin/passwd",
        "/bin/ping",
        "/usr/bin/ping",
        "/bin/ping6",
        "/usr/bin/ping6",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/sbin/unix_chkpwd",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/bin/mount",
        "/bin/umount",
    }

    def __init__(self):
        """Initialize binary checker."""
        self.logger = get_logger("binary_checker")

    def analyze_package(self, package_path: str) -> BinarySafetyResult:
        """Analyze binary files in a package for security issues.

        Args:
            package_path: Path to .deb package file

        Returns:
            BinarySafetyResult with analysis results
        """
        package_file = Path(package_path)

        if not package_file.exists():
            self.logger.error(f"Package file not found: {package_path}")
            return BinarySafetyResult(
                safe=False,
                files_analyzed=0,
                issues_found=[],
                warnings=[],
                suid_binaries=[],
                sgid_binaries=[],
                world_writable_files=[],
                analysis_date=datetime.now().isoformat(),
                error_message=f"Package file not found: {package_path}",
            )

        self.logger.info(f"Analyzing binary safety in: {package_file.name}")

        try:
            # Get file list with permissions
            file_list = self._get_file_list(package_path)

            if not file_list:
                # Empty package is suspicious - dpkg-deb succeeded but returned no files
                # This could indicate a malformed or empty package (both are unsafe)
                self.logger.warning(f"Package {package_file.name} contains no files - suspicious")
                return BinarySafetyResult(
                    safe=False,
                    files_analyzed=0,
                    issues_found=[
                        BinaryIssue(
                            severity="high",
                            issue_type="empty_package",
                            file_path="<package>",
                            description="Package contains no files (empty or malformed package)",
                        )
                    ],
                    warnings=["Package appears to be empty or have no parseable file entries"],
                    suid_binaries=[],
                    sgid_binaries=[],
                    world_writable_files=[],
                    analysis_date=datetime.now().isoformat(),
                )

            # Analyze files
            issues = []
            warnings = []
            suid_binaries = []
            sgid_binaries = []
            world_writable_files = []

            for file_info in file_list:
                file_issues, file_warnings, file_flags = self._analyze_file(file_info)
                issues.extend(file_issues)
                warnings.extend(file_warnings)

                if "suid" in file_flags:
                    suid_binaries.append(file_info["path"])
                if "sgid" in file_flags:
                    sgid_binaries.append(file_info["path"])
                if "world_writable" in file_flags:
                    world_writable_files.append(file_info["path"])

            # Determine if package is safe
            critical_issues = [i for i in issues if i.severity == "critical"]
            high_issues = [i for i in issues if i.severity == "high"]

            safe = len(critical_issues) == 0 and len(high_issues) == 0

            if not safe:
                self.logger.warning(
                    f"Package {package_file.name} has binary safety issues: "
                    f"{len(critical_issues)} critical, {len(high_issues)} high"
                )
            else:
                self.logger.info(f"Package {package_file.name} binaries appear safe")

            return BinarySafetyResult(
                safe=safe,
                files_analyzed=len(file_list),
                issues_found=issues,
                warnings=warnings,
                suid_binaries=suid_binaries,
                sgid_binaries=sgid_binaries,
                world_writable_files=world_writable_files,
                analysis_date=datetime.now().isoformat(),
            )

        except Exception as e:
            self.logger.exception(f"Binary safety analysis failed for {package_file.name}")
            return BinarySafetyResult(
                safe=False,
                files_analyzed=0,
                issues_found=[],
                warnings=[],
                suid_binaries=[],
                sgid_binaries=[],
                world_writable_files=[],
                analysis_date=datetime.now().isoformat(),
                error_message=str(e),
            )

    def _get_file_list(self, package_path: str) -> List[Dict[str, str]]:
        """Get list of files in package with permissions.

        Args:
            package_path: Path to .deb package

        Returns:
            List of file info dictionaries

        Raises:
            RuntimeError: If file listing fails (enforces default-deny)
        """
        try:
            result = subprocess.run(
                ["dpkg-deb", "-c", package_path],
                capture_output=True,
                check=True,
                timeout=60,
            )

            output = result.stdout.decode()
            file_list = []

            for line in output.splitlines():
                # Format: drwxr-xr-x root/root 0 2023-04-18 12:34 ./usr/bin/
                parts = line.split(None, 5)
                if len(parts) >= 6:
                    permissions = parts[0]
                    file_path = parts[5].lstrip("./")

                    file_list.append({
                        "permissions": permissions,
                        "path": file_path,
                        "raw": line,
                    })

            return file_list

        except subprocess.CalledProcessError as e:
            self.logger.exception("Failed to get file list")
            # Re-raise to enforce default-deny: listing failure = unsafe
            raise RuntimeError(f"File listing failed: {e.stderr.decode() if e.stderr else str(e)}") from e
        except subprocess.TimeoutExpired as e:
            self.logger.exception("File list retrieval timed out")
            # Re-raise to enforce default-deny: timeout = unsafe
            raise RuntimeError("File listing timed out") from e
        except Exception as e:
            self.logger.exception("Error getting file list")
            # Re-raise to enforce default-deny: any failure = unsafe
            raise RuntimeError(f"File listing error: {str(e)}") from e

    def _analyze_file(self, file_info: Dict[str, str]) -> tuple[List[BinaryIssue], List[str], Set[str]]:
        """Analyze a single file for security issues.

        Args:
            file_info: File information dictionary

        Returns:
            Tuple of (issues, warnings, flags)
        """
        issues = []
        warnings = []
        flags = set()

        permissions = file_info["permissions"]
        file_path = file_info["path"]

        # Parse permissions string (e.g., "-rwsr-xr-x")
        if len(permissions) < 10:
            return issues, warnings, flags

        file_type = permissions[0]
        owner_perms = permissions[1:4]
        group_perms = permissions[4:7]
        other_perms = permissions[7:10]

        # Check for SUID bit
        if owner_perms[2] in "sS":
            flags.add("suid")

            # Check if this is a suspicious SUID binary
            file_name = Path(file_path).name
            if file_name in self.SUSPICIOUS_SUID_BINARIES:
                issues.append(
                    BinaryIssue(
                        severity="critical",
                        issue_type="suspicious_suid",
                        file_path=file_path,
                        description=f"Suspicious SUID binary: {file_name}",
                        permissions=permissions,
                    )
                )
            elif file_path not in self.LEGITIMATE_SUID_PATHS:
                # Check if it's in a non-standard location
                if not file_path.startswith(("usr/bin/", "usr/sbin/", "bin/", "sbin/")):
                    issues.append(
                        BinaryIssue(
                            severity="high",
                            issue_type="unusual_suid",
                            file_path=file_path,
                            description="SUID binary in unusual location",
                            permissions=permissions,
                        )
                    )
                else:
                    warnings.append(f"SUID binary found: {file_path}")

        # Check for SGID bit
        if group_perms[2] in "sS":
            flags.add("sgid")

            # SGID on non-directory files can be suspicious
            if file_type != "d":
                file_name = Path(file_path).name
                if file_name in self.SUSPICIOUS_SUID_BINARIES:
                    issues.append(
                        BinaryIssue(
                            severity="high",
                            issue_type="suspicious_sgid",
                            file_path=file_path,
                            description=f"Suspicious SGID binary: {file_name}",
                            permissions=permissions,
                        )
                    )
                else:
                    warnings.append(f"SGID binary found: {file_path}")

        # Check for world-writable files
        if other_perms[1] == "w":
            flags.add("world_writable")

            # World-writable files are generally bad, except for specific cases
            if file_type != "d" or "t" not in permissions:  # Not a sticky directory
                severity = "high" if file_type != "d" else "medium"
                issues.append(
                    BinaryIssue(
                        severity=severity,
                        issue_type="world_writable",
                        file_path=file_path,
                        description="World-writable file/directory",
                        permissions=permissions,
                    )
                )

        # Check for overly permissive directories
        if file_type == "d" and other_perms == "rwx":
            if "t" not in permissions:  # No sticky bit
                issues.append(
                    BinaryIssue(
                        severity="medium",
                        issue_type="permissive_directory",
                        file_path=file_path,
                        description="Directory with overly permissive permissions",
                        permissions=permissions,
                    )
                )

        # Check for suspicious file locations
        # Directories to monitor (end with / or are known directories)
        suspicious_dirs = [
            "/etc/cron",
            "/etc/init.d",
            "/etc/systemd/system",
            "/.ssh/",
            "/root/",
        ]

        # Specific files to monitor
        suspicious_files = [
            "/etc/sudoers",
            "/etc/passwd",
            "/etc/shadow",
        ]

        # Normalize file path for comparison
        normalized_path = os.path.normpath("/" + file_path)

        # Check directory-based matches
        for suspicious_dir in suspicious_dirs:
            # Normalize the suspicious directory path
            norm_dir = os.path.normpath(suspicious_dir.rstrip("/"))

            # Check if file is in this directory or subdirectory
            # Must be exact path component match, not substring
            if normalized_path.startswith(norm_dir + os.sep) or normalized_path == norm_dir:
                issues.append(
                    BinaryIssue(
                        severity="medium",
                        issue_type="sensitive_location",
                        file_path=file_path,
                        description=f"File in sensitive directory: {suspicious_dir}",
                        permissions=permissions,
                    )
                )
                break

        # Check file-based matches (exact file match)
        for suspicious_file in suspicious_files:
            norm_file = os.path.normpath(suspicious_file)

            # Check exact match or basename match
            if normalized_path == norm_file or os.path.basename(normalized_path) == os.path.basename(norm_file):
                issues.append(
                    BinaryIssue(
                        severity="medium",
                        issue_type="sensitive_location",
                        file_path=file_path,
                        description=f"Sensitive file: {suspicious_file}",
                        permissions=permissions,
                    )
                )
                break

        # Check for hidden files in unusual locations
        if file_path.startswith(".") and file_type == "-":
            issues.append(
                BinaryIssue(
                    severity="low",
                    issue_type="hidden_file",
                    file_path=file_path,
                    description="Hidden file in package",
                    permissions=permissions,
                )
            )

        # Check for devices
        if file_type in ["b", "c"]:  # Block or character device
            issues.append(
                BinaryIssue(
                    severity="critical",
                    issue_type="device_file",
                    file_path=file_path,
                    description="Device file in package (should not exist)",
                    permissions=permissions,
                )
            )

        return issues, warnings, flags

    def check_elf_binary(self, binary_path: str) -> Dict[str, Any]:
        """Check ELF binary for security features.

        Args:
            binary_path: Path to binary file

        Returns:
            Dictionary with security feature status
        """
        try:
            # Use readelf to check security features
            result = subprocess.run(
                ["readelf", "-h", "-l", binary_path],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                # Not an ELF binary
                return {"is_elf": False}

            output = result.stdout.decode()

            # Check for security features
            features = {
                "is_elf": True,
                "pie": "DYN (Shared object file)" in output,  # Position Independent Executable
                "nx": "GNU_STACK" in output and "RWE" not in output,  # No Execute
                "relro": "GNU_RELRO" in output,  # Read-only relocations
                "canary": None,  # Would need to check with objdump/checksec
            }

            return features

        except FileNotFoundError:
            # readelf not available
            return {"is_elf": False, "error": "readelf not available"}
        except subprocess.TimeoutExpired:
            return {"is_elf": False, "error": "timeout"}
        except Exception as e:
            return {"is_elf": False, "error": str(e)}
