"""Maintainer script security analyzer for Debian packages.

This module analyzes maintainer scripts (preinst, postinst, prerm, postrm)
for suspicious patterns, dangerous commands, and potential security risks.
"""

import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Set, Tuple

from ..common.logger import get_logger


@dataclass
class ScriptIssue:
    """Security issue found in maintainer script."""

    severity: str  # critical, high, medium, low
    issue_type: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None


@dataclass
class ScriptAnalysisResult:
    """Result of maintainer script analysis."""

    safe: bool
    scripts_analyzed: List[str]
    issues_found: List[ScriptIssue]
    warnings: List[str]
    analysis_date: str
    error_message: Optional[str] = None


class ScriptAnalyzer:
    """Analyzer for Debian package maintainer scripts."""

    # Dangerous command patterns (regex patterns with severity and description)
    # Using regex to avoid false positives from substring matching
    DANGEROUS_COMMANDS: ClassVar[Dict[str, Tuple[str, str]]] = {
        r"\brm\s+-[a-zA-Z]*rf?\s+/(?:\s|$|;|\||&)": ("critical", "Recursive deletion of root directory (rm -rf /)"),
        r"\bdd\s+if=/dev/(?:zero|random)\s+of=/dev/[sh]d": ("critical", "Disk overwrite with dd"),
        r"\bmkfs\b": ("critical", "Filesystem creation (mkfs)"),
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:": ("critical", "Fork bomb detected"),
        r"(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh\b": ("high", "Pipe from network to shell (curl/wget | bash)"),
        r"\beval\s*\$\(": ("high", "Dynamic code evaluation with command substitution"),
        r"\bchmod\s+(?:0?777|a\+rwx)\b": ("medium", "Overly permissive file permissions (chmod 777)"),
        r"\bchown\s+-R\s+root:root\s+/(?:\s|$|;|\||&)": ("high", "Recursive ownership change of root directory"),
        r"/dev/(?:tcp|udp)/": ("medium", "Network device access (reverse shell risk)"),
        r"\b(?:nc|ncat|netcat)\s+-l": ("medium", "Netcat listener (reverse shell risk)"),
    }

    # Suspicious patterns
    SUSPICIOUS_PATTERNS: ClassVar[Dict[str, Tuple[str, str]]] = {
        r"base64.*decode": ("medium", "Base64 decoding (potential obfuscation)"),
        r"(curl|wget).*\|\s*(bash|sh)": ("high", "Pipe to shell from network"),
        r"chmod\s+[0-7]*[7][0-7]*\s+": ("medium", "Overly permissive file permissions"),
        r"chmod\s+u\+s": ("high", "SUID bit modification"),
        r"chmod\s+g\+s": ("medium", "SGID bit modification"),
        r"/etc/passwd": ("high", "Direct /etc/passwd manipulation"),
        r"/etc/shadow": ("critical", "Direct /etc/shadow access"),
        r"iptables\s+-F": ("medium", "Firewall rules flush"),
        r"setenforce\s+0": ("high", "SELinux disable"),
        r"systemctl\s+disable": ("low", "Service disable"),
        r"crontab.*-r": ("medium", "Crontab removal"),
        r"(^|;|\|)\s*rm\s+-rf\s+/": ("critical", "Recursive root deletion"),
        r"dd\s+if=/dev/(zero|random)": ("high", "Disk overwrite"),
        r">(>)?\s*/dev/(sd|hd|nvme)": ("critical", "Direct disk write"),
        r"mkfs\.\w+": ("critical", "Filesystem creation"),
        r"fdisk|parted|gdisk": ("high", "Partition manipulation"),
        r"echo\s+.*>>\s*/etc/sudoers": ("critical", "Sudoers modification"),
        r"useradd.*-o\s+-u\s+0": ("critical", "UID 0 user creation"),
        r"ssh.*-R\s+\d+:": ("medium", "SSH reverse tunnel"),
        r"\/proc\/kcore": ("high", "Kernel memory access"),
        r"\/dev\/mem": ("high", "Physical memory access"),
        r"modprobe": ("medium", "Kernel module loading"),
        r"insmod|rmmod": ("medium", "Kernel module manipulation"),
    }

    # Network-related patterns
    NETWORK_PATTERNS: ClassVar[Dict[str, Tuple[str, str]]] = {
        r"(curl|wget|nc|ncat|socat)\s+": ("low", "Network communication"),
        r"(ftp|telnet|ssh)\s+": ("low", "Remote connection"),
        r"\/dev\/(tcp|udp)\/": ("medium", "Network device access"),
        r"iptables|nftables|ufw": ("low", "Firewall modification"),
        r"(ifconfig|ip\s+addr|ip\s+link)": ("low", "Network configuration"),
    }

    # Command injection patterns
    INJECTION_PATTERNS: ClassVar[Dict[str, Tuple[str, str]]] = {
        r"eval\s+": ("high", "Dynamic code evaluation"),
        r"exec\s+": ("medium", "Command execution"),
        r"\$\(.*\)": ("low", "Command substitution"),
        r"`[^`]+`": ("low", "Backtick command substitution"),
        r"source\s+": ("low", "External script sourcing"),
        r"\.\s+": ("low", "Script sourcing"),
    }

    def __init__(self):
        """Initialize script analyzer."""
        self.logger = get_logger("script_analyzer")

    def analyze_package(self, package_path: str) -> ScriptAnalysisResult:
        """Analyze all maintainer scripts in a package.

        Args:
            package_path: Path to .deb package file

        Returns:
            ScriptAnalysisResult with analysis results
        """
        package_file = Path(package_path)

        if not package_file.exists():
            self.logger.error(f"Package file not found: {package_path}")
            return ScriptAnalysisResult(
                safe=False,
                scripts_analyzed=[],
                issues_found=[],
                warnings=[],
                analysis_date=datetime.now().isoformat(),
                error_message=f"Package file not found: {package_path}",
            )

        self.logger.info(f"Analyzing maintainer scripts in: {package_file.name}")

        try:
            # Extract maintainer scripts
            scripts = self._extract_maintainer_scripts(package_path)

            if not scripts:
                self.logger.info("No maintainer scripts found in package")
                return ScriptAnalysisResult(
                    safe=True,
                    scripts_analyzed=[],
                    issues_found=[],
                    warnings=[],
                    analysis_date=datetime.now().isoformat(),
                )

            # Analyze each script
            all_issues = []
            all_warnings = []
            scripts_analyzed = []

            for script_name, script_content in scripts.items():
                scripts_analyzed.append(script_name)
                issues, warnings = self._analyze_script(script_name, script_content)
                all_issues.extend(issues)
                all_warnings.extend(warnings)

            # Determine if package is safe
            critical_issues = [i for i in all_issues if i.severity == "critical"]
            high_issues = [i for i in all_issues if i.severity == "high"]

            safe = len(critical_issues) == 0 and len(high_issues) == 0

            if not safe:
                self.logger.warning(
                    f"Package {package_file.name} has security issues in maintainer scripts: "
                    f"{len(critical_issues)} critical, {len(high_issues)} high"
                )
            else:
                self.logger.info(f"Package {package_file.name} maintainer scripts appear safe")

            return ScriptAnalysisResult(
                safe=safe,
                scripts_analyzed=scripts_analyzed,
                issues_found=all_issues,
                warnings=all_warnings,
                analysis_date=datetime.now().isoformat(),
            )

        except Exception as e:
            self.logger.exception(f"Script analysis failed for {package_file.name}")
            return ScriptAnalysisResult(
                safe=False,
                scripts_analyzed=[],
                issues_found=[],
                warnings=[],
                analysis_date=datetime.now().isoformat(),
                error_message=str(e),
            )

    def _extract_maintainer_scripts(self, package_path: str) -> Dict[str, str]:
        """Extract maintainer scripts from package.

        Args:
            package_path: Path to .deb package

        Returns:
            Dictionary of script_name -> script_content

        Raises:
            RuntimeError: If extraction fails (enforces default-deny)
        """
        scripts = {}
        script_names = ["preinst", "postinst", "prerm", "postrm", "config"]

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract control.tar.* from .deb
                subprocess.run(
                    ["dpkg-deb", "-e", package_path, temp_dir],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )

                # Read each script if it exists
                for script_name in script_names:
                    script_path = Path(temp_dir) / script_name
                    if script_path.exists():
                        with script_path.open("r", encoding="utf-8", errors="ignore") as f:
                            scripts[script_name] = f.read()

        except subprocess.CalledProcessError as e:
            self.logger.exception("Failed to extract maintainer scripts")
            # Re-raise to enforce default-deny: extraction failure = unsafe
            raise RuntimeError(f"Maintainer script extraction failed: {e.stderr.decode() if e.stderr else str(e)}") from e
        except subprocess.TimeoutExpired as e:
            self.logger.exception("Script extraction timed out")
            # Re-raise to enforce default-deny: timeout = unsafe
            raise RuntimeError("Maintainer script extraction timed out") from e
        except Exception as e:
            self.logger.exception("Error extracting scripts")
            # Re-raise to enforce default-deny: any failure = unsafe
            raise RuntimeError(f"Maintainer script extraction error: {str(e)}") from e

        return scripts

    def _analyze_script(self, script_name: str, script_content: str) -> Tuple[List[ScriptIssue], List[str]]:
        """Analyze a single maintainer script for security issues.

        Args:
            script_name: Name of the script
            script_content: Content of the script

        Returns:
            Tuple of (issues, warnings)
        """
        issues = []
        warnings = []

        lines = script_content.splitlines()

        # Check for shebang
        if lines and not lines[0].startswith("#!"):
            warnings.append(f"{script_name}: Missing shebang")

        # Check each line
        for line_num, line in enumerate(lines, start=1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for dangerous commands (using regex patterns)
            for pattern, (severity, description) in self.DANGEROUS_COMMANDS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        ScriptIssue(
                            severity=severity,
                            issue_type="dangerous_command",
                            description=description,
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                        )
                    )

            # Check for suspicious patterns
            for pattern, (severity, description) in self.SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        ScriptIssue(
                            severity=severity,
                            issue_type="suspicious_pattern",
                            description=description,
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                        )
                    )

            # Check for network patterns
            for pattern, (severity, description) in self.NETWORK_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    if severity in ["medium", "high", "critical"]:
                        issues.append(
                            ScriptIssue(
                                severity=severity,
                                issue_type="network_activity",
                                description=description,
                                line_number=line_num,
                                code_snippet=line.strip()[:100],
                            )
                        )
                    else:
                        warnings.append(f"{script_name}:{line_num}: {description}")

            # Check for injection patterns
            for pattern, (severity, description) in self.INJECTION_PATTERNS.items():
                if re.search(pattern, line):
                    if severity in ["high", "critical"]:
                        issues.append(
                            ScriptIssue(
                                severity=severity,
                                issue_type="code_injection",
                                description=description,
                                line_number=line_num,
                                code_snippet=line.strip()[:100],
                            )
                        )

        # Check for environment variable misuse
        env_issues = self._check_environment_variables(script_content)
        issues.extend(env_issues)

        # Check for insecure temp file usage
        temp_issues = self._check_temp_file_usage(script_content)
        issues.extend(temp_issues)

        return issues, warnings

    def _check_environment_variables(self, script_content: str) -> List[ScriptIssue]:
        """Check for insecure environment variable usage.

        Args:
            script_content: Script content to analyze

        Returns:
            List of issues found
        """
        issues = []

        # Check for PATH manipulation
        if re.search(r"PATH\s*=\s*[^:]", script_content):
            issues.append(
                ScriptIssue(
                    severity="medium",
                    issue_type="environment_manipulation",
                    description="PATH variable manipulation detected",
                )
            )

        # Check for LD_PRELOAD usage
        if "LD_PRELOAD" in script_content:
            issues.append(
                ScriptIssue(
                    severity="high",
                    issue_type="library_injection",
                    description="LD_PRELOAD usage (library injection risk)",
                )
            )

        # Check for LD_LIBRARY_PATH manipulation
        if "LD_LIBRARY_PATH" in script_content:
            issues.append(
                ScriptIssue(
                    severity="medium",
                    issue_type="library_path_manipulation",
                    description="LD_LIBRARY_PATH manipulation detected",
                )
            )

        return issues

    def _check_temp_file_usage(self, script_content: str) -> List[ScriptIssue]:
        """Check for insecure temporary file usage.

        Args:
            script_content: Script content to analyze

        Returns:
            List of issues found
        """
        issues = []

        # Check for predictable temp file names
        if re.search(r"/tmp/[a-zA-Z0-9_-]+\s*$", script_content, re.MULTILINE):
            issues.append(
                ScriptIssue(
                    severity="low",
                    issue_type="insecure_temp_file",
                    description="Predictable temp file name (use mktemp)",
                )
            )

        # Check for insecure temp directory creation
        if re.search(r"mkdir\s+/tmp/", script_content):
            issues.append(
                ScriptIssue(
                    severity="low",
                    issue_type="insecure_temp_dir",
                    description="Insecure temp directory creation",
                )
            )

        return issues
