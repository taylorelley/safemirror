"""Package integrity verification for Debian packages.

This module verifies package integrity through signature validation,
checksum verification, and package format validation.
"""

import hashlib
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..common.logger import get_logger


@dataclass
class IntegrityCheckResult:
    """Result of package integrity checks."""

    valid: bool
    checks_passed: List[str]
    checks_failed: List[str]
    warnings: List[str]
    check_date: str
    package_format_valid: bool
    signature_valid: Optional[bool] = None
    checksum_valid: Optional[bool] = None
    control_file_valid: bool = True
    error_message: Optional[str] = None


class IntegrityChecker:
    """Package integrity verification for .deb files."""

    def __init__(self):
        """Initialize integrity checker."""
        self.logger = get_logger("integrity_checker")

    def check_package(
        self, package_path: str, expected_checksum: Optional[str] = None
    ) -> IntegrityCheckResult:
        """Perform comprehensive integrity checks on a package.

        Args:
            package_path: Path to .deb package file
            expected_checksum: Optional expected SHA256 checksum

        Returns:
            IntegrityCheckResult with validation results
        """
        package_file = Path(package_path)

        if not package_file.exists():
            self.logger.error(f"Package file not found: {package_path}")
            return IntegrityCheckResult(
                valid=False,
                checks_passed=[],
                checks_failed=["package_exists"],
                warnings=[],
                check_date=datetime.now().isoformat(),
                package_format_valid=False,
                error_message=f"Package file not found: {package_path}",
            )

        self.logger.info(f"Checking integrity of package: {package_file.name}")

        checks_passed = []
        checks_failed = []
        warnings = []

        # Check 1: Package format validation
        format_valid = self._check_package_format(package_path)
        if format_valid:
            checks_passed.append("package_format")
        else:
            checks_failed.append("package_format")

        # Check 2: Control file validation
        control_valid = self._check_control_file(package_path)
        if control_valid:
            checks_passed.append("control_file")
        else:
            checks_failed.append("control_file")
            warnings.append("Control file validation failed - package may be corrupted")

        # Check 3: Checksum verification
        checksum_valid = None
        if expected_checksum:
            checksum_valid = self._verify_checksum(package_path, expected_checksum)
            if checksum_valid:
                checks_passed.append("checksum")
            else:
                checks_failed.append("checksum")
                warnings.append("Checksum mismatch - package may be tampered")

        # Check 4: Internal consistency
        consistency_valid = self._check_internal_consistency(package_path)
        if consistency_valid:
            checks_passed.append("internal_consistency")
        else:
            checks_failed.append("internal_consistency")
            warnings.append("Package internal structure inconsistent")

        # Check 5: File integrity
        file_integrity_valid = self._check_file_integrity(package_path)
        if file_integrity_valid:
            checks_passed.append("file_integrity")
        else:
            checks_failed.append("file_integrity")

        # Determine overall validity
        valid = len(checks_failed) == 0 and format_valid and control_valid

        if valid:
            self.logger.info(f"Package {package_file.name} passed integrity checks")
        else:
            self.logger.warning(
                f"Package {package_file.name} failed integrity checks: {', '.join(checks_failed)}"
            )

        return IntegrityCheckResult(
            valid=valid,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            warnings=warnings,
            check_date=datetime.now().isoformat(),
            package_format_valid=format_valid,
            checksum_valid=checksum_valid,
            control_file_valid=control_valid,
        )

    def _check_package_format(self, package_path: str) -> bool:
        """Verify package has valid .deb format.

        Args:
            package_path: Path to package file

        Returns:
            True if format is valid
        """
        try:
            # Use dpkg-deb to validate format
            result = subprocess.run(
                ["dpkg-deb", "--info", package_path],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode().strip()
                self.logger.warning(f"Invalid package format: {error_msg}")
                return False

            return True

        except subprocess.TimeoutExpired:
            self.logger.error("Package format check timed out")
            return False
        except Exception as e:
            self.logger.exception(f"Package format check failed: {e}")
            return False

    def _check_control_file(self, package_path: str) -> bool:
        """Verify package control file is valid.

        Args:
            package_path: Path to package file

        Returns:
            True if control file is valid
        """
        try:
            # Extract control file
            result = subprocess.run(
                ["dpkg-deb", "-f", package_path],
                capture_output=True,
                timeout=30,
                check=True,
            )

            control_content = result.stdout.decode()

            # Verify required fields exist
            required_fields = ["Package:", "Version:", "Architecture:"]
            for field in required_fields:
                if field not in control_content:
                    self.logger.warning(f"Missing required field in control: {field}")
                    return False

            return True

        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Control file extraction failed: {e}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Control file check timed out")
            return False
        except Exception as e:
            self.logger.exception(f"Control file check failed: {e}")
            return False

    def _verify_checksum(self, package_path: str, expected_checksum: str) -> bool:
        """Verify package checksum matches expected value.

        Args:
            package_path: Path to package file
            expected_checksum: Expected SHA256 checksum

        Returns:
            True if checksum matches
        """
        try:
            actual_checksum = self.calculate_checksum(package_path)

            if actual_checksum.lower() == expected_checksum.lower():
                self.logger.debug(f"Checksum verified: {actual_checksum}")
                return True
            else:
                self.logger.warning(
                    f"Checksum mismatch - expected: {expected_checksum}, got: {actual_checksum}"
                )
                return False

        except Exception as e:
            self.logger.exception(f"Checksum verification failed: {e}")
            return False

    def _check_internal_consistency(self, package_path: str) -> bool:
        """Check internal consistency of package structure.

        Args:
            package_path: Path to package file

        Returns:
            True if package structure is consistent
        """
        try:
            # List package contents
            result = subprocess.run(
                ["dpkg-deb", "-c", package_path],
                capture_output=True,
                timeout=30,
                check=True,
            )

            contents = result.stdout.decode()

            # Basic sanity checks
            if not contents.strip():
                self.logger.warning("Package appears to be empty")
                return False

            # Check for suspicious patterns
            suspicious_patterns = ["/../", "//", "./.."]
            for pattern in suspicious_patterns:
                if pattern in contents:
                    self.logger.warning(f"Suspicious path pattern found: {pattern}")
                    return False

            return True

        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Internal consistency check failed: {e}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Internal consistency check timed out")
            return False
        except Exception as e:
            self.logger.exception(f"Internal consistency check failed: {e}")
            return False

    def _check_file_integrity(self, package_path: str) -> bool:
        """Check file integrity of package.

        Args:
            package_path: Path to package file

        Returns:
            True if file integrity is valid
        """
        try:
            package_file = Path(package_path)

            # Check file is not empty
            if package_file.stat().st_size == 0:
                self.logger.warning("Package file is empty")
                return False

            # Check file is readable
            with package_file.open("rb") as f:
                # Read first few bytes to verify it's a valid archive
                header = f.read(8)
                # Debian packages are ar archives
                if not header.startswith(b"!<arch>"):
                    self.logger.warning("Invalid package file header")
                    return False

            return True

        except Exception as e:
            self.logger.exception(f"File integrity check failed: {e}")
            return False

    def calculate_checksum(self, package_path: str, algorithm: str = "sha256") -> str:
        """Calculate checksum of package file.

        Args:
            package_path: Path to package file
            algorithm: Hash algorithm (sha256, sha512, md5)

        Returns:
            Hexadecimal checksum string
        """
        try:
            if algorithm == "sha256":
                hasher = hashlib.sha256()
            elif algorithm == "sha512":
                hasher = hashlib.sha512()
            elif algorithm == "md5":
                hasher = hashlib.md5()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            with open(package_path, "rb") as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)

            return hasher.hexdigest()

        except Exception as e:
            self.logger.exception(f"Checksum calculation failed: {e}")
            raise

    def verify_gpg_signature(self, package_path: str, keyring: Optional[str] = None) -> bool:
        """Verify GPG signature of package (if available).

        Args:
            package_path: Path to package file
            keyring: Optional path to GPG keyring

        Returns:
            True if signature is valid, False otherwise
        """
        # Note: .deb files themselves are not typically signed
        # This would be used for verifying Release files in the repository
        try:
            signature_path = f"{package_path}.asc"
            if not Path(signature_path).exists():
                self.logger.debug("No signature file found for package")
                return True  # No signature is not a failure

            cmd = ["gpg", "--verify", signature_path, package_path]
            if keyring:
                cmd.extend(["--keyring", keyring])

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("GPG signature verified successfully")
                return True
            else:
                self.logger.warning(f"GPG signature verification failed: {result.stderr.decode()}")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("GPG verification timed out")
            return False
        except Exception as e:
            self.logger.exception(f"GPG verification failed: {e}")
            return False
