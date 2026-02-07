"""Scanner integration service.

Bridges the standalone scanner module with the Enterprise database,
populating packages, scans, and triggering approval workflows.
"""

import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.db.models import Package, Scan, Mirror
from enterprise.db.models.approval import ApprovalRequest, ApprovalHistory
from enterprise.core.approval.service import ApprovalService
from enterprise.core.approval.states import (
    ApprovalState,
    ApprovalTransition,
    APPROVED_STATES,
    BLOCKED_STATES,
)
from enterprise.core.policy.engine import PolicyEngine, PolicyDecision

# Import the scanner module
from src.scanner.scan_packages import PackageScanner, ScanResult, ScanStatus
from src.formats.registry import detect_format


class ScannerIntegrationService:
    """
    Service to integrate package scanner with Enterprise database.
    
    Handles:
    - Creating Package records from scanned files
    - Creating and updating Scan records with results
    - Triggering approval workflows based on policy evaluation
    - Supporting all package formats (DEB, RPM, APK, PyPI, NPM)
    """
    
    # Map package file extensions to package types
    EXTENSION_TYPE_MAP = {
        '.deb': 'deb',
        '.rpm': 'rpm',
        '.apk': 'apk',
        '.whl': 'pypi',
        '.tar.gz': 'pypi',  # sdist
        '.tgz': 'npm',
    }
    
    def __init__(
        self,
        db: Session,
        org_id: UUID,
        user_id: UUID,
        scanner_type: str = "trivy",
    ):
        """
        Initialize the scanner integration service.
        
        Args:
            db: Database session
            org_id: Organization ID
            user_id: User ID performing the scan
            scanner_type: Vulnerability scanner to use (trivy, grype, pip-audit, npm-audit)
        """
        self.db = db
        self.org_id = org_id
        self.user_id = user_id
        self.scanner_type = scanner_type
        
        # Initialize sub-services
        self.approval_service = ApprovalService(db, org_id)
        self.policy_engine = PolicyEngine(db)
    
    def scan_and_ingest_package(
        self,
        package_path: str,
        *,
        mirror_id: Optional[UUID] = None,
        policy_id: Optional[UUID] = None,
        auto_approve: bool = True,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Scan a package file and ingest results into the database.
        
        This is the main entry point for processing a package:
        1. Detect package format and extract metadata
        2. Create or update Package record
        3. Run vulnerability scan
        4. Create Scan record with results
        5. Evaluate against policy
        6. Create ApprovalRequest and trigger workflow
        
        Args:
            package_path: Path to the package file
            mirror_id: Optional mirror this package belongs to
            policy_id: Optional specific policy to evaluate against
            auto_approve: Whether to auto-approve if policy passes
            extra_metadata: Additional metadata to store
            
        Returns:
            Dictionary with package, scan, and approval details
        """
        package_file = Path(package_path)
        
        if not package_file.exists():
            raise FileNotFoundError(f"Package file not found: {package_path}")
        
        # 1. Detect format and extract metadata
        format_handler = detect_format(package_file)
        if not format_handler:
            # Fall back to extension-based detection
            package_type = self._detect_type_from_extension(package_file)
        else:
            package_type = format_handler.format_name
        
        # Get or create Package record
        package_record = self._create_or_update_package(
            package_file=package_file,
            package_type=package_type,
            format_handler=format_handler,
            mirror_id=mirror_id,
            extra_metadata=extra_metadata,
        )
        
        # 2. Create scan record (pending)
        scan_record = self._create_scan_record(
            package=package_record,
            policy_id=policy_id,
        )
        
        # 3. Run the actual scan
        try:
            scan_result = self._run_scan(
                package_path=package_path,
                package_type=package_type,
                format_handler=format_handler,
            )
            
            # 4. Update scan with results
            self._update_scan_with_results(scan_record, scan_result)
            
            # 5. Update package with scan summary
            self._update_package_scan_summary(package_record, scan_record, scan_result)
            
        except Exception as e:
            # Mark scan as failed
            scan_record.status = "failed"
            scan_record.completed_at = datetime.utcnow()
            scan_record.results = {"error": str(e)}
            self.db.commit()
            
            raise RuntimeError(f"Scan failed: {e}") from e
        
        # 6. Evaluate policy and create approval request
        approval_result = self._evaluate_and_create_approval(
            package=package_record,
            scan=scan_record,
            scan_result=scan_result,
            mirror_id=mirror_id,
            policy_id=policy_id,
            auto_approve=auto_approve,
        )
        
        self.db.commit()
        
        return {
            "package": {
                "id": str(package_record.id),
                "name": package_record.name,
                "version": package_record.version,
                "package_type": package_record.package_type,
                "approval_status": package_record.approval_status,
            },
            "scan": {
                "id": str(scan_record.id),
                "status": scan_record.status,
                "cve_count": len(scan_result.vulnerabilities) if scan_result else 0,
                "max_cvss": scan_result.cvss_max if scan_result else 0,
            },
            "approval": approval_result,
        }
    
    def scan_directory(
        self,
        directory_path: str,
        *,
        mirror_id: Optional[UUID] = None,
        policy_id: Optional[UUID] = None,
        auto_approve: bool = True,
        package_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Scan all packages in a directory.
        
        Args:
            directory_path: Path to directory containing packages
            mirror_id: Optional mirror these packages belong to
            policy_id: Optional policy to evaluate against
            auto_approve: Whether to auto-approve passing packages
            package_types: Optional filter for package types
            
        Returns:
            Summary of scan results
        """
        directory = Path(directory_path)
        if not directory.is_dir():
            raise ValueError(f"Not a directory: {directory_path}")
        
        results = {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "auto_approved": 0,
            "pending_review": 0,
            "rejected": 0,
            "packages": [],
            "errors": [],
        }
        
        # Find all package files
        extensions = set(self.EXTENSION_TYPE_MAP.keys())
        
        for package_file in directory.rglob("*"):
            if not package_file.is_file():
                continue
            
            # Check extension
            suffix = package_file.suffix.lower()
            if suffix == '.gz' and package_file.name.endswith('.tar.gz'):
                suffix = '.tar.gz'
            
            if suffix not in extensions:
                continue
            
            # Check type filter
            if package_types:
                pkg_type = self.EXTENSION_TYPE_MAP.get(suffix)
                if pkg_type not in package_types:
                    continue
            
            results["total"] += 1
            
            try:
                result = self.scan_and_ingest_package(
                    str(package_file),
                    mirror_id=mirror_id,
                    policy_id=policy_id,
                    auto_approve=auto_approve,
                )
                
                results["successful"] += 1
                results["packages"].append(result)
                
                # Count by approval state
                approval_state = result["approval"].get("state", "pending")
                if approval_state in ("approved", "auto_approved"):
                    results["auto_approved"] += 1
                elif approval_state in ("rejected", "blocked"):
                    results["rejected"] += 1
                else:
                    results["pending_review"] += 1
                    
            except Exception as e:
                results["failed"] += 1
                results["errors"].append({
                    "file": str(package_file),
                    "error": str(e),
                })
        
        return results
    
    def rescan_package(
        self,
        package_id: UUID,
        *,
        policy_id: Optional[UUID] = None,
    ) -> Dict[str, Any]:
        """
        Re-scan an existing package.
        
        Useful when:
        - Vulnerability database has been updated
        - Policy has changed
        - Initial scan failed
        
        Args:
            package_id: ID of the package to re-scan
            policy_id: Optional new policy to evaluate against
            
        Returns:
            Updated scan results
        """
        package = self.db.query(Package).filter(
            and_(
                Package.id == package_id,
                Package.org_id == self.org_id,
            )
        ).first()
        
        if not package:
            raise ValueError(f"Package {package_id} not found")
        
        if not package.filename:
            raise ValueError(f"Package {package_id} has no file path stored")
        
        return self.scan_and_ingest_package(
            package.filename,
            mirror_id=package.mirror_id,
            policy_id=policy_id,
        )
    
    def _detect_type_from_extension(self, package_file: Path) -> str:
        """Detect package type from file extension."""
        suffix = package_file.suffix.lower()
        
        # Handle .tar.gz
        if suffix == '.gz' and package_file.name.endswith('.tar.gz'):
            suffix = '.tar.gz'
        
        return self.EXTENSION_TYPE_MAP.get(suffix, 'unknown')
    
    def _create_or_update_package(
        self,
        package_file: Path,
        package_type: str,
        format_handler,
        mirror_id: Optional[UUID],
        extra_metadata: Optional[Dict[str, Any]],
    ) -> Package:
        """Create or update a Package record."""
        # Try to extract metadata
        metadata = {}
        if format_handler:
            try:
                parsed = format_handler.parse_metadata(package_file)
                metadata = {
                    "name": parsed.name,
                    "version": parsed.version,
                    "architecture": getattr(parsed, 'architecture', None),
                    "maintainer": getattr(parsed, 'maintainer', None),
                    "description": getattr(parsed, 'description', None),
                    "homepage": getattr(parsed, 'homepage', None),
                    "license": getattr(parsed, 'license', None),
                    "dependencies": getattr(parsed, 'dependencies', None),
                }
            except Exception:
                pass
        
        # Fall back to filename parsing for .deb
        if not metadata.get('name'):
            name, version = self._parse_package_filename(package_file.name, package_type)
            metadata['name'] = name
            metadata['version'] = version
        
        # Check for existing package
        existing = self.db.query(Package).filter(
            and_(
                Package.org_id == self.org_id,
                Package.name == metadata['name'],
                Package.version == metadata['version'],
                Package.package_type == package_type,
            )
        ).first()
        
        if existing:
            # Update existing record
            existing.filename = str(package_file)
            existing.file_size = package_file.stat().st_size
            existing.updated_at = datetime.utcnow()
            if extra_metadata:
                existing.extra_data = {**existing.extra_data, **extra_metadata}
            return existing
        
        # Create new package
        package = Package(
            id=uuid.uuid4(),
            org_id=self.org_id,
            mirror_id=mirror_id,
            name=metadata['name'],
            version=metadata['version'],
            package_type=package_type,
            architecture=metadata.get('architecture'),
            maintainer=metadata.get('maintainer'),
            description=metadata.get('description'),
            homepage=metadata.get('homepage'),
            license=metadata.get('license'),
            filename=str(package_file),
            file_size=package_file.stat().st_size,
            dependencies=metadata.get('dependencies'),
            extra_data=extra_metadata or {},
        )
        self.db.add(package)
        self.db.flush()
        
        return package
    
    def _parse_package_filename(self, filename: str, package_type: str) -> tuple:
        """Parse package name and version from filename."""
        if package_type == 'deb':
            # Format: name_version_arch.deb
            parts = filename.replace('.deb', '').split('_')
            if len(parts) >= 2:
                return parts[0], parts[1]
        elif package_type == 'rpm':
            # Format: name-version-release.arch.rpm
            base = filename.replace('.rpm', '')
            parts = base.rsplit('.', 1)  # Remove arch
            if parts:
                name_ver = parts[0].rsplit('-', 2)
                if len(name_ver) >= 2:
                    return name_ver[0], '-'.join(name_ver[1:])
        elif package_type == 'pypi':
            # Format: name-version-py3-none-any.whl or name-version.tar.gz
            base = filename.replace('.whl', '').replace('.tar.gz', '')
            parts = base.split('-')
            if len(parts) >= 2:
                return parts[0], parts[1]
        elif package_type == 'npm':
            # Format: name-version.tgz
            base = filename.replace('.tgz', '')
            parts = base.rsplit('-', 1)
            if len(parts) >= 2:
                return parts[0], parts[1]
        
        return filename, 'unknown'
    
    def _create_scan_record(
        self,
        package: Package,
        policy_id: Optional[UUID],
    ) -> Scan:
        """Create a new Scan record."""
        scan = Scan(
            id=uuid.uuid4(),
            org_id=self.org_id,
            user_id=self.user_id,
            policy_id=policy_id,
            package_name=package.name,
            package_version=package.version,
            package_type=package.package_type,
            status="running",
            started_at=datetime.utcnow(),
        )
        self.db.add(scan)
        self.db.flush()
        return scan
    
    def _run_scan(
        self,
        package_path: str,
        package_type: str,
        format_handler,
    ) -> ScanResult:
        """Run the actual vulnerability scan."""
        # Select appropriate scanner
        if package_type == 'pypi':
            scanner = PackageScanner(
                scanner_type='pip-audit',
                format_handler=format_handler,
            )
        elif package_type == 'npm':
            scanner = PackageScanner(
                scanner_type='npm-audit',
                format_handler=format_handler,
            )
        else:
            scanner = PackageScanner(
                scanner_type=self.scanner_type,
                format_handler=format_handler,
            )
        
        return scanner.scan_package(package_path)
    
    def _update_scan_with_results(self, scan: Scan, result: ScanResult) -> None:
        """Update Scan record with results."""
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.results = {
            "scanner_type": result.scanner_type,
            "status": result.status.value,
            "cve_count": result.cve_count,
            "cvss_max": result.cvss_max,
            "vulnerabilities": result.vulnerabilities,
            "error_message": result.error_message,
        }
    
    def _update_package_scan_summary(
        self,
        package: Package,
        scan: Scan,
        result: ScanResult,
    ) -> None:
        """Update package with latest scan summary."""
        package.last_scan_id = scan.id
        package.last_scan_at = scan.completed_at
        
        if result.status == ScanStatus.APPROVED:
            package.scan_status = "passed"
        elif result.status == ScanStatus.BLOCKED:
            package.scan_status = "failed"
        else:
            package.scan_status = "warning"
        
        # Store vulnerability summary
        package.vulnerabilities = {
            "cve_count": result.cve_count,
            "cvss_max": result.cvss_max,
            "by_severity": self._count_by_severity(result.vulnerabilities),
        }
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            severity = v.get("severity", "").lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _evaluate_and_create_approval(
        self,
        package: Package,
        scan: Scan,
        scan_result: ScanResult,
        mirror_id: Optional[UUID],
        policy_id: Optional[UUID],
        auto_approve: bool,
    ) -> Dict[str, Any]:
        """Evaluate policy and create/update approval request."""
        # Build context for policy evaluation
        scan_results = {
            "vulnerabilities": scan_result.vulnerabilities,
            "cve_count": scan_result.cve_count,
            "cvss_max": scan_result.cvss_max,
            "status": scan_result.status.value,
        }
        
        package_metadata = {
            "name": package.name,
            "version": package.version,
            "package_type": package.package_type,
            "license": package.license,
            "maintainer": package.maintainer,
        }
        
        # Evaluate policy
        policy_result = self.policy_engine.evaluate(
            scan_results=scan_results,
            package_metadata=package_metadata,
            policy_id=policy_id,
            mirror_id=mirror_id,
            org_id=self.org_id,
        )
        
        # Create approval request with "scanned" state (completed scan)
        approval_request = self._create_approval_request(
            package=package,
            scan=scan,
            mirror_id=mirror_id,
            policy_result=policy_result,
        )
        
        # Transition based on policy decision
        if auto_approve and policy_result.decision == PolicyDecision.APPROVE:
            # Auto-approve: scanned -> auto_approved
            self._transition_to_state(
                approval_request,
                ApprovalTransition.AUTO_APPROVE,
                ApprovalState.AUTO_APPROVED,
                comment=f"Auto-approved by policy: {policy_result.policy_name}",
            )
            package.approval_status = "approved"
            package.approved_at = datetime.utcnow()
            package.approved_by = self.user_id
            
            return {
                "id": str(approval_request.id),
                "state": "auto_approved",
                "decision": "auto_approved",
                "policy": policy_result.to_dict(),
            }
        
        elif policy_result.decision == PolicyDecision.REJECT:
            # Auto-reject: scanned -> needs_review -> rejected
            # First transition to needs_review
            self._transition_to_state(
                approval_request,
                ApprovalTransition.REQUIRE_REVIEW,
                ApprovalState.NEEDS_REVIEW,
            )
            # Then reject
            reasons = [r.reason for r in policy_result.failed_rules if r.reason]
            self._transition_to_state(
                approval_request,
                ApprovalTransition.REJECT,
                ApprovalState.REJECTED,
                comment=f"Auto-rejected by policy: {'; '.join(reasons)}",
            )
            approval_request.rejected_at = datetime.utcnow()
            approval_request.rejected_by = self.user_id
            package.approval_status = "rejected"
            
            return {
                "id": str(approval_request.id),
                "state": "rejected",
                "decision": "auto_rejected",
                "policy": policy_result.to_dict(),
            }
        
        else:
            # Needs manual review: scanned -> needs_review
            self._transition_to_state(
                approval_request,
                ApprovalTransition.REQUIRE_REVIEW,
                ApprovalState.NEEDS_REVIEW,
            )
            package.approval_status = "pending"
            
            return {
                "id": str(approval_request.id),
                "state": "needs_review",
                "decision": "needs_review",
                "policy": policy_result.to_dict(),
            }
    
    def _create_approval_request(
        self,
        package: Package,
        scan: Scan,
        mirror_id: Optional[UUID],
        policy_result,
    ) -> ApprovalRequest:
        """Create a new approval request in scanned state."""
        # Check for existing approval request
        existing = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.package_id == package.id,
            )
        ).first()
        
        if existing:
            # Update existing request
            existing.scan_id = scan.id
            existing.state = ApprovalState.SCANNED.value
            existing.updated_at = datetime.utcnow()
            existing.extra_data = {"policy_result": policy_result.to_dict()}
            return existing
        
        # Create new request
        request = ApprovalRequest(
            id=uuid.uuid4(),
            org_id=self.org_id,
            package_id=package.id,
            package_name=package.name,
            package_version=package.version,
            package_type=package.package_type,
            mirror_id=mirror_id,
            scan_id=scan.id,
            policy_id=policy_result.policy_id if str(policy_result.policy_id) != "00000000-0000-0000-0000-000000000000" else None,
            state=ApprovalState.SCANNED.value,
            requested_by=self.user_id,
            extra_data={"policy_result": policy_result.to_dict()},
        )
        self.db.add(request)
        self.db.flush()
        return request
    
    def _transition_to_state(
        self,
        request: ApprovalRequest,
        transition: ApprovalTransition,
        target_state: ApprovalState,
        comment: Optional[str] = None,
    ) -> None:
        """Record a state transition."""
        old_state = request.state
        request.state = target_state.value
        request.updated_at = datetime.utcnow()
        
        # Record history
        history = ApprovalHistory(
            id=uuid.uuid4(),
            request_id=request.id,
            from_state=old_state,
            to_state=target_state.value,
            transition=transition.value,
            user_id=self.user_id,
            comment=comment,
            extra_data={"auto": True},
        )
        self.db.add(history)
