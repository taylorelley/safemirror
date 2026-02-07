"""Integration tests for the complete package approval workflow.

Tests end-to-end flows:
1. Upload package → scan → policy evaluation → approval
2. Auto-approval path (passes all policies)
3. Manual review path (requires approval)
4. Rejection with reason
5. Revocation workflow

These tests require a running PostgreSQL database and mock the scanner
to avoid needing actual package files.
"""

import pytest
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock
from pathlib import Path

from sqlalchemy.orm import Session

from enterprise.db.models import (
    Organization, User, Role, Policy, Scan, 
    Package, Mirror, ApprovalRequest, ApprovalHistory,
)
from enterprise.core.approval.states import ApprovalState, ApprovalTransition
from enterprise.core.approval.service import ApprovalService
from enterprise.core.policy.engine import PolicyEngine, PolicyDecision
from enterprise.services.scanner_integration import ScannerIntegrationService

from tests.factories import (
    create_organization,
    create_user,
    create_role,
    create_policy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def test_org(db_session):
    """Create a test organization."""
    return create_organization(db_session, name="IntegrationTest Corp", slug="integration-test")


@pytest.fixture()
def admin_role(db_session, test_org):
    """Create an admin role with full permissions."""
    return create_role(
        db_session,
        org=test_org,
        name="admin",
        permissions=[
            "packages:*",
            "scans:*", 
            "approvals:*",
            "policies:*",
            "mirrors:*",
        ],
    )


@pytest.fixture()
def test_user(db_session, test_org, admin_role):
    """Create a test admin user."""
    return create_user(db_session, org=test_org, role=admin_role, name="Test Admin")


@pytest.fixture()
def strict_policy(db_session, test_org):
    """Create a strict security policy (blocks anything with high+ vulns)."""
    return create_policy(
        db_session,
        org=test_org,
        name="Strict Security",
        rules={
            "max_severity": "medium",
            "max_cvss": 6.9,
            "max_cve_count": 10,
            "auto_approve": False,
        },
    )


@pytest.fixture()
def permissive_policy(db_session, test_org):
    """Create a permissive policy with auto-approve."""
    return create_policy(
        db_session,
        org=test_org,
        name="Permissive",
        rules={
            "max_severity": "critical",
            "max_cvss": 10.0,
            "auto_approve": True,
        },
    )


@pytest.fixture()
def test_mirror(db_session, test_org, strict_policy):
    """Create a test mirror."""
    mirror = Mirror(
        id=uuid.uuid4(),
        org_id=test_org.id,
        name="Test APT Mirror",
        slug="test-apt",
        mirror_type="apt",
        upstream_url="https://archive.ubuntu.com/ubuntu",
        policy_id=strict_policy.id,
        auto_approve=False,
    )
    db_session.add(mirror)
    db_session.flush()
    return mirror


@pytest.fixture()
def mock_scanner():
    """Mock the PackageScanner to avoid needing real files."""
    with patch("enterprise.services.scanner_integration.PackageScanner") as mock:
        yield mock


@pytest.fixture()
def mock_format_registry():
    """Mock the format detection."""
    with patch("enterprise.services.scanner_integration.detect_format") as mock:
        mock.return_value = None  # Use extension-based detection
        yield mock


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def create_mock_scan_result(
    status="approved",
    vulnerabilities=None,
    cve_count=0,
    cvss_max=0.0,
):
    """Create a mock ScanResult object."""
    from src.scanner.scan_packages import ScanResult, ScanStatus
    
    status_enum = ScanStatus.APPROVED if status == "approved" else ScanStatus.BLOCKED
    
    return ScanResult(
        package_name="test-package",
        package_version="1.0.0",
        status=status_enum,
        scan_date=datetime.utcnow().isoformat(),
        scanner_type="trivy",
        vulnerabilities=vulnerabilities or [],
        cvss_max=cvss_max,
        cve_count=cve_count,
    )


def create_test_package_file(tmp_path: Path, name: str = "test-pkg_1.0.0_amd64.deb"):
    """Create a minimal test package file."""
    pkg_file = tmp_path / name
    pkg_file.write_bytes(b"FAKE DEB CONTENT")
    return pkg_file


# ---------------------------------------------------------------------------
# Test: Complete flow - Package upload → Scan → Policy → Approval
# ---------------------------------------------------------------------------

class TestCompleteApprovalFlow:
    """Test the complete package approval workflow."""

    def test_flow_scan_to_manual_review(
        self, db_session, test_org, test_user, test_mirror, strict_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: package scan leads to manual review when policy not fully passed."""
        # Setup mock scanner to return no vulnerabilities but policy requires review
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result(
            status="approved",
            vulnerabilities=[],
            cve_count=0,
            cvss_max=0.0,
        )
        mock_scanner.return_value = mock_instance
        
        # Create test package file
        pkg_file = create_test_package_file(tmp_path)
        
        # Run the scanner integration
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=str(pkg_file),
            mirror_id=test_mirror.id,
            policy_id=strict_policy.id,
            auto_approve=True,  # Policy doesn't have auto_approve=True
        )
        
        # Verify package was created
        assert result["package"]["name"] == "test-pkg"
        assert result["package"]["version"] == "1.0.0"
        
        # Verify scan completed
        assert result["scan"]["status"] == "completed"
        assert result["scan"]["cve_count"] == 0
        
        # Verify approval request is in needs_review (strict policy doesn't auto-approve)
        assert result["approval"]["state"] == "needs_review"
        
        # Verify database records
        package = db_session.query(Package).filter(
            Package.org_id == test_org.id,
            Package.name == "test-pkg",
        ).first()
        assert package is not None
        assert package.approval_status == "pending"
        
        approval = db_session.query(ApprovalRequest).filter(
            ApprovalRequest.package_id == package.id,
        ).first()
        assert approval is not None
        assert approval.state == "needs_review"

    def test_flow_auto_approval_path(
        self, db_session, test_org, test_user, permissive_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: package passes policy and gets auto-approved."""
        # Setup mock scanner to return clean result
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result(
            status="approved",
            vulnerabilities=[],
            cve_count=0,
            cvss_max=0.0,
        )
        mock_scanner.return_value = mock_instance
        
        # Create test package file
        pkg_file = create_test_package_file(tmp_path, "clean-pkg_2.0.0_amd64.deb")
        
        # Run scanner integration with permissive policy
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=str(pkg_file),
            policy_id=permissive_policy.id,
            auto_approve=True,
        )
        
        # Verify auto-approval
        assert result["approval"]["state"] == "auto_approved"
        assert result["approval"]["decision"] == "auto_approved"
        
        # Verify package status
        package = db_session.query(Package).filter(
            Package.name == "clean-pkg",
        ).first()
        assert package is not None
        assert package.approval_status == "approved"
        assert package.approved_at is not None

    def test_flow_auto_rejection_path(
        self, db_session, test_org, test_user, strict_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: package fails policy and gets auto-rejected."""
        # Setup mock scanner to return critical vulnerabilities
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result(
            status="blocked",
            vulnerabilities=[
                {"cve_id": "CVE-2024-0001", "severity": "CRITICAL", "cvss_score": 9.8},
                {"cve_id": "CVE-2024-0002", "severity": "HIGH", "cvss_score": 8.5},
            ],
            cve_count=2,
            cvss_max=9.8,
        )
        mock_scanner.return_value = mock_instance
        
        # Create test package file
        pkg_file = create_test_package_file(tmp_path, "vuln-pkg_1.0.0_amd64.deb")
        
        # Run scanner integration with strict policy
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=str(pkg_file),
            policy_id=strict_policy.id,
            auto_approve=True,
        )
        
        # Verify auto-rejection
        assert result["approval"]["state"] == "rejected"
        assert result["approval"]["decision"] == "auto_rejected"
        
        # Verify package status
        package = db_session.query(Package).filter(
            Package.name == "vuln-pkg",
        ).first()
        assert package is not None
        assert package.approval_status == "rejected"


class TestManualReviewWorkflow:
    """Test manual review approve/reject workflows."""

    def test_manual_approval_after_review(
        self, db_session, test_org, test_user, strict_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: package in needs_review gets manually approved."""
        # Setup: create package in needs_review state
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result()
        mock_scanner.return_value = mock_instance
        
        pkg_file = create_test_package_file(tmp_path, "review-pkg_1.0.0_amd64.deb")
        
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=str(pkg_file),
            policy_id=strict_policy.id,
            auto_approve=True,
        )
        
        approval_id = result["approval"]["id"]
        
        # Now manually approve
        approval_service = ApprovalService(db_session, test_org.id)
        
        updated = approval_service.transition(
            request_id=uuid.UUID(approval_id),
            transition=ApprovalTransition.APPROVE,
            user_id=test_user.id,
            user_permissions=["approvals:approve"],
            comment="Reviewed and approved by security team",
        )
        
        # Verify approval
        assert updated["state"] == "approved"
        
        # Verify history recorded
        history = db_session.query(ApprovalHistory).filter(
            ApprovalHistory.request_id == uuid.UUID(approval_id),
            ApprovalHistory.to_state == "approved",
        ).first()
        assert history is not None
        assert history.comment == "Reviewed and approved by security team"

    def test_manual_rejection_with_reason(
        self, db_session, test_org, test_user, strict_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: package in needs_review gets manually rejected with reason."""
        # Setup: create package in needs_review state
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result()
        mock_scanner.return_value = mock_instance
        
        pkg_file = create_test_package_file(tmp_path, "reject-pkg_1.0.0_amd64.deb")
        
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=str(pkg_file),
            policy_id=strict_policy.id,
            auto_approve=True,
        )
        
        approval_id = result["approval"]["id"]
        
        # Manually reject with reason
        approval_service = ApprovalService(db_session, test_org.id)
        
        updated = approval_service.transition(
            request_id=uuid.UUID(approval_id),
            transition=ApprovalTransition.REJECT,
            user_id=test_user.id,
            user_permissions=["approvals:reject"],
            comment="Package contains unmaintained dependencies",
        )
        
        # Verify rejection
        assert updated["state"] == "rejected"
        
        # Verify history
        history = db_session.query(ApprovalHistory).filter(
            ApprovalHistory.request_id == uuid.UUID(approval_id),
            ApprovalHistory.transition == "reject",
        ).first()
        assert history is not None
        assert "unmaintained dependencies" in history.comment


class TestRevocationWorkflow:
    """Test revoking previously approved packages."""

    def test_revoke_approved_package(
        self, db_session, test_org, test_user, permissive_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: approved package can be revoked."""
        # Setup: create auto-approved package
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result()
        mock_scanner.return_value = mock_instance
        
        pkg_file = create_test_package_file(tmp_path, "revoke-pkg_1.0.0_amd64.deb")
        
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=str(pkg_file),
            policy_id=permissive_policy.id,
            auto_approve=True,
        )
        
        assert result["approval"]["state"] == "auto_approved"
        approval_id = result["approval"]["id"]
        
        # Now revoke
        approval_service = ApprovalService(db_session, test_org.id)
        
        revoked = approval_service.transition(
            request_id=uuid.UUID(approval_id),
            transition=ApprovalTransition.REVOKE,
            user_id=test_user.id,
            user_permissions=["approvals:reject"],
            comment="CVE-2024-9999 discovered after approval",
        )
        
        # Verify revocation
        assert revoked["state"] == "revoked"
        
        # Verify history chain
        history_count = db_session.query(ApprovalHistory).filter(
            ApprovalHistory.request_id == uuid.UUID(approval_id),
        ).count()
        assert history_count >= 2  # At least auto_approve and revoke


class TestBatchOperations:
    """Test batch approval/rejection operations."""

    def test_batch_approve_multiple_packages(
        self, db_session, test_org, test_user, strict_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: approve multiple packages at once."""
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result()
        mock_scanner.return_value = mock_instance
        
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        # Create multiple packages
        approval_ids = []
        for i in range(3):
            pkg_file = create_test_package_file(
                tmp_path, f"batch-pkg-{i}_1.0.0_amd64.deb"
            )
            result = service.scan_and_ingest_package(
                package_path=str(pkg_file),
                policy_id=strict_policy.id,
                auto_approve=True,
            )
            approval_ids.append(uuid.UUID(result["approval"]["id"]))
        
        # Batch approve
        approval_service = ApprovalService(db_session, test_org.id)
        result = approval_service.batch_approve(
            request_ids=approval_ids,
            user_id=test_user.id,
            user_permissions=["approvals:approve"],
            comment="Batch approved after security review",
        )
        
        # Verify
        assert len(result["approved"]) == 3
        assert len(result["failed"]) == 0


class TestDirectoryScan:
    """Test scanning entire directories."""

    def test_scan_directory_with_multiple_packages(
        self, db_session, test_org, test_user, permissive_policy,
        mock_scanner, mock_format_registry, tmp_path
    ):
        """Test: scan directory creates packages and approvals for all files."""
        mock_instance = MagicMock()
        mock_instance.scan_package.return_value = create_mock_scan_result()
        mock_scanner.return_value = mock_instance
        
        # Create multiple package files
        for i in range(5):
            create_test_package_file(tmp_path, f"dir-pkg-{i}_1.0.0_amd64.deb")
        
        service = ScannerIntegrationService(
            db=db_session,
            org_id=test_org.id,
            user_id=test_user.id,
        )
        
        result = service.scan_directory(
            directory_path=str(tmp_path),
            policy_id=permissive_policy.id,
            auto_approve=True,
        )
        
        # Verify results
        assert result["total"] == 5
        assert result["successful"] == 5
        assert result["failed"] == 0
        assert result["auto_approved"] == 5
        
        # Verify database
        packages = db_session.query(Package).filter(
            Package.org_id == test_org.id,
            Package.name.like("dir-pkg-%"),
        ).all()
        assert len(packages) == 5
