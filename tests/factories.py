"""Factory functions for creating test database records.

Each factory creates a model instance, adds it to the session, and flushes
so that database-generated fields (id, created_at, etc.) are populated.
All fields have sensible defaults but can be overridden via keyword arguments.

Usage::

    from tests.factories import create_organization, create_user

    def test_something(db_session):
        org = create_organization(db_session, name="Acme")
        role = create_role(db_session, org=org)
        user = create_user(db_session, org=org, role=role)
        assert user.organization.name == "Acme"
"""

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from enterprise.db.models import (
    AuditLog,
    Organization,
    Policy,
    Role,
    Scan,
    User,
)


_counter = 0

# Pre-computed bcrypt hash for "testpass123" to avoid passlib/bcrypt issues in tests
TEST_PASSWORD_HASH = "\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.LQ3h9DgKSH6z6e"


def _next_id() -> int:
    """Return a monotonically increasing integer for unique default values."""
    global _counter
    _counter += 1
    return _counter


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------


def create_organization(
    session: Session,
    *,
    name: Optional[str] = None,
    slug: Optional[str] = None,
    settings: Optional[dict] = None,
) -> Organization:
    n = _next_id()
    org = Organization(
        name=name or f"Test Org {n}",
        slug=slug or f"test-org-{n}",
        settings=settings or {},
    )
    session.add(org)
    session.flush()
    return org


# ---------------------------------------------------------------------------
# Role
# ---------------------------------------------------------------------------


def create_role(
    session: Session,
    *,
    org: Optional[Organization] = None,
    name: Optional[str] = None,
    permissions: Optional[list] = None,
    is_system: bool = False,
) -> Role:
    if org is None:
        org = create_organization(session)
    n = _next_id()
    role = Role(
        org_id=org.id,
        name=name or f"role-{n}",
        permissions=permissions or ["read"],
        is_system=is_system,
    )
    session.add(role)
    session.flush()
    return role


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


def create_user(
    session: Session,
    *,
    org: Optional[Organization] = None,
    role: Optional[Role] = None,
    email: Optional[str] = None,
    name: Optional[str] = None,
    password_hash: Optional[str] = None,
    is_active: bool = True,
) -> User:
    if org is None:
        org = create_organization(session)
    if role is None:
        role = create_role(session, org=org)
    n = _next_id()
    user = User(
        org_id=org.id,
        role_id=role.id,
        email=email or f"user-{n}@example.com",
        name=name or f"Test User {n}",
        password_hash=password_hash or TEST_PASSWORD_HASH,
        is_active=is_active,
    )
    session.add(user)
    session.flush()
    return user


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def create_policy(
    session: Session,
    *,
    org: Optional[Organization] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    rules: Optional[dict] = None,
    enabled: bool = True,
) -> Policy:
    if org is None:
        org = create_organization(session)
    n = _next_id()
    policy = Policy(
        org_id=org.id,
        name=name or f"Policy {n}",
        description=description,
        rules=rules or {"max_severity": "HIGH", "block_critical": True},
        enabled=enabled,
    )
    session.add(policy)
    session.flush()
    return policy


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def create_scan(
    session: Session,
    *,
    org: Optional[Organization] = None,
    user: Optional[User] = None,
    policy: Optional[Policy] = None,
    package_type: str = "deb",
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    status: str = "pending",
    results: Optional[dict] = None,
) -> Scan:
    if org is None:
        org = create_organization(session)
    if user is None:
        user = create_user(session, org=org)
    n = _next_id()
    scan = Scan(
        org_id=org.id,
        user_id=user.id,
        policy_id=policy.id if policy else None,
        package_type=package_type,
        package_name=package_name or f"test-package-{n}",
        package_version=package_version or "1.0.0",
        status=status,
        results=results,
    )
    session.add(scan)
    session.flush()
    return scan


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


def create_audit_log(
    session: Session,
    *,
    org: Optional[Organization] = None,
    user: Optional[User] = None,
    action: str = "create",
    resource_type: str = "scan",
    resource_id: Optional[uuid.UUID] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    if org is None:
        org = create_organization(session)
    log = AuditLog(
        org_id=org.id,
        user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    session.add(log)
    session.flush()
    return log


# ---------------------------------------------------------------------------
# Mirror
# ---------------------------------------------------------------------------


def create_mirror(
    session: Session,
    *,
    org: Optional[Organization] = None,
    policy: Optional[Policy] = None,
    name: Optional[str] = None,
    slug: Optional[str] = None,
    mirror_type: str = "apt",
    upstream_url: str = "https://archive.ubuntu.com/ubuntu",
    auto_approve: bool = False,
) -> "Mirror":
    from enterprise.db.models import Mirror
    
    if org is None:
        org = create_organization(session)
    n = _next_id()
    mirror = Mirror(
        org_id=org.id,
        name=name or f"Test Mirror {n}",
        slug=slug or f"test-mirror-{n}",
        mirror_type=mirror_type,
        upstream_url=upstream_url,
        policy_id=policy.id if policy else None,
        auto_approve=auto_approve,
    )
    session.add(mirror)
    session.flush()
    return mirror


# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------


def create_package(
    session: Session,
    *,
    org: Optional[Organization] = None,
    mirror: Optional["Mirror"] = None,
    name: Optional[str] = None,
    version: str = "1.0.0",
    package_type: str = "deb",
    approval_status: str = "pending",
) -> "Package":
    from enterprise.db.models import Package
    
    if org is None:
        org = create_organization(session)
    n = _next_id()
    package = Package(
        org_id=org.id,
        mirror_id=mirror.id if mirror else None,
        name=name or f"test-package-{n}",
        version=version,
        package_type=package_type,
        approval_status=approval_status,
    )
    session.add(package)
    session.flush()
    return package


# ---------------------------------------------------------------------------
# ApprovalRequest
# ---------------------------------------------------------------------------


def create_approval_request(
    session: Session,
    *,
    org: Optional[Organization] = None,
    package: Optional["Package"] = None,
    mirror: Optional["Mirror"] = None,
    scan: Optional[Scan] = None,
    state: str = "pending",
) -> "ApprovalRequest":
    from enterprise.db.models import ApprovalRequest
    
    if org is None:
        org = create_organization(session)
    if package is None:
        package = create_package(session, org=org, mirror=mirror)
    
    request = ApprovalRequest(
        org_id=org.id,
        package_id=package.id,
        package_name=package.name,
        package_version=package.version,
        package_type=package.package_type,
        mirror_id=mirror.id if mirror else None,
        scan_id=scan.id if scan else None,
        state=state,
    )
    session.add(request)
    session.flush()
    return request
