"""Example tests demonstrating the database fixture usage.

Run with: pytest tests/integration/test_db_fixtures.py -m db
Requires a reachable PostgreSQL instance (see TEST_DATABASE_URL).
"""

import uuid

import pytest

from enterprise.core.security import verify_password
from enterprise.db.models import Organization, Role, User, Policy, Scan, AuditLog


pytestmark = [pytest.mark.db, pytest.mark.integration]


# ---------------------------------------------------------------------------
# Basic CRUD with db_session
# ---------------------------------------------------------------------------


class TestOrganizationCRUD:

    def test_create_organization(self, db_session):
        org = Organization(name="Acme Corp", slug="acme-corp", settings={"plan": "enterprise"})
        db_session.add(org)
        db_session.flush()

        assert org.id is not None
        assert isinstance(org.id, uuid.UUID)
        assert org.name == "Acme Corp"
        assert org.settings == {"plan": "enterprise"}

    def test_query_organization(self, db_session):
        org = Organization(name="Query Test", slug="query-test")
        db_session.add(org)
        db_session.flush()

        result = db_session.query(Organization).filter_by(slug="query-test").one()
        assert result.id == org.id

    def test_session_isolation(self, db_session):
        """Each test gets a clean session — data from other tests is invisible."""
        result = db_session.query(Organization).filter_by(slug="acme-corp").first()
        assert result is None  # rolled back from previous test


# ---------------------------------------------------------------------------
# Factory fixtures
# ---------------------------------------------------------------------------


class TestFactories:

    def test_org_factory_defaults(self, org_factory):
        org = org_factory()
        assert org.id is not None
        assert org.name.startswith("Test Org")
        assert org.slug.startswith("test-org-")

    def test_org_factory_custom(self, org_factory):
        org = org_factory(name="Custom Org", slug="custom")
        assert org.name == "Custom Org"
        assert org.slug == "custom"

    def test_role_factory(self, role_factory, org_factory):
        org = org_factory()
        role = role_factory(org=org, name="admin", permissions=["read", "write", "delete"])
        assert role.org_id == org.id
        assert role.name == "admin"
        assert "delete" in role.permissions

    def test_user_factory(self, user_factory):
        user = user_factory(name="Alice", email="alice@test.com")
        assert user.name == "Alice"
        assert user.email == "alice@test.com"
        assert user.is_active is True
        assert verify_password("testpass123", user.password_hash)

    def test_user_factory_with_org(self, user_factory, org_factory, role_factory):
        org = org_factory(name="Acme")
        role = role_factory(org=org, name="viewer")
        user = user_factory(org=org, role=role)
        assert user.org_id == org.id
        assert user.role_id == role.id

    def test_policy_factory(self, policy_factory, org_factory):
        org = org_factory()
        policy = policy_factory(
            org=org,
            name="Strict Policy",
            rules={"max_severity": "LOW", "block_critical": True},
        )
        assert policy.org_id == org.id
        assert policy.enabled is True

    def test_scan_factory(self, scan_factory, org_factory, user_factory):
        org = org_factory()
        user = user_factory(org=org)
        scan = scan_factory(
            org=org,
            user=user,
            package_type="npm",
            package_name="lodash",
            status="completed",
            results={"vulnerabilities": []},
        )
        assert scan.org_id == org.id
        assert scan.user_id == user.id
        assert scan.package_type == "npm"
        assert scan.status == "completed"

    def test_audit_log_factory(self, audit_log_factory, org_factory, user_factory):
        org = org_factory()
        user = user_factory(org=org)
        log = audit_log_factory(
            org=org,
            user=user,
            action="scan.create",
            resource_type="scan",
            details={"package": "curl"},
        )
        assert log.org_id == org.id
        assert log.action == "scan.create"


# ---------------------------------------------------------------------------
# Relationship traversal
# ---------------------------------------------------------------------------


class TestRelationships:

    def test_user_organization_relationship(self, user_factory, org_factory):
        org = org_factory(name="RelTest Org")
        user = user_factory(org=org)
        assert user.organization.name == "RelTest Org"

    def test_org_has_many_users(self, db_session, org_factory, role_factory, user_factory):
        org = org_factory()
        role = role_factory(org=org)
        user_factory(org=org, role=role, email="a@test.com")
        user_factory(org=org, role=role, email="b@test.com")

        db_session.refresh(org)
        assert len(org.users) == 2

    def test_scan_references(self, scan_factory, org_factory, user_factory, policy_factory):
        org = org_factory()
        user = user_factory(org=org)
        policy = policy_factory(org=org)
        scan = scan_factory(org=org, user=user, policy=policy)

        assert scan.organization.id == org.id
        assert scan.user.id == user.id
        assert scan.policy.id == policy.id


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:

    def test_multiple_orgs_isolation(self, org_factory, user_factory):
        org1 = org_factory(name="Org One")
        org2 = org_factory(name="Org Two")
        user1 = user_factory(org=org1, email="u1@test.com")
        user2 = user_factory(org=org2, email="u2@test.com")

        assert user1.org_id != user2.org_id

    def test_scan_without_policy(self, scan_factory):
        scan = scan_factory(policy=None)
        assert scan.policy_id is None

    def test_audit_log_without_user(self, audit_log_factory, org_factory):
        org = org_factory()
        log = audit_log_factory(org=org, user=None, action="system.startup")
        assert log.user_id is None
