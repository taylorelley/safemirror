"""Test Alembic migrations — upgrade, downgrade, and structural checks.

Requires a live PostgreSQL database. Set DATABASE_URL or the test will use the
default dev connection string. Skip with ``pytest -m 'not integration'`` when
no database is available.
"""

import os
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://safemirror:devpass@localhost:5432/safemirror",
)

ALEMBIC_INI = os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini")

EXPECTED_TABLES = {
    "organizations",
    "roles",
    "users",
    "policies",
    "scans",
    "audit_logs",
}


def _alembic_cfg() -> Config:
    cfg = Config(ALEMBIC_INI)
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    return cfg


def _engine():
    return create_engine(DATABASE_URL)


def _can_connect() -> bool:
    try:
        engine = _engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


skip_no_db = pytest.mark.skipif(
    not _can_connect(),
    reason="PostgreSQL not reachable — skipping migration tests",
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_no_db
@pytest.mark.integration
class TestMigrations:
    """Run upgrade → verify → downgrade → verify cycle."""

    def setup_method(self):
        """Ensure a clean slate before each test by downgrading to base."""
        cfg = _alembic_cfg()
        try:
            command.downgrade(cfg, "base")
        except Exception:
            pass  # May already be at base or tables may not exist

    def teardown_method(self):
        """Leave database at base after each test."""
        cfg = _alembic_cfg()
        try:
            command.downgrade(cfg, "base")
        except Exception:
            pass

    # -- Upgrade tests -------------------------------------------------------

    def test_upgrade_creates_all_tables(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        engine.dispose()

        for table in EXPECTED_TABLES:
            assert table in tables, f"Table {table!r} not created by upgrade"

    def test_upgrade_creates_alembic_version(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        assert "alembic_version" in inspector.get_table_names()
        engine.dispose()

    def test_upgrade_is_idempotent(self):
        """Running upgrade twice should not fail."""
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")
        command.upgrade(cfg, "head")  # should be a no-op

    # -- Column / constraint checks ------------------------------------------

    def test_organizations_columns(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("organizations")}
        engine.dispose()

        assert cols == {"id", "name", "slug", "settings", "created_at", "updated_at"}

    def test_users_columns(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("users")}
        engine.dispose()

        expected = {
            "id", "email", "password_hash", "name", "org_id", "role_id",
            "is_active", "created_at", "updated_at", "last_login",
        }
        assert cols == expected

    def test_scans_columns(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("scans")}
        engine.dispose()

        expected = {
            "id", "org_id", "user_id", "policy_id", "package_type",
            "package_name", "package_version", "status", "results",
            "created_at", "started_at", "completed_at",
        }
        assert cols == expected

    def test_audit_logs_columns(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("audit_logs")}
        engine.dispose()

        expected = {
            "id", "org_id", "user_id", "action", "resource_type",
            "resource_id", "details", "ip_address", "created_at",
        }
        assert cols == expected

    def test_foreign_keys(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)

        # users → organizations, roles
        user_fks = {
            fk["name"] for fk in inspector.get_foreign_keys("users")
        }
        assert "fk_users_org_id_organizations" in user_fks
        assert "fk_users_role_id_roles" in user_fks

        # scans → organizations, users, policies
        scan_fks = {
            fk["name"] for fk in inspector.get_foreign_keys("scans")
        }
        assert "fk_scans_org_id_organizations" in scan_fks
        assert "fk_scans_user_id_users" in scan_fks
        assert "fk_scans_policy_id_policies" in scan_fks

        # audit_logs → organizations, users
        audit_fks = {
            fk["name"] for fk in inspector.get_foreign_keys("audit_logs")
        }
        assert "fk_audit_logs_org_id_organizations" in audit_fks
        assert "fk_audit_logs_user_id_users" in audit_fks

        engine.dispose()

    def test_indexes(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)

        org_idx = {idx["name"] for idx in inspector.get_indexes("organizations")}
        assert "ix_organizations_slug" in org_idx

        user_idx = {idx["name"] for idx in inspector.get_indexes("users")}
        assert "ix_users_email" in user_idx

        scan_idx = {idx["name"] for idx in inspector.get_indexes("scans")}
        assert "ix_scans_created_at" in scan_idx

        audit_idx = {idx["name"] for idx in inspector.get_indexes("audit_logs")}
        assert "ix_audit_logs_created_at" in audit_idx

        engine.dispose()

    def test_unique_constraints(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)

        org_uq = {
            uc["name"] for uc in inspector.get_unique_constraints("organizations")
        }
        assert "uq_organizations_slug" in org_uq

        user_uq = {
            uc["name"] for uc in inspector.get_unique_constraints("users")
        }
        assert "uq_users_email" in user_uq

        engine.dispose()

    # -- Downgrade tests -----------------------------------------------------

    def test_downgrade_removes_all_tables(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")

        engine = _engine()
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        engine.dispose()

        for table in EXPECTED_TABLES:
            assert table not in tables, f"Table {table!r} still present after downgrade"

    def test_upgrade_after_downgrade(self):
        """Full round-trip: upgrade → downgrade → upgrade."""
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")

        engine = _engine()
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        engine.dispose()

        for table in EXPECTED_TABLES:
            assert table in tables


@skip_no_db
@pytest.mark.integration
class TestMigrationCurrentRevision:
    """Verify that current() reports the expected revision after upgrade."""

    def setup_method(self):
        cfg = _alembic_cfg()
        try:
            command.downgrade(cfg, "base")
        except Exception:
            pass

    def teardown_method(self):
        cfg = _alembic_cfg()
        try:
            command.downgrade(cfg, "base")
        except Exception:
            pass

    def test_current_revision_after_upgrade(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")

        engine = _engine()
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT version_num FROM alembic_version")
            )
            row = result.fetchone()
        engine.dispose()

        assert row is not None
        assert row[0] == "0001"

    def test_no_revision_after_downgrade(self):
        cfg = _alembic_cfg()
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")

        engine = _engine()
        inspector = inspect(engine)
        # alembic_version table may or may not exist after downgrade to base;
        # if it exists, it should be empty
        if "alembic_version" in inspector.get_table_names():
            with engine.connect() as conn:
                result = conn.execute(
                    text("SELECT version_num FROM alembic_version")
                )
                row = result.fetchone()
            assert row is None
        engine.dispose()
