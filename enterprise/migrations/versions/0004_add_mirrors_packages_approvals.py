"""Add mirrors, packages, and approval workflow tables

Revision ID: 0004
Revises: 0003
Create Date: 2026-02-07

Tables added:
- mirrors: Package mirror configurations
- packages: Scanned packages
- approval_requests: Package approval workflow
- approval_history: State transition audit trail
- mirror_role_assignments: Per-mirror role assignments
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, Sequence[str], None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create mirrors, packages, and approval tables."""
    
    # --- mirrors ---
    op.create_table(
        "mirrors",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("mirror_type", sa.String(50), nullable=False),
        sa.Column("upstream_url", sa.Text(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("is_syncing", sa.Boolean(), server_default="false"),
        sa.Column("last_sync_at", sa.DateTime(), nullable=True),
        sa.Column("last_sync_error", sa.Text(), nullable=True),
        sa.Column("auto_approve", sa.Boolean(), server_default="false"),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_mirrors"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], name="fk_mirrors_org_id"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], name="fk_mirrors_policy_id", ondelete="SET NULL"),
    )
    op.create_index("ix_mirrors_org_id", "mirrors", ["org_id"])
    op.create_index("ix_mirrors_slug", "mirrors", ["slug"])
    op.create_index("ix_mirrors_mirror_type", "mirrors", ["mirror_type"])
    
    # --- packages ---
    op.create_table(
        "packages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mirror_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100), nullable=False),
        sa.Column("package_type", sa.String(50), nullable=False),
        sa.Column("architecture", sa.String(50), nullable=True),
        sa.Column("maintainer", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("homepage", sa.Text(), nullable=True),
        sa.Column("license", sa.String(255), nullable=True),
        sa.Column("filename", sa.String(512), nullable=True),
        sa.Column("file_size", sa.BigInteger(), nullable=True),
        sa.Column("checksum_sha256", sa.String(64), nullable=True),
        sa.Column("checksum_sha512", sa.String(128), nullable=True),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(), nullable=True),
        sa.Column("scan_status", sa.String(50), nullable=True),
        sa.Column("approval_status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("dependencies", sa.JSON(), nullable=True),
        sa.Column("vulnerabilities", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_packages"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], name="fk_packages_org_id"),
        sa.ForeignKeyConstraint(["mirror_id"], ["mirrors.id"], name="fk_packages_mirror_id", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["scans.id"], name="fk_packages_last_scan_id", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], name="fk_packages_approved_by", ondelete="SET NULL"),
    )
    op.create_index("ix_packages_org_id", "packages", ["org_id"])
    op.create_index("ix_packages_mirror_id", "packages", ["mirror_id"])
    op.create_index("ix_packages_name", "packages", ["name"])
    op.create_index("ix_packages_package_type", "packages", ["package_type"])
    op.create_index("ix_packages_approval_status", "packages", ["approval_status"])
    op.create_index("ix_packages_created_at", "packages", ["created_at"])
    # Composite index for common queries
    op.create_index("ix_packages_name_version", "packages", ["name", "version"])
    
    # --- approval_requests ---
    op.create_table(
        "approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("package_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("package_version", sa.String(100), nullable=False),
        sa.Column("package_type", sa.String(50), nullable=False),
        sa.Column("mirror_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("state", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("rejected_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rejected_at", sa.DateTime(), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_approval_requests"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], name="fk_approval_requests_org_id"),
        sa.ForeignKeyConstraint(["package_id"], ["packages.id"], name="fk_approval_requests_package_id", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["mirror_id"], ["mirrors.id"], name="fk_approval_requests_mirror_id", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name="fk_approval_requests_scan_id", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], name="fk_approval_requests_policy_id", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], name="fk_approval_requests_requested_by", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], name="fk_approval_requests_approved_by", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rejected_by"], ["users.id"], name="fk_approval_requests_rejected_by", ondelete="SET NULL"),
    )
    op.create_index("ix_approval_requests_org_id", "approval_requests", ["org_id"])
    op.create_index("ix_approval_requests_package_id", "approval_requests", ["package_id"])
    op.create_index("ix_approval_requests_mirror_id", "approval_requests", ["mirror_id"])
    op.create_index("ix_approval_requests_state", "approval_requests", ["state"])
    op.create_index("ix_approval_requests_created_at", "approval_requests", ["created_at"])
    
    # --- approval_history ---
    op.create_table(
        "approval_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("from_state", sa.String(50), nullable=False),
        sa.Column("to_state", sa.String(50), nullable=False),
        sa.Column("transition", sa.String(50), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_approval_history"),
        sa.ForeignKeyConstraint(["request_id"], ["approval_requests.id"], name="fk_approval_history_request_id", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_approval_history_user_id", ondelete="SET NULL"),
    )
    op.create_index("ix_approval_history_request_id", "approval_history", ["request_id"])
    op.create_index("ix_approval_history_created_at", "approval_history", ["created_at"])
    
    # --- mirror_role_assignments ---
    op.create_table(
        "mirror_role_assignments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mirror_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_mirror_role_assignments"),
        sa.ForeignKeyConstraint(["mirror_id"], ["mirrors.id"], name="fk_mirror_role_assignments_mirror_id", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_mirror_role_assignments_user_id", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], name="fk_mirror_role_assignments_role_id", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_by"], ["users.id"], name="fk_mirror_role_assignments_assigned_by", ondelete="SET NULL"),
    )
    op.create_index("ix_mirror_role_assignments_mirror_id", "mirror_role_assignments", ["mirror_id"])
    op.create_index("ix_mirror_role_assignments_user_id", "mirror_role_assignments", ["user_id"])
    # Unique constraint: user can only have one role per mirror
    op.create_unique_constraint("uq_mirror_role_assignments_mirror_user", "mirror_role_assignments", ["mirror_id", "user_id"])


def downgrade() -> None:
    """Drop mirrors, packages, and approval tables."""
    op.drop_table("mirror_role_assignments")
    op.drop_table("approval_history")
    op.drop_table("approval_requests")
    op.drop_table("packages")
    op.drop_table("mirrors")
