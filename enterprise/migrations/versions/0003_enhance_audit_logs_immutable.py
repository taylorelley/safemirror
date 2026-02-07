"""Enhance audit_logs table with immutability and additional fields

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-07

This migration:
1. Adds new columns for better tracing (user_agent, session_id, request_id)
2. Creates database triggers to enforce immutability (prevent UPDATE/DELETE)
3. Adds indexes for common query patterns
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Enhance audit_logs with immutability and tracing fields."""
    
    # Add new columns for better tracing
    op.add_column(
        "audit_logs",
        sa.Column("user_agent", sa.Text(), nullable=True)
    )
    op.add_column(
        "audit_logs",
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=True)
    )
    op.add_column(
        "audit_logs",
        sa.Column("request_id", sa.String(64), nullable=True)
    )
    op.add_column(
        "audit_logs",
        sa.Column("severity", sa.String(20), server_default="info", nullable=False)
    )
    op.add_column(
        "audit_logs",
        sa.Column("old_values", sa.JSON(), nullable=True)
    )
    op.add_column(
        "audit_logs",
        sa.Column("new_values", sa.JSON(), nullable=True)
    )
    
    # Add indexes for common query patterns
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_resource_type", "audit_logs", ["resource_type"])
    op.create_index("ix_audit_logs_resource_id", "audit_logs", ["resource_id"])
    op.create_index("ix_audit_logs_severity", "audit_logs", ["severity"])
    op.create_index("ix_audit_logs_session_id", "audit_logs", ["session_id"])
    
    # Composite index for common filtering pattern
    op.create_index(
        "ix_audit_logs_org_created",
        "audit_logs",
        ["org_id", "created_at"],
        postgresql_using="btree"
    )
    op.create_index(
        "ix_audit_logs_user_created",
        "audit_logs",
        ["user_id", "created_at"],
        postgresql_using="btree"
    )
    
    # Create trigger function to prevent updates
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_log_update()
        RETURNS TRIGGER AS $trigger$
        BEGIN
            RAISE EXCEPTION 'Audit logs are immutable and cannot be updated. Record ID: %', OLD.id;
        END;
        $trigger$ LANGUAGE plpgsql;
    """)
    
    # Create trigger function to prevent deletes (but allow admin override via session variable)
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_log_delete()
        RETURNS TRIGGER AS $trigger$
        BEGIN
            -- Allow deletion only if explicit admin bypass is set
            IF current_setting('safemirror.audit_admin_bypass', true) = 'true' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'Audit logs are immutable and cannot be deleted. Record ID: %', OLD.id;
        END;
        $trigger$ LANGUAGE plpgsql;
    """)
    
    # Create trigger to prevent updates
    op.execute("""
        CREATE TRIGGER audit_logs_prevent_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW
        EXECUTE FUNCTION prevent_audit_log_update();
    """)
    
    # Create trigger to prevent deletes
    op.execute("""
        CREATE TRIGGER audit_logs_prevent_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW
        EXECUTE FUNCTION prevent_audit_log_delete();
    """)
    
    # Add foreign key to sessions table (if session tracking)
    op.create_foreign_key(
        "fk_audit_logs_session_id_sessions",
        "audit_logs",
        "sessions",
        ["session_id"],
        ["id"],
        ondelete="SET NULL"
    )


def downgrade() -> None:
    """Remove audit log enhancements."""
    
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS audit_logs_prevent_update ON audit_logs;")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_prevent_delete ON audit_logs;")
    
    # Drop trigger functions
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_update();")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_delete();")
    
    # Drop foreign key
    op.drop_constraint("fk_audit_logs_session_id_sessions", "audit_logs", type_="foreignkey")
    
    # Drop indexes
    op.drop_index("ix_audit_logs_user_created", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_created", table_name="audit_logs")
    op.drop_index("ix_audit_logs_session_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_severity", table_name="audit_logs")
    op.drop_index("ix_audit_logs_resource_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_resource_type", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_id", table_name="audit_logs")
    
    # Drop columns
    op.drop_column("audit_logs", "new_values")
    op.drop_column("audit_logs", "old_values")
    op.drop_column("audit_logs", "severity")
    op.drop_column("audit_logs", "request_id")
    op.drop_column("audit_logs", "session_id")
    op.drop_column("audit_logs", "user_agent")
