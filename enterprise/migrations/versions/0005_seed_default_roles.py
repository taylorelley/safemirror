"""Seed default roles for existing organizations

Revision ID: 0005
Revises: 0004
Create Date: 2026-02-07

Creates the 5 default roles (Admin, Developer, Security Analyst, Auditor, Viewer)
for all existing organizations.
"""
from typing import Sequence, Union
import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: Union[str, Sequence[str], None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Default roles with their permissions
DEFAULT_ROLES = {
    "Admin": ["*:*"],
    "Developer": [
        "mirrors:read", "mirrors:list",
        "packages:read", "packages:list",
        "scans:create", "scans:read", "scans:list", "scans:execute",
        "approvals:read", "approvals:list",
        "api_keys:create", "api_keys:read", "api_keys:list", "api_keys:delete",
        "reports:read", "reports:list",
    ],
    "Security Analyst": [
        "mirrors:create", "mirrors:read", "mirrors:update", "mirrors:delete", "mirrors:list", "mirrors:configure",
        "packages:read", "packages:list", "packages:approve", "packages:reject", "packages:delete",
        "scans:create", "scans:read", "scans:list", "scans:execute", "scans:delete",
        "approvals:read", "approvals:list", "approvals:approve", "approvals:reject",
        "policies:create", "policies:read", "policies:update", "policies:delete", "policies:list",
        "audit_logs:read", "audit_logs:list", "audit_logs:export",
        "reports:create", "reports:read", "reports:list", "reports:export",
        "api_keys:create", "api_keys:read", "api_keys:list", "api_keys:delete",
    ],
    "Auditor": [
        "mirrors:read", "mirrors:list",
        "packages:read", "packages:list",
        "scans:read", "scans:list",
        "approvals:read", "approvals:list",
        "policies:read", "policies:list",
        "users:read", "users:list",
        "roles:read", "roles:list",
        "audit_logs:read", "audit_logs:list", "audit_logs:export",
        "reports:create", "reports:read", "reports:list", "reports:export",
        "organization:read",
    ],
    "Viewer": [
        "mirrors:read", "mirrors:list",
        "packages:read", "packages:list",
        "scans:read", "scans:list",
        "approvals:read", "approvals:list",
        "reports:read", "reports:list",
    ],
}


def upgrade() -> None:
    """Create default roles for all existing organizations."""
    # Get connection
    connection = op.get_bind()
    
    # Get all organizations
    orgs = connection.execute(
        sa.text("SELECT id FROM organizations")
    ).fetchall()
    
    for org in orgs:
        org_id = org[0]
        
        for role_name, permissions in DEFAULT_ROLES.items():
            # Check if role already exists
            existing = connection.execute(
                sa.text("""
                    SELECT id FROM roles 
                    WHERE org_id = :org_id AND name = :name AND is_system = true
                """),
                {"org_id": org_id, "name": role_name}
            ).fetchone()
            
            if existing:
                continue
            
            # Insert new role
            import json
            connection.execute(
                sa.text("""
                    INSERT INTO roles (id, org_id, name, permissions, is_system, created_at)
                    VALUES (:id, :org_id, :name, :permissions, true, now())
                """),
                {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "name": role_name,
                    "permissions": json.dumps(permissions),
                }
            )


def downgrade() -> None:
    """Remove seeded default roles."""
    connection = op.get_bind()
    
    for role_name in DEFAULT_ROLES.keys():
        connection.execute(
            sa.text("""
                DELETE FROM roles 
                WHERE name = :name AND is_system = true
            """),
            {"name": role_name}
        )
