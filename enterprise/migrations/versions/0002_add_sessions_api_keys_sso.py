"""Add sessions, API keys, SSO config, and password reset tokens

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-06

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add enterprise authentication tables."""

    # --- sessions (FK -> users) ---
    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_jti", sa.String(255), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_sessions_user_id_users",
        ),
        sa.UniqueConstraint("token_jti", name="uq_sessions_token_jti"),
    )
    op.create_index("ix_sessions_token_jti", "sessions", ["token_jti"])
    op.create_index("ix_sessions_created_at", "sessions", ["created_at"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    # --- api_keys (FK -> users, organizations) ---
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_api_keys_user_id_users",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name="fk_api_keys_org_id_organizations",
        ),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])

    # --- sso_configs (FK -> organizations) ---
    op.create_table(
        "sso_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_type", sa.String(50), nullable=False),
        sa.Column("provider_name", sa.String(255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default="true"),
        # OIDC fields
        sa.Column("client_id", sa.String(255), nullable=True),
        sa.Column("client_secret", sa.Text(), nullable=True),
        sa.Column("discovery_url", sa.Text(), nullable=True),
        # SAML fields
        sa.Column("saml_entity_id", sa.String(255), nullable=True),
        sa.Column("saml_sso_url", sa.Text(), nullable=True),
        sa.Column("saml_certificate", sa.Text(), nullable=True),
        # LDAP fields
        sa.Column("ldap_server", sa.String(255), nullable=True),
        sa.Column("ldap_port", sa.String(10), nullable=True),
        sa.Column("ldap_bind_dn", sa.Text(), nullable=True),
        sa.Column("ldap_bind_password", sa.Text(), nullable=True),
        sa.Column("ldap_search_base", sa.Text(), nullable=True),
        sa.Column("ldap_search_filter", sa.Text(), nullable=True),
        # Additional settings
        sa.Column("settings", sa.JSON(), server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_sso_configs"),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name="fk_sso_configs_org_id_organizations",
        ),
    )

    # --- password_reset_tokens (FK -> users) ---
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("is_used", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_password_reset_tokens"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_password_reset_tokens_user_id_users",
        ),
        sa.UniqueConstraint("token_hash", name="uq_password_reset_tokens_token_hash"),
    )
    op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"])
    op.create_index("ix_password_reset_tokens_created_at", "password_reset_tokens", ["created_at"])
    op.create_index("ix_password_reset_tokens_expires_at", "password_reset_tokens", ["expires_at"])


def downgrade() -> None:
    """Drop enterprise authentication tables."""
    op.drop_table("password_reset_tokens")
    op.drop_table("sso_configs")
    op.drop_table("api_keys")
    op.drop_table("sessions")
