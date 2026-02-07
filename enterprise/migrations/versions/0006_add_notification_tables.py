"""Add notification tables

Revision ID: 0006
Revises: 0005
Create Date: 2026-02-07

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0006'
down_revision: Union[str, None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create notification_preferences table
    op.create_table(
        'notification_preferences',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_enabled', sa.Boolean(), nullable=True, default=True),
        sa.Column('email_address', sa.String(255), nullable=True),
        sa.Column('subscribed_events', postgresql.ARRAY(sa.String(50)), nullable=True),
        sa.Column('digest_enabled', sa.Boolean(), nullable=True, default=False),
        sa.Column('digest_hour_utc', sa.Integer(), nullable=True, default=9),
        sa.Column('mirror_ids', postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_notification_preferences_user_id', 'notification_preferences', ['user_id'])
    op.create_index('ix_notification_preferences_org_id', 'notification_preferences', ['org_id'])

    # Create webhook_configs table
    op.create_table(
        'webhook_configs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('method', sa.String(10), nullable=True, default='POST'),
        sa.Column('auth_type', sa.String(50), nullable=True),
        sa.Column('auth_value', sa.Text(), nullable=True),
        sa.Column('headers', postgresql.JSON(), nullable=True),
        sa.Column('subscribed_events', postgresql.ARRAY(sa.String(50)), nullable=True),
        sa.Column('payload_template', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.Column('last_triggered_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('failure_count', sa.Integer(), nullable=True, default=0),
        sa.Column('max_retries', sa.Integer(), nullable=True, default=3),
        sa.Column('retry_delay_seconds', sa.Integer(), nullable=True, default=60),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_webhook_configs_org_id', 'webhook_configs', ['org_id'])

    # Create notification_logs table
    op.create_table(
        'notification_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('channel', sa.String(50), nullable=False),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('recipient', sa.String(255), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('webhook_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('approval_request_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('subject', sa.String(512), nullable=True),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('payload', postgresql.JSON(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False, default='pending'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=True, default=0),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['approval_request_id'], ['approval_requests.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['webhook_id'], ['webhook_configs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_notification_logs_org_id', 'notification_logs', ['org_id'])
    op.create_index('ix_notification_logs_created_at', 'notification_logs', ['created_at'])


def downgrade() -> None:
    op.drop_table('notification_logs')
    op.drop_table('webhook_configs')
    op.drop_table('notification_preferences')
