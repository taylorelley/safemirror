"""Notification preferences and history models."""

import uuid
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Boolean, Text, Integer
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class NotificationChannel(str, Enum):
    """Available notification channels."""
    EMAIL = "email"
    WEBHOOK = "webhook"
    

class NotificationEventType(str, Enum):
    """Events that can trigger notifications."""
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_APPROVED = "approval_approved"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    POLICY_VIOLATION = "policy_violation"
    DAILY_DIGEST = "daily_digest"


class NotificationPreference(Base):
    """
    User notification preferences.
    
    Controls what notifications a user receives and how.
    """
    __tablename__ = "notification_preferences"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Email preferences
    email_enabled = Column(Boolean, default=True)
    email_address = Column(String(255), nullable=True)  # Override user's primary email
    
    # Event subscriptions (array of event types)
    subscribed_events = Column(ARRAY(String(50)), default=list)
    
    # Digest preferences
    digest_enabled = Column(Boolean, default=False)  # Daily digest instead of immediate
    digest_hour_utc = Column(Integer, default=9)  # Hour to send digest (0-23 UTC)
    
    # Mirror-specific subscriptions (null = all mirrors)
    mirror_ids = Column(ARRAY(UUID(as_uuid=True)), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
    organization = relationship("Organization")
    
    def __repr__(self) -> str:
        return f"<NotificationPreference user={self.user_id}>"


class WebhookConfig(Base):
    """
    Webhook configuration for external integrations.
    
    Allows sending notifications to external systems like Slack, Teams, etc.
    """
    __tablename__ = "webhook_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Basic info
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Webhook configuration
    url = Column(Text, nullable=False)
    method = Column(String(10), default="POST")  # POST, PUT
    
    # Authentication
    auth_type = Column(String(50), nullable=True)  # bearer, basic, header
    auth_value = Column(Text, nullable=True)  # Encrypted token/password
    
    # Custom headers
    headers = Column(JSON, default=dict)
    
    # Event subscriptions
    subscribed_events = Column(ARRAY(String(50)), default=list)
    
    # Payload template (Jinja2 template for custom payloads)
    payload_template = Column(Text, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    last_triggered_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    failure_count = Column(Integer, default=0)
    
    # Rate limiting
    max_retries = Column(Integer, default=3)
    retry_delay_seconds = Column(Integer, default=60)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization")
    
    def __repr__(self) -> str:
        return f"<WebhookConfig {self.name}>"


class NotificationLog(Base):
    """
    Log of sent notifications for audit and debugging.
    """
    __tablename__ = "notification_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Notification details
    channel = Column(String(50), nullable=False)  # email, webhook
    event_type = Column(String(50), nullable=False)
    recipient = Column(String(255), nullable=False)  # Email address or webhook ID
    
    # Related entities
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    webhook_id = Column(UUID(as_uuid=True), ForeignKey("webhook_configs.id", ondelete="SET NULL"), nullable=True)
    approval_request_id = Column(UUID(as_uuid=True), ForeignKey("approval_requests.id", ondelete="SET NULL"), nullable=True)
    
    # Payload
    subject = Column(String(512), nullable=True)
    body = Column(Text, nullable=True)
    payload = Column(JSON, nullable=True)
    
    # Status
    status = Column(String(50), nullable=False, default="pending")  # pending, sent, failed
    error_message = Column(Text, nullable=True)
    attempts = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    sent_at = Column(DateTime, nullable=True)
    
    # Relationships
    organization = relationship("Organization")
    user = relationship("User")
    webhook = relationship("WebhookConfig")
    approval_request = relationship("ApprovalRequest")
    
    def __repr__(self) -> str:
        return f"<NotificationLog {self.event_type} to {self.recipient}>"
