"""Audit log model for SafeMirror Enterprise.

This table is IMMUTABLE - database triggers prevent UPDATE and DELETE operations.
All audit entries are permanent for compliance and forensic purposes.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class AuditSeverity(str, Enum):
    """Severity levels for audit log entries."""
    DEBUG = "debug"       # Low-level debugging info
    INFO = "info"         # Standard operations
    WARNING = "warning"   # Potentially concerning actions
    ERROR = "error"       # Failed operations
    CRITICAL = "critical" # Security-relevant events (login failures, permission denials)


class AuditLog(Base):
    """
    Immutable audit log entry.
    
    Records all significant actions in the system for compliance and security.
    Database triggers prevent modification or deletion of entries.
    """
    __tablename__ = "audit_logs"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Organization scope
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Actor information
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    
    # Change tracking
    old_values = Column(JSON, nullable=True)  # Previous state (for updates)
    new_values = Column(JSON, nullable=True)  # New state (for creates/updates)
    details = Column(JSON, nullable=True)     # Additional context
    
    # Metadata
    severity = Column(String(20), nullable=False, default="info", index=True)
    request_id = Column(String(64), nullable=True)  # For distributed tracing
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships (read-only for querying)
    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")
    session = relationship("Session", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} on {self.resource_type} by user {self.user_id}>"
    
    @classmethod
    def create_entry(
        cls,
        org_id: uuid.UUID,
        action: str,
        resource_type: str,
        *,
        user_id: Optional[uuid.UUID] = None,
        resource_id: Optional[uuid.UUID] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[uuid.UUID] = None,
        request_id: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
    ) -> "AuditLog":
        """
        Factory method to create a new audit log entry.
        
        Args:
            org_id: Organization ID
            action: Action performed (e.g., 'create', 'update', 'delete', 'login')
            resource_type: Type of resource (e.g., 'package', 'mirror', 'user')
            user_id: ID of user performing action (None for system actions)
            resource_id: ID of affected resource
            old_values: Previous values (for updates)
            new_values: New values (for creates/updates)
            details: Additional context
            ip_address: Client IP address
            user_agent: Client user agent string
            session_id: Session ID for tracking
            request_id: Request correlation ID
            severity: Log severity level
        """
        return cls(
            org_id=org_id,
            action=action,
            resource_type=resource_type,
            user_id=user_id,
            resource_id=resource_id,
            old_values=old_values,
            new_values=new_values,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            severity=severity.value if isinstance(severity, AuditSeverity) else severity,
        )
