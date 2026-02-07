"""Mirror database model.

Represents a package mirror that SafeMirror manages.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Boolean, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class Mirror(Base):
    """
    Package mirror configuration.
    
    A mirror represents a source of packages that SafeMirror scans
    and manages approvals for.
    """
    __tablename__ = "mirrors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Basic info
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    
    # Mirror type and configuration
    mirror_type = Column(String(50), nullable=False)  # apt, yum, npm, pypi, etc.
    upstream_url = Column(Text, nullable=False)
    
    # Configuration
    config = Column(JSON, nullable=False, default=dict)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_syncing = Column(Boolean, default=False)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_error = Column(Text, nullable=True)
    
    # Approval settings
    auto_approve = Column(Boolean, default=False)  # Auto-approve if policy passes
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="mirrors")
    policy = relationship("Policy")
    approval_requests = relationship("ApprovalRequest", back_populates="mirror")
    packages = relationship("Package", back_populates="mirror")
    role_assignments = relationship("MirrorRoleAssignment", back_populates="mirror")
    
    def __repr__(self) -> str:
        return f"<Mirror {self.name} ({self.mirror_type})>"


class MirrorRoleAssignment(Base):
    """
    Per-mirror role assignments for users.
    
    Allows granting users specific roles on individual mirrors,
    separate from their organization-wide role.
    """
    __tablename__ = "mirror_role_assignments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mirror_id = Column(UUID(as_uuid=True), ForeignKey("mirrors.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Who assigned this role
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    
    # Relationships
    mirror = relationship("Mirror", back_populates="role_assignments")
    user = relationship("User", foreign_keys=[user_id])
    role = relationship("Role")
    assigner = relationship("User", foreign_keys=[assigned_by])
    
    def __repr__(self) -> str:
        return f"<MirrorRoleAssignment mirror={self.mirror_id} user={self.user_id}>"
