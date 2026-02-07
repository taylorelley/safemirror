"""Approval workflow database models.

Stores approval requests and their state transition history.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class ApprovalRequest(Base):
    """
    Tracks approval status for packages.
    
    Each package version can have one approval request per organization.
    """
    __tablename__ = "approval_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Package identification
    package_id = Column(UUID(as_uuid=True), nullable=True, index=True)  # FK to packages when connected
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=False)
    package_type = Column(String(50), nullable=False)  # deb, rpm, npm, pypi, etc.
    
    # Related entities
    mirror_id = Column(UUID(as_uuid=True), ForeignKey("mirrors.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    
    # Workflow state
    state = Column(String(50), nullable=False, default="pending", index=True)
    
    # Request tracking
    requested_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Approval tracking
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    
    # Rejection tracking
    rejected_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    
    # Additional data
    extra_data = Column(JSON, nullable=False, default={})
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization")
    mirror = relationship("Mirror", back_populates="approval_requests")
    scan = relationship("Scan")
    policy = relationship("Policy")
    requester = relationship("User", foreign_keys=[requested_by])
    approver = relationship("User", foreign_keys=[approved_by])
    rejecter = relationship("User", foreign_keys=[rejected_by])
    history = relationship("ApprovalHistory", back_populates="request", order_by="ApprovalHistory.created_at")
    
    def __repr__(self) -> str:
        return f"<ApprovalRequest {self.package_name}@{self.package_version} [{self.state}]>"


class ApprovalHistory(Base):
    """
    Records all state transitions for approval requests.
    
    Provides a complete audit trail of the approval workflow.
    """
    __tablename__ = "approval_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(UUID(as_uuid=True), ForeignKey("approval_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Transition details
    from_state = Column(String(50), nullable=False)
    to_state = Column(String(50), nullable=False)
    transition = Column(String(50), nullable=False)
    
    # Actor
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Optional comment (required for rejections)
    comment = Column(Text, nullable=True)
    
    # Additional context
    extra_data = Column(JSON, nullable=False, default={})
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    request = relationship("ApprovalRequest", back_populates="history")
    user = relationship("User")
    
    def __repr__(self) -> str:
        return f"<ApprovalHistory {self.from_state} -> {self.to_state}>"
