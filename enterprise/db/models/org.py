import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users = relationship("User", back_populates="organization")
    roles = relationship("Role", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    sso_configs = relationship("SSOConfig", back_populates="organization", cascade="all, delete-orphan")
