import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=True)
    package_type = Column(String(50), nullable=False)  # deb, rpm, apk, pypi, npm
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=True)
    status = Column(String(50), nullable=False, default="pending")  # pending, running, completed, failed
    results = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="scans")
    user = relationship("User", back_populates="scans")
    policy = relationship("Policy", back_populates="scans")
