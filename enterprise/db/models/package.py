"""Package database model.

Represents scanned packages in the SafeMirror system.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Boolean, BigInteger, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class Package(Base):
    """
    A scanned package.
    
    Represents a specific version of a package that has been
    ingested into SafeMirror for scanning and approval.
    """
    __tablename__ = "packages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    mirror_id = Column(UUID(as_uuid=True), ForeignKey("mirrors.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Package identification
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(100), nullable=False)
    package_type = Column(String(50), nullable=False, index=True)  # deb, rpm, npm, pypi, etc.
    
    # Package metadata
    architecture = Column(String(50), nullable=True)  # amd64, arm64, noarch, etc.
    maintainer = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    homepage = Column(Text, nullable=True)
    license = Column(String(255), nullable=True)
    
    # File information
    filename = Column(String(512), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    checksum_sha256 = Column(String(64), nullable=True)
    checksum_sha512 = Column(String(128), nullable=True)
    
    # Scan status
    last_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    scan_status = Column(String(50), nullable=True)  # passed, failed, warning
    
    # Approval status
    approval_status = Column(String(50), nullable=False, default="pending")  # pending, approved, rejected
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Additional metadata
    extra_data = Column(JSON, nullable=False, default={})
    dependencies = Column(JSON, nullable=True)  # List of dependencies
    vulnerabilities = Column(JSON, nullable=True)  # Scan results summary
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization")
    mirror = relationship("Mirror", back_populates="packages")
    last_scan = relationship("Scan", foreign_keys=[last_scan_id])
    approver = relationship("User", foreign_keys=[approved_by])
    
    def __repr__(self) -> str:
        return f"<Package {self.name}@{self.version} ({self.package_type})>"
