import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from enterprise.db.base import Base


class SSOConfig(Base):
    """SSO/IdP configuration per organization."""
    __tablename__ = "sso_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    provider_type = Column(String(50), nullable=False)  # oidc, saml, ldap
    provider_name = Column(String(255), nullable=False)  # e.g., "Okta", "Azure AD"
    is_enabled = Column(Boolean, default=True)
    
    # OIDC fields
    client_id = Column(String(255), nullable=True)
    client_secret = Column(Text, nullable=True)  # Encrypted
    discovery_url = Column(Text, nullable=True)
    
    # SAML fields
    saml_entity_id = Column(String(255), nullable=True)
    saml_sso_url = Column(Text, nullable=True)
    saml_certificate = Column(Text, nullable=True)
    
    # LDAP fields
    ldap_server = Column(String(255), nullable=True)
    ldap_port = Column(String(10), nullable=True)
    ldap_bind_dn = Column(Text, nullable=True)
    ldap_bind_password = Column(Text, nullable=True)  # Encrypted
    ldap_search_base = Column(Text, nullable=True)
    ldap_search_filter = Column(Text, nullable=True)
    
    # Additional settings (JSON for flexibility)
    settings = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="sso_configs")
