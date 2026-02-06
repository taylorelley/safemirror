"""API key generation and management utilities."""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from enterprise.db.models.api_key import APIKey


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key.
    
    Returns:
        (full_key, key_hash, key_prefix) tuple
        - full_key: The actual key to return to user (only shown once)
        - key_hash: Hash to store in database
        - key_prefix: First 8 chars for identification
    """
    # Generate 32 random bytes, base64 encode
    random_bytes = secrets.token_bytes(32)
    full_key = f"sm_{secrets.token_urlsafe(32)}"
    
    # Hash for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    
    # Prefix for identification (first 8 chars after sm_)
    key_prefix = full_key[:11]  # "sm_" + first 8 chars
    
    return full_key, key_hash, key_prefix


def verify_api_key(key: str, db: Session) -> Optional[APIKey]:
    """Verify an API key and return the APIKey object if valid.
    
    Args:
        key: The full API key string
        db: Database session
        
    Returns:
        APIKey object if valid and active, None otherwise
    """
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    
    api_key = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()
    
    if not api_key:
        return None
    
    # Check expiration
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        return None
    
    # Update last used
    api_key.last_used_at = datetime.utcnow()
    db.commit()
    
    return api_key


def create_api_key(
    user_id: UUID,
    org_id: UUID,
    name: str,
    scopes: List[str],
    db: Session,
    expires_in_days: Optional[int] = None
) -> tuple[APIKey, str]:
    """Create a new API key.
    
    Returns:
        (api_key_model, full_key) tuple
        The full_key should be returned to user and never stored
    """
    full_key, key_hash, key_prefix = generate_api_key()
    
    expires_at = None
    if expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    
    api_key = APIKey(
        user_id=user_id,
        org_id=org_id,
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=scopes,
        expires_at=expires_at,
    )
    
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    return api_key, full_key


def revoke_api_key(api_key_id: UUID, db: Session) -> bool:
    """Revoke an API key by marking it inactive."""
    api_key = db.query(APIKey).filter(APIKey.id == api_key_id).first()
    if api_key:
        api_key.is_active = False
        db.commit()
        return True
    return False


def list_user_api_keys(user_id: UUID, db: Session, include_inactive: bool = False) -> List[APIKey]:
    """List all API keys for a user."""
    query = db.query(APIKey).filter(APIKey.user_id == user_id)
    
    if not include_inactive:
        query = query.filter(APIKey.is_active == True)
    
    return query.order_by(APIKey.created_at.desc()).all()
