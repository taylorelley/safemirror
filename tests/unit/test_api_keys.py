"""Tests for API key generation and management."""

import pytest
from datetime import datetime, timedelta

from enterprise.core.api_key import (
    generate_api_key,
    create_api_key,
    verify_api_key,
    revoke_api_key,
    list_user_api_keys,
)


def test_generate_api_key():
    """Test API key generation."""
    full_key, key_hash, key_prefix = generate_api_key()
    
    # Key should start with sm_
    assert full_key.startswith("sm_")
    
    # Prefix should be first 11 chars
    assert key_prefix == full_key[:11]
    
    # Hash should be 64 char hex string (SHA256)
    assert len(key_hash) == 64
    assert all(c in '0123456789abcdef' for c in key_hash)


def test_create_api_key(db_session, user_factory):
    """Test creating an API key."""
    user = user_factory()
    
    api_key, full_key = create_api_key(
        user_id=user.id,
        org_id=user.org_id,
        name="Test Key",
        scopes=["scans:read", "scans:write"],
        db=db_session
    )
    
    assert api_key.name == "Test Key"
    assert api_key.scopes == ["scans:read", "scans:write"]
    assert api_key.is_active is True
    assert api_key.user_id == user.id
    assert api_key.org_id == user.org_id
    assert full_key.startswith("sm_")


def test_verify_api_key(db_session, user_factory):
    """Test API key verification."""
    user = user_factory()
    
    api_key, full_key = create_api_key(
        user_id=user.id,
        org_id=user.org_id,
        name="Test Key",
        scopes=["scans:read"],
        db=db_session
    )
    
    # Valid key should work
    verified = verify_api_key(full_key, db_session)
    assert verified is not None
    assert verified.id == api_key.id
    assert verified.last_used_at is not None
    
    # Invalid key should return None
    verified = verify_api_key("sm_invalid_key", db_session)
    assert verified is None


def test_revoke_api_key(db_session, user_factory):
    """Test API key revocation."""
    user = user_factory()
    
    api_key, full_key = create_api_key(
        user_id=user.id,
        org_id=user.org_id,
        name="Test Key",
        scopes=["scans:read"],
        db=db_session
    )
    
    # Revoke the key
    result = revoke_api_key(api_key.id, db_session)
    assert result is True
    
    # Verify should now fail
    verified = verify_api_key(full_key, db_session)
    assert verified is None


def test_api_key_expiration(db_session, user_factory):
    """Test API key expiration."""
    user = user_factory()
    
    # Create key that expires in -1 days (already expired)
    api_key, full_key = create_api_key(
        user_id=user.id,
        org_id=user.org_id,
        name="Expired Key",
        scopes=["scans:read"],
        db=db_session,
        expires_in_days=-1
    )
    
    # Verify should fail for expired key
    verified = verify_api_key(full_key, db_session)
    assert verified is None


def test_list_user_api_keys(db_session, user_factory):
    """Test listing user API keys."""
    user = user_factory()
    
    # Create multiple keys
    key1, _ = create_api_key(user.id, user.org_id, "Key 1", ["scans:read"], db_session)
    key2, _ = create_api_key(user.id, user.org_id, "Key 2", ["scans:write"], db_session)
    key3, _ = create_api_key(user.id, user.org_id, "Key 3", ["admin"], db_session)
    
    # Revoke one
    revoke_api_key(key2.id, db_session)
    
    # List active keys only
    keys = list_user_api_keys(user.id, db_session, include_inactive=False)
    assert len(keys) == 2
    assert key2.id not in [k.id for k in keys]
    
    # List all keys
    keys = list_user_api_keys(user.id, db_session, include_inactive=True)
    assert len(keys) == 3
