"""Tests for password reset functionality."""

import pytest
from datetime import datetime, timedelta

from enterprise.core.password_reset import (
    generate_reset_token,
    create_reset_token,
    verify_reset_token,
    use_reset_token,
    cleanup_expired_tokens,
)
from enterprise.core.security import get_password_hash, verify_password


def test_generate_reset_token():
    """Test reset token generation."""
    token, token_hash = generate_reset_token()
    
    # Token should be URL-safe
    assert len(token) > 20
    
    # Hash should be 64 char hex string (SHA256)
    assert len(token_hash) == 64
    assert all(c in '0123456789abcdef' for c in token_hash)


def test_create_reset_token(db_session, user_factory):
    """Test creating a password reset token."""
    user = user_factory()
    
    reset_token, plain_token = create_reset_token(user.id, db_session)
    
    assert reset_token.user_id == user.id
    assert reset_token.is_used is False
    assert reset_token.expires_at > datetime.utcnow()
    assert len(plain_token) > 20


def test_verify_reset_token(db_session, user_factory):
    """Test verifying a password reset token."""
    user = user_factory()
    
    reset_token, plain_token = create_reset_token(user.id, db_session)
    
    # Valid token should return user_id
    user_id = verify_reset_token(plain_token, db_session)
    assert user_id == user.id
    
    # Invalid token should return None
    user_id = verify_reset_token("invalid_token", db_session)
    assert user_id is None


def test_use_reset_token(db_session, user_factory):
    """Test using a reset token to change password."""
    user = user_factory(password="oldpassword")
    
    reset_token, plain_token = create_reset_token(user.id, db_session)
    
    # Use token to change password
    new_password_hash = get_password_hash("newpassword")
    success = use_reset_token(plain_token, new_password_hash, db_session)
    assert success is True
    
    # Refresh user and verify new password
    db_session.refresh(user)
    assert verify_password("newpassword", user.password_hash)
    assert not verify_password("oldpassword", user.password_hash)
    
    # Token should be marked as used
    db_session.refresh(reset_token)
    assert reset_token.is_used is True
    assert reset_token.used_at is not None
    
    # Cannot reuse token
    success = use_reset_token(plain_token, new_password_hash, db_session)
    assert success is False


def test_expired_token(db_session, user_factory):
    """Test that expired tokens don't work."""
    user = user_factory()
    
    # Create token that expires immediately
    reset_token, plain_token = create_reset_token(user.id, db_session, expires_in_hours=-1)
    
    # Verify should fail
    user_id = verify_reset_token(plain_token, db_session)
    assert user_id is None
    
    # Use should fail
    new_password_hash = get_password_hash("newpassword")
    success = use_reset_token(plain_token, new_password_hash, db_session)
    assert success is False


def test_create_reset_token_invalidates_old_tokens(db_session, user_factory):
    """Test that creating a new token invalidates old unused tokens."""
    user = user_factory()
    
    # Create first token
    token1, plain_token1 = create_reset_token(user.id, db_session)
    
    # Create second token
    token2, plain_token2 = create_reset_token(user.id, db_session)
    
    # First token should be marked as used
    db_session.refresh(token1)
    assert token1.is_used is True
    
    # Second token should still be valid
    user_id = verify_reset_token(plain_token2, db_session)
    assert user_id == user.id


def test_cleanup_expired_tokens(db_session, user_factory):
    """Test cleaning up expired tokens."""
    user1 = user_factory()
    user2 = user_factory()
    
    # Create expired tokens
    create_reset_token(user1.id, db_session, expires_in_hours=-1)
    create_reset_token(user2.id, db_session, expires_in_hours=-1)
    
    # Create valid token
    create_reset_token(user1.id, db_session, expires_in_hours=1)
    
    # Cleanup should remove 2 expired tokens
    count = cleanup_expired_tokens(db_session)
    assert count == 2
