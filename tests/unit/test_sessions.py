"""Tests for JWT session tracking and management."""

import pytest
from datetime import datetime, timedelta
from jose import jwt

from enterprise.core.security import (
    create_access_token,
    decode_token,
    revoke_session,
    revoke_user_sessions,
)
from enterprise.db.models.session import Session as SessionModel
from enterprise.core.config import get_settings


settings = get_settings()


def test_create_access_token_creates_session(db_session, user_factory):
    """Test that creating an access token also creates a session record."""
    user = user_factory()
    
    # Initially no sessions
    assert db_session.query(SessionModel).count() == 0
    
    # Create token
    token = create_access_token(
        user.id,
        db_session,
        ip_address="192.168.1.1",
        user_agent="TestBrowser/1.0"
    )
    
    # Session should be created
    sessions = db_session.query(SessionModel).filter(SessionModel.user_id == user.id).all()
    assert len(sessions) == 1
    
    session = sessions[0]
    assert session.ip_address == "192.168.1.1"
    assert session.user_agent == "TestBrowser/1.0"
    assert session.revoked_at is None
    
    # Token should contain JTI
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    assert payload["jti"] == session.token_jti


def test_decode_token_validates_session(db_session, user_factory):
    """Test that decode_token checks for revoked sessions."""
    user = user_factory()
    
    # Create token
    token = create_access_token(user.id, db_session)
    
    # Token should be valid
    user_id = decode_token(token, db_session)
    assert user_id == user.id
    
    # Revoke the session
    session = db_session.query(SessionModel).filter(SessionModel.user_id == user.id).first()
    revoke_session(session.token_jti, db_session)
    
    # Token should now be invalid
    user_id = decode_token(token, db_session)
    assert user_id is None


def test_revoke_session(db_session, user_factory):
    """Test revoking a single session."""
    user = user_factory()
    token = create_access_token(user.id, db_session)
    
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    jti = payload["jti"]
    
    # Revoke session
    result = revoke_session(jti, db_session)
    assert result is True
    
    # Session should be marked as revoked
    session = db_session.query(SessionModel).filter(SessionModel.token_jti == jti).first()
    assert session.revoked_at is not None
    
    # Revoking again should return False
    result = revoke_session(jti, db_session)
    assert result is False


def test_revoke_user_sessions(db_session, user_factory):
    """Test revoking all sessions for a user."""
    user = user_factory()
    
    # Create multiple sessions
    token1 = create_access_token(user.id, db_session)
    token2 = create_access_token(user.id, db_session)
    token3 = create_access_token(user.id, db_session)
    
    payload1 = jwt.decode(token1, settings.secret_key, algorithms=[settings.algorithm])
    jti1 = payload1["jti"]
    
    # Revoke all except token1
    count = revoke_user_sessions(user.id, db_session, except_jti=jti1)
    assert count == 2
    
    # Token1 should still be valid
    assert decode_token(token1, db_session) == user.id
    
    # Token2 and token3 should be revoked
    assert decode_token(token2, db_session) is None
    assert decode_token(token3, db_session) is None


def test_session_expires_at(db_session, user_factory):
    """Test that sessions have correct expiration time."""
    user = user_factory()
    
    before = datetime.utcnow()
    token = create_access_token(user.id, db_session)
    after = datetime.utcnow()
    
    session = db_session.query(SessionModel).filter(SessionModel.user_id == user.id).first()
    expected_expire = timedelta(minutes=settings.access_token_expire_minutes)
    
    # Check expiration is within expected range
    assert session.expires_at > before + expected_expire
    assert session.expires_at < after + expected_expire + timedelta(seconds=5)
