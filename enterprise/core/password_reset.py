"""Password reset functionality."""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from enterprise.db.models.password_reset_token import PasswordResetToken
from enterprise.db.models import User


def generate_reset_token() -> tuple[str, str]:
    """Generate a password reset token.
    
    Returns:
        (token, token_hash) tuple
        - token: The actual token to send to user
        - token_hash: Hash to store in database
    """
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash


def create_reset_token(
    user_id: UUID,
    db: Session,
    expires_in_hours: int = 1
) -> tuple[PasswordResetToken, str]:
    """Create a password reset token for a user.
    
    Returns:
        (token_model, plain_token) tuple
    """
    # Invalidate any existing unused tokens for this user
    existing_tokens = db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user_id,
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).all()
    
    for token in existing_tokens:
        token.is_used = True
    
    # Generate new token
    plain_token, token_hash = generate_reset_token()
    expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
    
    reset_token = PasswordResetToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    
    db.add(reset_token)
    db.commit()
    db.refresh(reset_token)
    
    return reset_token, plain_token


def verify_reset_token(token: str, db: Session) -> Optional[UUID]:
    """Verify a password reset token and return the user_id if valid.
    
    Returns:
        user_id if token is valid, None otherwise
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    
    if not reset_token:
        return None
    
    return reset_token.user_id


def use_reset_token(token: str, new_password_hash: str, db: Session) -> bool:
    """Use a password reset token to change a user's password.
    
    Returns:
        True if successful, False otherwise
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    
    if not reset_token:
        return False
    
    # Update user password
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        return False
    
    user.password_hash = new_password_hash
    
    # Mark token as used
    reset_token.is_used = True
    reset_token.used_at = datetime.utcnow()
    
    db.commit()
    return True


def cleanup_expired_tokens(db: Session) -> int:
    """Delete expired password reset tokens.
    
    Returns:
        Number of tokens deleted
    """
    count = db.query(PasswordResetToken).filter(
        PasswordResetToken.expires_at < datetime.utcnow()
    ).delete()
    
    db.commit()
    return count
