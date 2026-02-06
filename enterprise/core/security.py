from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
import uuid

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from enterprise.core.config import get_settings
from enterprise.db.models import Session as SessionModel

settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)


def create_access_token(
    user_id: UUID,
    db: Session,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token and track session."""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    # Generate unique JWT ID for session tracking
    jti = str(uuid.uuid4())
    
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "jti": jti,
        "type": "access"
    }
    token = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    
    # Create session record for revocation tracking
    session = SessionModel(
        user_id=user_id,
        token_jti=jti,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expire,
    )
    db.add(session)
    db.commit()
    
    return token


def decode_token(token: str, db: Session) -> Optional[UUID]:
    """Decode and validate JWT token. Returns user_id if valid and not revoked."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        
        if user_id is None or jti is None:
            return None
        
        # Check if session is revoked
        session = db.query(SessionModel).filter(
            SessionModel.token_jti == jti,
            SessionModel.revoked_at.is_(None)
        ).first()
        
        if session is None:
            # Session was revoked or doesn't exist
            return None
        
        return UUID(user_id)
    except JWTError:
        return None


def revoke_session(jti: str, db: Session) -> bool:
    """Revoke a session by JWT ID."""
    session = db.query(SessionModel).filter(SessionModel.token_jti == jti).first()
    if session and session.revoked_at is None:
        session.revoked_at = datetime.utcnow()
        db.commit()
        return True
    return False


def revoke_user_sessions(user_id: UUID, db: Session, except_jti: Optional[str] = None) -> int:
    """Revoke all sessions for a user (except optionally one session)."""
    query = db.query(SessionModel).filter(
        SessionModel.user_id == user_id,
        SessionModel.revoked_at.is_(None)
    )
    
    if except_jti:
        query = query.filter(SessionModel.token_jti != except_jti)
    
    count = 0
    for session in query.all():
        session.revoked_at = datetime.utcnow()
        count += 1
    
    if count > 0:
        db.commit()
    
    return count
