from typing import Generator, Union
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.orm import Session

from enterprise.db.session import SessionLocal
from enterprise.db.models import User
from enterprise.core.security import decode_token
from enterprise.core.api_key import verify_api_key

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_db() -> Generator:
    """Database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    api_key: str = Depends(api_key_header)
) -> User:
    """Get current authenticated user from JWT token or API key."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Try JWT token first
    if token:
        user_id = decode_token(token, db)
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
            if user and user.is_active:
                return user
    
    # Try API key authentication
    if api_key:
        api_key_obj = verify_api_key(api_key, db)
        if api_key_obj:
            user = db.query(User).filter(User.id == api_key_obj.user_id).first()
            if user and user.is_active:
                return user
    
    raise credentials_exception


def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Alias for get_current_user (already checks is_active)."""
    return current_user
