from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from slugify import slugify
from jose import jwt
import uuid

from enterprise.api.deps import get_db, get_current_user
from enterprise.api.schemas.auth import UserCreate, Token, UserResponse
from enterprise.db.models import User, Organization, Role
from enterprise.db.models.session import Session as SessionModel
from enterprise.core.security import (
    verify_password, 
    get_password_hash, 
    create_access_token,
    revoke_session,
    revoke_user_sessions,
)
from enterprise.core.config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """Register a new user and create their organization."""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create organization
    org_slug = slugify(user_in.org_name)
    existing_org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if existing_org:
        # Add random suffix if slug exists
        org_slug = f"{org_slug}-{uuid.uuid4().hex[:6]}"
    
    org = Organization(
        name=user_in.org_name,
        slug=org_slug,
    )
    db.add(org)
    db.flush()
    
    # Create default admin role for org
    admin_role = Role(
        org_id=org.id,
        name="admin",
        permissions=["*"],  # Full permissions
        is_system=True,
    )
    db.add(admin_role)
    db.flush()
    
    # Create user
    user = User(
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
        name=user_in.name,
        org_id=org.id,
        role_id=admin_role.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login and get access token with session tracking."""
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create token with session tracking
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    access_token = create_access_token(
        user.id, 
        db,
        ip_address=ip_address,
        user_agent=user_agent
    )
    return Token(access_token=access_token)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return current_user


@router.get("/sessions")
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all active sessions for current user."""
    sessions = db.query(SessionModel).filter(
        SessionModel.user_id == current_user.id,
        SessionModel.revoked_at.is_(None)
    ).order_by(SessionModel.created_at.desc()).all()
    
    return [{
        "id": str(session.id),
        "jti": session.token_jti,
        "ip_address": str(session.ip_address) if session.ip_address else None,
        "user_agent": session.user_agent,
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
    } for session in sessions]


@router.post("/sessions/{session_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session_endpoint(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a specific session."""
    session = db.query(SessionModel).filter(
        SessionModel.id == session_id,
        SessionModel.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    revoke_session(session.token_jti, db)
    return None


@router.post("/sessions/revoke-all", status_code=status.HTTP_200_OK)
def revoke_all_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke all sessions except the current one."""
    # Get current session JTI from token
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    current_jti = None
    
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        current_jti = payload.get("jti")
    except:
        pass
    
    count = revoke_user_sessions(current_user.id, db, except_jti=current_jti)
    return {"revoked": count}
