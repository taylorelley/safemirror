from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from slugify import slugify
import uuid

from enterprise.api.deps import get_db, get_current_user
from enterprise.api.schemas.auth import UserCreate, Token, UserResponse
from enterprise.db.models import User, Organization, Role
from enterprise.core.security import verify_password, get_password_hash, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


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
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login and get access token."""
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
    
    access_token = create_access_token(user.id)
    return Token(access_token=access_token)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return current_user
