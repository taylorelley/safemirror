"""API key management endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from enterprise.api.deps import get_db, get_current_user
from enterprise.core.api_key import (
    create_api_key,
    revoke_api_key,
    list_user_api_keys,
)
from enterprise.db.models import User


router = APIRouter(prefix="/api-keys", tags=["api-keys"])


# Schemas
class APIKeyCreate(BaseModel):
    name: str = Field(..., description="Descriptive name for the API key")
    scopes: List[str] = Field(default=["scans:read"], description="List of permission scopes")
    expires_in_days: Optional[int] = Field(None, description="Expiration in days (None = no expiration)")


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    created_at: str
    last_used_at: Optional[str]
    expires_at: Optional[str]
    
    class Config:
        from_attributes = True


class APIKeyCreateResponse(APIKeyResponse):
    key: str = Field(..., description="Full API key - save this, it won't be shown again!")


@router.post("", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
def create_api_key_endpoint(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new API key for the current user."""
    # Validate scopes (basic validation - extend as needed)
    valid_scopes = ["scans:read", "scans:write", "policies:read", "policies:write", "admin"]
    for scope in key_data.scopes:
        if scope not in valid_scopes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scope: {scope}"
            )
    
    api_key, full_key = create_api_key(
        user_id=current_user.id,
        org_id=current_user.org_id,
        name=key_data.name,
        scopes=key_data.scopes,
        db=db,
        expires_in_days=key_data.expires_in_days
    )
    
    return APIKeyCreateResponse(
        id=str(api_key.id),
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        is_active=api_key.is_active,
        created_at=api_key.created_at.isoformat(),
        last_used_at=api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        key=full_key
    )


@router.get("", response_model=List[APIKeyResponse])
def list_api_keys(
    include_inactive: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all API keys for the current user."""
    keys = list_user_api_keys(current_user.id, db, include_inactive=include_inactive)
    
    return [
        APIKeyResponse(
            id=str(key.id),
            name=key.name,
            key_prefix=key.key_prefix,
            scopes=key.scopes,
            is_active=key.is_active,
            created_at=key.created_at.isoformat(),
            last_used_at=key.last_used_at.isoformat() if key.last_used_at else None,
            expires_at=key.expires_at.isoformat() if key.expires_at else None,
        )
        for key in keys
    ]


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key_endpoint(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke an API key."""
    from uuid import UUID
    
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key ID format"
        )
    
    # Verify the key belongs to the current user
    from enterprise.db.models.api_key import APIKey
    api_key = db.query(APIKey).filter(
        APIKey.id == key_uuid,
        APIKey.user_id == current_user.id
    ).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    revoke_api_key(key_uuid, db)
    return None
