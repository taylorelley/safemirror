"""Mirror management API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Mirror, User, Policy
from enterprise.core.rbac import require_permission
from enterprise.api.middleware.audit import AuditLogger

router = APIRouter(prefix="/mirrors", tags=["mirrors"])


# Schemas
class MirrorBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern="^[a-z0-9-]+$")
    description: Optional[str] = None
    mirror_type: str = Field(..., description="Mirror type: apt, yum, npm, pypi, etc.")
    upstream_url: str = Field(..., description="Upstream mirror URL")
    config: dict = Field(default_factory=dict)
    auto_approve: bool = False
    policy_id: Optional[UUID] = None

class MirrorCreate(MirrorBase):
    pass

class MirrorUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    upstream_url: Optional[str] = None
    config: Optional[dict] = None
    is_active: Optional[bool] = None
    auto_approve: Optional[bool] = None
    policy_id: Optional[UUID] = None

class MirrorResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    slug: str
    description: Optional[str]
    mirror_type: str
    upstream_url: str
    config: dict
    is_active: bool
    is_syncing: bool
    auto_approve: bool
    policy_id: Optional[UUID]
    last_sync_at: Optional[datetime]
    last_sync_error: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class MirrorListResponse(BaseModel):
    items: List[MirrorResponse]
    total: int
    page: int
    per_page: int


# Endpoints
@router.get("", response_model=MirrorListResponse)
@require_permission("mirrors:list")
async def list_mirrors(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    mirror_type: Optional[str] = None,
    is_active: Optional[bool] = None,
):
    """List all mirrors for the current organization."""
    query = db.query(Mirror).filter(Mirror.org_id == current_user.org_id)
    
    if search:
        query = query.filter(
            or_(
                Mirror.name.ilike(f"%{search}%"),
                Mirror.slug.ilike(f"%{search}%"),
            )
        )
    
    if mirror_type:
        query = query.filter(Mirror.mirror_type == mirror_type)
    
    if is_active is not None:
        query = query.filter(Mirror.is_active == is_active)
    
    total = query.count()
    mirrors = query.order_by(Mirror.name).offset((page - 1) * per_page).limit(per_page).all()
    
    return MirrorListResponse(
        items=[MirrorResponse.model_validate(m) for m in mirrors],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{mirror_id}", response_model=MirrorResponse)
@require_permission("mirrors:read")
async def get_mirror(
    mirror_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific mirror by ID."""
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    return MirrorResponse.model_validate(mirror)


@router.post("", response_model=MirrorResponse, status_code=status.HTTP_201_CREATED)
@require_permission("mirrors:create")
async def create_mirror(
    mirror_data: MirrorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new mirror."""
    # Check for duplicate slug
    existing = db.query(Mirror).filter(
        and_(Mirror.org_id == current_user.org_id, Mirror.slug == mirror_data.slug)
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Mirror with this slug already exists")
    
    # Validate policy if provided
    if mirror_data.policy_id:
        policy = db.query(Policy).filter(
            and_(Policy.id == mirror_data.policy_id, Policy.org_id == current_user.org_id)
        ).first()
        if not policy:
            raise HTTPException(status_code=400, detail="Policy not found")
    
    mirror = Mirror(
        org_id=current_user.org_id,
        **mirror_data.model_dump(),
    )
    db.add(mirror)
    db.commit()
    db.refresh(mirror)
    
    return MirrorResponse.model_validate(mirror)


@router.patch("/{mirror_id}", response_model=MirrorResponse)
@require_permission("mirrors:update")
async def update_mirror(
    mirror_id: UUID,
    mirror_data: MirrorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a mirror."""
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    # Validate policy if provided
    if mirror_data.policy_id:
        policy = db.query(Policy).filter(
            and_(Policy.id == mirror_data.policy_id, Policy.org_id == current_user.org_id)
        ).first()
        if not policy:
            raise HTTPException(status_code=400, detail="Policy not found")
    
    # Update fields
    update_data = mirror_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(mirror, field, value)
    
    db.commit()
    db.refresh(mirror)
    
    return MirrorResponse.model_validate(mirror)


@router.delete("/{mirror_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("mirrors:delete")
async def delete_mirror(
    mirror_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a mirror."""
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    db.delete(mirror)
    db.commit()
    
    return None


@router.post("/{mirror_id}/sync", status_code=status.HTTP_202_ACCEPTED)
@require_permission("mirrors:configure")
async def trigger_sync(
    mirror_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger a sync for a mirror."""
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    if mirror.is_syncing:
        raise HTTPException(status_code=409, detail="Mirror is already syncing")
    
    # TODO: Queue sync job
    mirror.is_syncing = True
    db.commit()
    
    return {"message": "Sync started", "mirror_id": str(mirror_id)}
