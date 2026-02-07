"""Role management API endpoints."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Role, User
from enterprise.core.rbac import require_permission, has_permission
from enterprise.core.rbac.permissions import get_all_permissions
from enterprise.api.middleware.audit import AuditLogger

router = APIRouter(prefix="/roles", tags=["roles"])


# Schemas
class RoleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    permissions: List[str] = Field(default_factory=list)

class RoleCreate(RoleBase):
    pass

class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    permissions: Optional[List[str]] = None

class RoleResponse(RoleBase):
    id: UUID
    org_id: UUID
    is_system: bool
    created_at: str
    
    class Config:
        from_attributes = True

class PermissionInfo(BaseModel):
    permission: str
    resource: str
    action: str


# Endpoints
@router.get("", response_model=List[RoleResponse])
@require_permission("roles:list")
async def list_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    include_system: bool = Query(True, description="Include system roles"),
):
    """List all roles for the current organization."""
    query = db.query(Role).filter(Role.org_id == current_user.org_id)
    
    if not include_system:
        query = query.filter(Role.is_system == False)
    
    roles = query.order_by(Role.name).all()
    
    return [
        RoleResponse(
            id=r.id,
            org_id=r.org_id,
            name=r.name,
            permissions=r.permissions or [],
            is_system=r.is_system,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in roles
    ]


@router.get("/permissions", response_model=List[PermissionInfo])
async def list_all_permissions(
    current_user: User = Depends(get_current_user),
):
    """List all available permissions."""
    permissions = get_all_permissions()
    return [
        PermissionInfo(
            permission=p,
            resource=p.split(":")[0],
            action=p.split(":")[1],
        )
        for p in sorted(permissions)
    ]


@router.get("/{role_id}", response_model=RoleResponse)
@require_permission("roles:read")
async def get_role(
    role_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific role by ID."""
    role = db.query(Role).filter(
        and_(Role.id == role_id, Role.org_id == current_user.org_id)
    ).first()
    
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    return RoleResponse(
        id=role.id,
        org_id=role.org_id,
        name=role.name,
        permissions=role.permissions or [],
        is_system=role.is_system,
        created_at=role.created_at.isoformat() if role.created_at else "",
    )


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
@require_permission("roles:create")
async def create_role(
    role_data: RoleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new custom role."""
    from fastapi import Request
    
    # Check for duplicate name
    existing = db.query(Role).filter(
        and_(Role.org_id == current_user.org_id, Role.name == role_data.name)
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Role with this name already exists")
    
    # Validate permissions
    valid_permissions = set(get_all_permissions())
    for perm in role_data.permissions:
        if perm not in valid_permissions and perm != "*:*":
            raise HTTPException(status_code=400, detail=f"Invalid permission: {perm}")
    
    role = Role(
        org_id=current_user.org_id,
        name=role_data.name,
        permissions=role_data.permissions,
        is_system=False,
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    
    return RoleResponse(
        id=role.id,
        org_id=role.org_id,
        name=role.name,
        permissions=role.permissions or [],
        is_system=role.is_system,
        created_at=role.created_at.isoformat() if role.created_at else "",
    )


@router.patch("/{role_id}", response_model=RoleResponse)
@require_permission("roles:update")
async def update_role(
    role_id: UUID,
    role_data: RoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a role. System roles cannot be modified."""
    role = db.query(Role).filter(
        and_(Role.id == role_id, Role.org_id == current_user.org_id)
    ).first()
    
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    if role.is_system:
        raise HTTPException(status_code=403, detail="System roles cannot be modified")
    
    # Validate permissions if provided
    if role_data.permissions is not None:
        valid_permissions = set(get_all_permissions())
        for perm in role_data.permissions:
            if perm not in valid_permissions and perm != "*:*":
                raise HTTPException(status_code=400, detail=f"Invalid permission: {perm}")
        role.permissions = role_data.permissions
    
    if role_data.name is not None:
        # Check for duplicate name
        existing = db.query(Role).filter(
            and_(
                Role.org_id == current_user.org_id,
                Role.name == role_data.name,
                Role.id != role_id,
            )
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Role with this name already exists")
        role.name = role_data.name
    
    db.commit()
    db.refresh(role)
    
    return RoleResponse(
        id=role.id,
        org_id=role.org_id,
        name=role.name,
        permissions=role.permissions or [],
        is_system=role.is_system,
        created_at=role.created_at.isoformat() if role.created_at else "",
    )


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("roles:delete")
async def delete_role(
    role_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a role. System roles cannot be deleted."""
    role = db.query(Role).filter(
        and_(Role.id == role_id, Role.org_id == current_user.org_id)
    ).first()
    
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    if role.is_system:
        raise HTTPException(status_code=403, detail="System roles cannot be deleted")
    
    # Check if role is in use
    users_with_role = db.query(User).filter(User.role_id == role_id).count()
    if users_with_role > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete role: {users_with_role} users are assigned to this role"
        )
    
    db.delete(role)
    db.commit()
    
    return None
