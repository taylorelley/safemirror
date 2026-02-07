"""Mirror role assignment API endpoints.

Allows assigning users specific roles on individual mirrors.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Mirror, MirrorRoleAssignment, User, Role
from enterprise.core.rbac import require_permission

router = APIRouter(prefix="/mirrors/{mirror_id}/assignments", tags=["mirror-assignments"])


# Schemas
class MirrorRoleAssignmentCreate(BaseModel):
    user_id: UUID
    role_id: UUID
    expires_at: Optional[datetime] = None


class MirrorRoleAssignmentResponse(BaseModel):
    id: UUID
    mirror_id: UUID
    user_id: UUID
    role_id: UUID
    assigned_by: Optional[UUID]
    created_at: datetime
    expires_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class MirrorRoleAssignmentWithDetails(MirrorRoleAssignmentResponse):
    user_email: Optional[str] = None
    role_name: Optional[str] = None


# Endpoints
@router.get("", response_model=List[MirrorRoleAssignmentWithDetails])
@require_permission("roles:read")
async def list_mirror_assignments(
    mirror_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all role assignments for a mirror."""
    # Verify mirror exists and user has access
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    assignments = db.query(MirrorRoleAssignment).filter(
        MirrorRoleAssignment.mirror_id == mirror_id
    ).all()
    
    result = []
    for a in assignments:
        user = db.query(User).filter(User.id == a.user_id).first()
        role = db.query(Role).filter(Role.id == a.role_id).first()
        
        result.append(MirrorRoleAssignmentWithDetails(
            id=a.id,
            mirror_id=a.mirror_id,
            user_id=a.user_id,
            role_id=a.role_id,
            assigned_by=a.assigned_by,
            created_at=a.created_at,
            expires_at=a.expires_at,
            user_email=user.email if user else None,
            role_name=role.name if role else None,
        ))
    
    return result


@router.post("", response_model=MirrorRoleAssignmentResponse, status_code=status.HTTP_201_CREATED)
@require_permission("roles:assign")
async def create_mirror_assignment(
    mirror_id: UUID,
    assignment_data: MirrorRoleAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Assign a role to a user on a specific mirror."""
    # Verify mirror exists
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    # Verify user exists and is in same org
    target_user = db.query(User).filter(
        and_(User.id == assignment_data.user_id, User.org_id == current_user.org_id)
    ).first()
    
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify role exists and is in same org
    role = db.query(Role).filter(
        and_(Role.id == assignment_data.role_id, Role.org_id == current_user.org_id)
    ).first()
    
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    # Check for existing assignment (unique constraint)
    existing = db.query(MirrorRoleAssignment).filter(
        and_(
            MirrorRoleAssignment.mirror_id == mirror_id,
            MirrorRoleAssignment.user_id == assignment_data.user_id,
        )
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400, 
            detail="User already has a role assignment on this mirror. Delete the existing one first."
        )
    
    assignment = MirrorRoleAssignment(
        mirror_id=mirror_id,
        user_id=assignment_data.user_id,
        role_id=assignment_data.role_id,
        assigned_by=current_user.id,
        expires_at=assignment_data.expires_at,
    )
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    
    return MirrorRoleAssignmentResponse.model_validate(assignment)


@router.delete("/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("roles:assign")
async def delete_mirror_assignment(
    mirror_id: UUID,
    assignment_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove a role assignment from a mirror."""
    # Verify mirror exists
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    assignment = db.query(MirrorRoleAssignment).filter(
        and_(
            MirrorRoleAssignment.id == assignment_id,
            MirrorRoleAssignment.mirror_id == mirror_id,
        )
    ).first()
    
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    
    db.delete(assignment)
    db.commit()
    
    return None


@router.put("/{assignment_id}", response_model=MirrorRoleAssignmentResponse)
@require_permission("roles:assign")
async def update_mirror_assignment(
    mirror_id: UUID,
    assignment_id: UUID,
    assignment_data: MirrorRoleAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a role assignment (change role or expiration)."""
    # Verify mirror exists
    mirror = db.query(Mirror).filter(
        and_(Mirror.id == mirror_id, Mirror.org_id == current_user.org_id)
    ).first()
    
    if not mirror:
        raise HTTPException(status_code=404, detail="Mirror not found")
    
    assignment = db.query(MirrorRoleAssignment).filter(
        and_(
            MirrorRoleAssignment.id == assignment_id,
            MirrorRoleAssignment.mirror_id == mirror_id,
        )
    ).first()
    
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")
    
    # Verify new role exists
    role = db.query(Role).filter(
        and_(Role.id == assignment_data.role_id, Role.org_id == current_user.org_id)
    ).first()
    
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    
    assignment.role_id = assignment_data.role_id
    assignment.expires_at = assignment_data.expires_at
    
    db.commit()
    db.refresh(assignment)
    
    return MirrorRoleAssignmentResponse.model_validate(assignment)
