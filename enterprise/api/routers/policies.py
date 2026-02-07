"""Policy management API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Policy, User
from enterprise.core.rbac import require_permission
from enterprise.core.policy.engine import DEFAULT_POLICIES

router = APIRouter(prefix="/policies", tags=["policies"])


# Schemas
class PolicyBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    rules: dict = Field(default_factory=dict)
    enabled: bool = True

class PolicyCreate(PolicyBase):
    pass

class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    rules: Optional[dict] = None
    enabled: Optional[bool] = None

class PolicyResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    description: Optional[str]
    rules: dict
    enabled: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PolicyListResponse(BaseModel):
    items: List[PolicyResponse]
    total: int


class PolicyTemplateResponse(BaseModel):
    name: str
    description: str
    rules: dict


# Endpoints
@router.get("", response_model=PolicyListResponse)
@require_permission("policies:list")
async def list_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    enabled_only: bool = False,
):
    """List all policies for the current organization."""
    query = db.query(Policy).filter(Policy.org_id == current_user.org_id)
    
    if enabled_only:
        query = query.filter(Policy.enabled == True)
    
    policies = query.order_by(Policy.name).all()
    
    return PolicyListResponse(
        items=[PolicyResponse.model_validate(p) for p in policies],
        total=len(policies),
    )


@router.get("/templates", response_model=List[PolicyTemplateResponse])
async def list_policy_templates(
    current_user: User = Depends(get_current_user),
):
    """List available policy templates."""
    return [
        PolicyTemplateResponse(
            name=template["name"],
            description=template["description"],
            rules=template["rules"],
        )
        for template in DEFAULT_POLICIES.values()
    ]


@router.get("/{policy_id}", response_model=PolicyResponse)
@require_permission("policies:read")
async def get_policy(
    policy_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific policy by ID."""
    policy = db.query(Policy).filter(
        and_(Policy.id == policy_id, Policy.org_id == current_user.org_id)
    ).first()
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    return PolicyResponse.model_validate(policy)


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
@require_permission("policies:create")
async def create_policy(
    policy_data: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new policy."""
    # Check for duplicate name
    existing = db.query(Policy).filter(
        and_(Policy.org_id == current_user.org_id, Policy.name == policy_data.name)
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Policy with this name already exists")
    
    policy = Policy(
        org_id=current_user.org_id,
        name=policy_data.name,
        description=policy_data.description,
        rules=policy_data.rules,
        enabled=policy_data.enabled,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    
    return PolicyResponse.model_validate(policy)


@router.post("/from-template/{template_key}", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
@require_permission("policies:create")
async def create_policy_from_template(
    template_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name_suffix: str = Query("", description="Suffix to add to template name"),
):
    """Create a new policy from a template."""
    if template_key not in DEFAULT_POLICIES:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_key}")
    
    template = DEFAULT_POLICIES[template_key]
    template_name = template["name"]
    policy_name = template_name + name_suffix if name_suffix else template_name
    
    # Check for duplicate name
    existing = db.query(Policy).filter(
        and_(Policy.org_id == current_user.org_id, Policy.name == policy_name)
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Policy with this name already exists")
    
    policy = Policy(
        org_id=current_user.org_id,
        name=policy_name,
        description=template["description"],
        rules=template["rules"],
        enabled=True,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    
    return PolicyResponse.model_validate(policy)


@router.patch("/{policy_id}", response_model=PolicyResponse)
@require_permission("policies:update")
async def update_policy(
    policy_id: UUID,
    policy_data: PolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a policy."""
    policy = db.query(Policy).filter(
        and_(Policy.id == policy_id, Policy.org_id == current_user.org_id)
    ).first()
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    # Update fields
    update_data = policy_data.model_dump(exclude_unset=True)
    
    if "name" in update_data:
        # Check for duplicate name
        existing = db.query(Policy).filter(
            and_(
                Policy.org_id == current_user.org_id,
                Policy.name == update_data["name"],
                Policy.id != policy_id,
            )
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Policy with this name already exists")
    
    for field, value in update_data.items():
        setattr(policy, field, value)
    
    db.commit()
    db.refresh(policy)
    
    return PolicyResponse.model_validate(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("policies:delete")
async def delete_policy(
    policy_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a policy."""
    policy = db.query(Policy).filter(
        and_(Policy.id == policy_id, Policy.org_id == current_user.org_id)
    ).first()
    
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    db.delete(policy)
    db.commit()
    
    return None
