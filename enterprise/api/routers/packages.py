"""Package management API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Package, User, Mirror
from enterprise.core.rbac import require_permission

router = APIRouter(prefix="/packages", tags=["packages"])


# Schemas
class PackageResponse(BaseModel):
    id: UUID
    org_id: UUID
    mirror_id: Optional[UUID]
    name: str
    version: str
    package_type: str
    architecture: Optional[str]
    maintainer: Optional[str]
    description: Optional[str]
    license: Optional[str]
    file_size: Optional[int]
    scan_status: Optional[str]
    approval_status: str
    approved_at: Optional[datetime]
    vulnerabilities: Optional[dict]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PackageListResponse(BaseModel):
    items: List[PackageResponse]
    total: int
    page: int
    per_page: int


class PackageApprovalRequest(BaseModel):
    comment: Optional[str] = None


# Endpoints
@router.get("", response_model=PackageListResponse)
@require_permission("packages:list")
async def list_packages(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    mirror_id: Optional[UUID] = None,
    package_type: Optional[str] = None,
    approval_status: Optional[str] = None,
    scan_status: Optional[str] = None,
):
    """List all packages for the current organization."""
    query = db.query(Package).filter(Package.org_id == current_user.org_id)
    
    if search:
        query = query.filter(
            or_(
                Package.name.ilike(f"%{search}%"),
                Package.description.ilike(f"%{search}%"),
            )
        )
    
    if mirror_id:
        query = query.filter(Package.mirror_id == mirror_id)
    
    if package_type:
        query = query.filter(Package.package_type == package_type)
    
    if approval_status:
        query = query.filter(Package.approval_status == approval_status)
    
    if scan_status:
        query = query.filter(Package.scan_status == scan_status)
    
    total = query.count()
    packages = query.order_by(Package.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    return PackageListResponse(
        items=[PackageResponse.model_validate(p) for p in packages],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{package_id}", response_model=PackageResponse)
@require_permission("packages:read")
async def get_package(
    package_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific package by ID."""
    package = db.query(Package).filter(
        and_(Package.id == package_id, Package.org_id == current_user.org_id)
    ).first()
    
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    return PackageResponse.model_validate(package)


@router.post("/{package_id}/approve", response_model=PackageResponse)
@require_permission("packages:approve")
async def approve_package(
    package_id: UUID,
    approval_data: PackageApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Approve a package."""
    package = db.query(Package).filter(
        and_(Package.id == package_id, Package.org_id == current_user.org_id)
    ).first()
    
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    if package.approval_status == "approved":
        raise HTTPException(status_code=400, detail="Package is already approved")
    
    package.approval_status = "approved"
    package.approved_at = datetime.utcnow()
    package.approved_by = current_user.id
    
    db.commit()
    db.refresh(package)
    
    return PackageResponse.model_validate(package)


@router.post("/{package_id}/reject", response_model=PackageResponse)
@require_permission("packages:reject")
async def reject_package(
    package_id: UUID,
    approval_data: PackageApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reject a package."""
    package = db.query(Package).filter(
        and_(Package.id == package_id, Package.org_id == current_user.org_id)
    ).first()
    
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    if package.approval_status == "rejected":
        raise HTTPException(status_code=400, detail="Package is already rejected")
    
    package.approval_status = "rejected"
    
    db.commit()
    db.refresh(package)
    
    return PackageResponse.model_validate(package)


@router.delete("/{package_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("packages:delete")
async def delete_package(
    package_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a package."""
    package = db.query(Package).filter(
        and_(Package.id == package_id, Package.org_id == current_user.org_id)
    ).first()
    
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    db.delete(package)
    db.commit()
    
    return None
