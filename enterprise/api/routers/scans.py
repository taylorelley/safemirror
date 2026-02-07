"""Scan management API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Scan, User, Package
from enterprise.core.rbac import require_permission

router = APIRouter(prefix="/scans", tags=["scans"])


# Schemas
class ScanCreate(BaseModel):
    package_id: Optional[UUID] = None
    package_name: str
    package_version: Optional[str] = None
    package_type: str
    policy_id: Optional[UUID] = None

class ScanResponse(BaseModel):
    id: UUID
    org_id: UUID
    user_id: UUID
    policy_id: Optional[UUID]
    package_type: str
    package_name: str
    package_version: Optional[str]
    status: str
    results: Optional[dict]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    per_page: int


# Endpoints
@router.get("", response_model=ScanListResponse)
@require_permission("scans:list")
async def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    package_type: Optional[str] = None,
    package_name: Optional[str] = None,
):
    """List all scans for the current organization."""
    query = db.query(Scan).filter(Scan.org_id == current_user.org_id)
    
    if status:
        query = query.filter(Scan.status == status)
    
    if package_type:
        query = query.filter(Scan.package_type == package_type)
    
    if package_name:
        query = query.filter(Scan.package_name.ilike(f"%{package_name}%"))
    
    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
@require_permission("scans:read")
async def get_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific scan by ID."""
    scan = db.query(Scan).filter(
        and_(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResponse.model_validate(scan)


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@require_permission("scans:create")
async def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new scan request."""
    scan = Scan(
        org_id=current_user.org_id,
        user_id=current_user.id,
        package_name=scan_data.package_name,
        package_version=scan_data.package_version,
        package_type=scan_data.package_type,
        policy_id=scan_data.policy_id,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/execute", response_model=ScanResponse)
@require_permission("scans:execute")
async def execute_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute/start a pending scan."""
    scan = db.query(Scan).filter(
        and_(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in ("pending", "failed"):
        raise HTTPException(status_code=400, detail=f"Cannot execute scan in status: {scan.status}")
    
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    
    # TODO: Queue actual scan job
    
    db.commit()
    db.refresh(scan)
    
    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("scans:delete")
async def delete_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scan."""
    scan = db.query(Scan).filter(
        and_(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    
    return None
