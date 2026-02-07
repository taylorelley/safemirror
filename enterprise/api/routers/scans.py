"""Scan management API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import Scan, User, Package
from enterprise.core.rbac import require_permission
from enterprise.services.scanner_integration import ScannerIntegrationService

router = APIRouter(prefix="/scans", tags=["scans"])


# Schemas
class ScanCreate(BaseModel):
    package_id: Optional[UUID] = None
    package_name: str
    package_version: Optional[str] = None
    package_type: str
    policy_id: Optional[UUID] = None


class ScanExecuteRequest(BaseModel):
    package_path: str = Field(..., description="Path to the package file to scan")
    mirror_id: Optional[UUID] = None
    policy_id: Optional[UUID] = None
    auto_approve: bool = True
    async_mode: bool = False


class ScanDirectoryRequest(BaseModel):
    directory_path: str = Field(..., description="Path to directory containing packages")
    mirror_id: Optional[UUID] = None
    policy_id: Optional[UUID] = None
    auto_approve: bool = True
    package_types: Optional[List[str]] = None


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


class ScanResultResponse(BaseModel):
    package: dict
    scan: dict
    approval: dict


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    per_page: int


class DirectoryScanResponse(BaseModel):
    total: int
    successful: int
    failed: int
    auto_approved: int
    pending_review: int
    rejected: int
    task_id: Optional[str] = None
    packages: Optional[List[dict]] = None
    errors: Optional[List[dict]] = None


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
    """Create a new scan request (pending state)."""
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


@router.post("/execute", response_model=ScanResultResponse)
@require_permission("scans:execute")
async def execute_scan(
    request: ScanExecuteRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Scan a package file and ingest results.
    
    This endpoint:
    1. Scans the package for vulnerabilities
    2. Creates/updates Package record
    3. Creates Scan record with results
    4. Evaluates policy and creates ApprovalRequest
    5. Auto-approves or auto-rejects based on policy
    
    Set async_mode=true to run scan in background (returns task_id).
    """
    if request.async_mode:
        # Queue async scan
        from enterprise.workers.scanner_tasks import scan_package
        
        task = scan_package.delay(
            package_path=request.package_path,
            org_id=str(current_user.org_id),
            user_id=str(current_user.id),
            mirror_id=str(request.mirror_id) if request.mirror_id else None,
            policy_id=str(request.policy_id) if request.policy_id else None,
            auto_approve=request.auto_approve,
        )
        
        return ScanResultResponse(
            package={"task_id": task.id, "status": "queued"},
            scan={"status": "pending"},
            approval={"state": "pending"},
        )
    
    # Synchronous scan
    try:
        service = ScannerIntegrationService(
            db=db,
            org_id=current_user.org_id,
            user_id=current_user.id,
        )
        
        result = service.scan_and_ingest_package(
            package_path=request.package_path,
            mirror_id=request.mirror_id,
            policy_id=request.policy_id,
            auto_approve=request.auto_approve,
        )
        
        return ScanResultResponse(**result)
        
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/directory", response_model=DirectoryScanResponse)
@require_permission("scans:execute")
async def scan_directory(
    request: ScanDirectoryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Scan all packages in a directory.
    
    For large directories, this runs asynchronously and returns a task_id.
    """
    from enterprise.workers.scanner_tasks import scan_directory as scan_dir_task
    
    # Always run directory scans async
    task = scan_dir_task.delay(
        directory_path=request.directory_path,
        org_id=str(current_user.org_id),
        user_id=str(current_user.id),
        mirror_id=str(request.mirror_id) if request.mirror_id else None,
        policy_id=str(request.policy_id) if request.policy_id else None,
        auto_approve=request.auto_approve,
        package_types=request.package_types,
    )
    
    return DirectoryScanResponse(
        total=0,
        successful=0,
        failed=0,
        auto_approved=0,
        pending_review=0,
        rejected=0,
        task_id=task.id,
    )


@router.post("/{scan_id}/execute", response_model=ScanResponse)
@require_permission("scans:execute")
async def execute_pending_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute/start a pending scan (legacy endpoint)."""
    scan = db.query(Scan).filter(
        and_(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in ("pending", "failed"):
        raise HTTPException(status_code=400, detail=f"Cannot execute scan in status: {scan.status}")
    
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    
    # The actual scan execution is now handled by the scanner integration service
    # Queue the scan task
    from enterprise.workers.scanner_tasks import rescan_package
    
    # Look up the package for this scan
    package = db.query(Package).filter(
        and_(
            Package.org_id == current_user.org_id,
            Package.name == scan.package_name,
            Package.version == scan.package_version,
        )
    ).first()
    
    if package:
        rescan_package.delay(
            package_id=str(package.id),
            org_id=str(current_user.org_id),
            user_id=str(current_user.id),
            policy_id=str(scan.policy_id) if scan.policy_id else None,
        )
    
    db.commit()
    db.refresh(scan)
    
    return ScanResponse.model_validate(scan)


@router.post("/rescan/{package_id}", response_model=ScanResultResponse)
@require_permission("scans:execute")
async def rescan_package_endpoint(
    package_id: UUID,
    policy_id: Optional[UUID] = None,
    async_mode: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Re-scan an existing package."""
    package = db.query(Package).filter(
        and_(Package.id == package_id, Package.org_id == current_user.org_id)
    ).first()
    
    if not package:
        raise HTTPException(status_code=404, detail="Package not found")
    
    if async_mode:
        from enterprise.workers.scanner_tasks import rescan_package
        
        task = rescan_package.delay(
            package_id=str(package_id),
            org_id=str(current_user.org_id),
            user_id=str(current_user.id),
            policy_id=str(policy_id) if policy_id else None,
        )
        
        return ScanResultResponse(
            package={"id": str(package_id), "task_id": task.id},
            scan={"status": "pending"},
            approval={"state": "pending"},
        )
    
    service = ScannerIntegrationService(
        db=db,
        org_id=current_user.org_id,
        user_id=current_user.id,
    )
    
    result = service.rescan_package(
        package_id=package_id,
        policy_id=policy_id,
    )
    
    return ScanResultResponse(**result)


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
