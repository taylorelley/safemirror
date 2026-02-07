"""Approval workflow API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import ApprovalRequest, ApprovalHistory, User
from enterprise.core.rbac import require_permission
from enterprise.core.approval import ApprovalService, ApprovalTransition, ApprovalState

router = APIRouter(prefix="/approvals", tags=["approvals"])


# Schemas
class ApprovalRequestResponse(BaseModel):
    id: UUID
    org_id: UUID
    package_id: Optional[UUID]
    package_name: str
    package_version: str
    package_type: str
    mirror_id: Optional[UUID]
    scan_id: Optional[UUID]
    state: str
    requested_by: Optional[UUID]
    approved_by: Optional[UUID]
    approved_at: Optional[datetime]
    rejected_by: Optional[UUID]
    rejected_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ApprovalHistoryResponse(BaseModel):
    id: UUID
    from_state: str
    to_state: str
    transition: str
    user_id: Optional[UUID]
    comment: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class ApprovalListResponse(BaseModel):
    items: List[ApprovalRequestResponse]
    total: int
    page: int
    per_page: int


class ApprovalAction(BaseModel):
    comment: Optional[str] = None


class BatchApprovalRequest(BaseModel):
    request_ids: List[UUID]
    comment: Optional[str] = None


class BatchApprovalResponse(BaseModel):
    approved: List[str] = []
    rejected: List[str] = []
    failed: List[dict] = []


# Endpoints
@router.get("", response_model=ApprovalListResponse)
@require_permission("approvals:list")
async def list_approvals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    state: Optional[str] = None,
    mirror_id: Optional[UUID] = None,
    package_type: Optional[str] = None,
    pending_only: bool = False,
):
    """List approval requests for the current organization."""
    query = db.query(ApprovalRequest).filter(ApprovalRequest.org_id == current_user.org_id)
    
    if state:
        query = query.filter(ApprovalRequest.state == state)
    
    if mirror_id:
        query = query.filter(ApprovalRequest.mirror_id == mirror_id)
    
    if package_type:
        query = query.filter(ApprovalRequest.package_type == package_type)
    
    if pending_only:
        query = query.filter(ApprovalRequest.state == "needs_review")
    
    total = query.count()
    requests = query.order_by(ApprovalRequest.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    return ApprovalListResponse(
        items=[ApprovalRequestResponse.model_validate(r) for r in requests],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/pending", response_model=ApprovalListResponse)
@require_permission("approvals:list")
async def list_pending_approvals(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    mirror_id: Optional[UUID] = None,
):
    """List pending approval requests awaiting review."""
    query = db.query(ApprovalRequest).filter(
        and_(
            ApprovalRequest.org_id == current_user.org_id,
            ApprovalRequest.state == "needs_review",
        )
    )
    
    if mirror_id:
        query = query.filter(ApprovalRequest.mirror_id == mirror_id)
    
    total = query.count()
    requests = query.order_by(ApprovalRequest.created_at.asc()).offset((page - 1) * per_page).limit(per_page).all()
    
    return ApprovalListResponse(
        items=[ApprovalRequestResponse.model_validate(r) for r in requests],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{request_id}", response_model=ApprovalRequestResponse)
@require_permission("approvals:read")
async def get_approval(
    request_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific approval request."""
    request = db.query(ApprovalRequest).filter(
        and_(ApprovalRequest.id == request_id, ApprovalRequest.org_id == current_user.org_id)
    ).first()
    
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    return ApprovalRequestResponse.model_validate(request)


@router.get("/{request_id}/history", response_model=List[ApprovalHistoryResponse])
@require_permission("approvals:read")
async def get_approval_history(
    request_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the state transition history for an approval request."""
    request = db.query(ApprovalRequest).filter(
        and_(ApprovalRequest.id == request_id, ApprovalRequest.org_id == current_user.org_id)
    ).first()
    
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    history = db.query(ApprovalHistory).filter(
        ApprovalHistory.request_id == request_id
    ).order_by(ApprovalHistory.created_at.asc()).all()
    
    return [ApprovalHistoryResponse.model_validate(h) for h in history]


@router.post("/{request_id}/approve", response_model=ApprovalRequestResponse)
@require_permission("approvals:approve")
async def approve_request(
    request_id: UUID,
    action: ApprovalAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Approve a pending approval request."""
    service = ApprovalService(db, current_user.org_id)
    
    try:
        result = service.transition(
            request_id,
            ApprovalTransition.APPROVE,
            user_id=current_user.id,
            user_permissions=current_user.role.permissions or [],
            comment=action.comment,
        )
        db.commit()
        
        # Re-fetch for response
        request = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
        return ApprovalRequestResponse.model_validate(request)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{request_id}/reject", response_model=ApprovalRequestResponse)
@require_permission("approvals:reject")
async def reject_request(
    request_id: UUID,
    action: ApprovalAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reject a pending approval request."""
    if not action.comment:
        raise HTTPException(status_code=400, detail="Comment is required for rejections")
    
    service = ApprovalService(db, current_user.org_id)
    
    try:
        result = service.transition(
            request_id,
            ApprovalTransition.REJECT,
            user_id=current_user.id,
            user_permissions=current_user.role.permissions or [],
            comment=action.comment,
        )
        db.commit()
        
        # Re-fetch for response
        request = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
        return ApprovalRequestResponse.model_validate(request)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/batch/approve", response_model=BatchApprovalResponse)
@require_permission("approvals:approve")
async def batch_approve(
    batch: BatchApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Approve multiple requests in a batch."""
    service = ApprovalService(db, current_user.org_id)
    
    result = service.batch_approve(
        batch.request_ids,
        user_id=current_user.id,
        user_permissions=current_user.role.permissions or [],
        comment=batch.comment,
    )
    
    db.commit()
    
    return BatchApprovalResponse(**result)


@router.post("/batch/reject", response_model=BatchApprovalResponse)
@require_permission("approvals:reject")
async def batch_reject(
    batch: BatchApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reject multiple requests in a batch."""
    if not batch.comment:
        raise HTTPException(status_code=400, detail="Comment is required for batch rejections")
    
    service = ApprovalService(db, current_user.org_id)
    
    result = service.batch_reject(
        batch.request_ids,
        user_id=current_user.id,
        user_permissions=current_user.role.permissions or [],
        comment=batch.comment,
    )
    
    db.commit()
    
    return BatchApprovalResponse(**result)
