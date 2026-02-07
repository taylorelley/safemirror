"""Audit log query API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime
import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import AuditLog, User
from enterprise.core.rbac import require_permission

router = APIRouter(prefix="/audit-logs", tags=["audit"])


# Schemas
class AuditLogResponse(BaseModel):
    id: UUID
    org_id: UUID
    user_id: Optional[UUID]
    action: str
    resource_type: str
    resource_id: Optional[UUID]
    severity: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[dict]
    old_values: Optional[dict]
    new_values: Optional[dict]
    created_at: datetime
    
    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    page: int
    per_page: int


# Endpoints
@router.get("", response_model=AuditLogListResponse)
@require_permission("audit_logs:list")
async def list_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    user_id: Optional[UUID] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    search: Optional[str] = None,
):
    """
    List audit logs for the current organization.
    
    Supports filtering by user, action, resource, severity, and date range.
    """
    query = db.query(AuditLog).filter(AuditLog.org_id == current_user.org_id)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    
    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)
    
    if severity:
        query = query.filter(AuditLog.severity == severity)
    
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)
    
    if search:
        query = query.filter(
            or_(
                AuditLog.action.ilike(f"%{search}%"),
                AuditLog.resource_type.ilike(f"%{search}%"),
            )
        )
    
    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    return AuditLogListResponse(
        items=[
            AuditLogResponse(
                id=log.id,
                org_id=log.org_id,
                user_id=log.user_id,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                severity=log.severity,
                ip_address=str(log.ip_address) if log.ip_address else None,
                user_agent=log.user_agent,
                details=log.details,
                old_values=log.old_values,
                new_values=log.new_values,
                created_at=log.created_at,
            )
            for log in logs
        ],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{log_id}", response_model=AuditLogResponse)
@require_permission("audit_logs:read")
async def get_audit_log(
    log_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific audit log entry."""
    log = db.query(AuditLog).filter(
        and_(AuditLog.id == log_id, AuditLog.org_id == current_user.org_id)
    ).first()
    
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")
    
    return AuditLogResponse(
        id=log.id,
        org_id=log.org_id,
        user_id=log.user_id,
        action=log.action,
        resource_type=log.resource_type,
        resource_id=log.resource_id,
        severity=log.severity,
        ip_address=str(log.ip_address) if log.ip_address else None,
        user_agent=log.user_agent,
        details=log.details,
        old_values=log.old_values,
        new_values=log.new_values,
        created_at=log.created_at,
    )


@router.get("/export/csv")
@require_permission("audit_logs:export")
async def export_audit_logs_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_id: Optional[UUID] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
):
    """Export audit logs as CSV for compliance."""
    query = db.query(AuditLog).filter(AuditLog.org_id == current_user.org_id)
    
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    
    logs = query.order_by(AuditLog.created_at.desc()).limit(10000).all()
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "id", "timestamp", "user_id", "action", "resource_type", 
        "resource_id", "severity", "ip_address", "details"
    ])
    
    # Data
    for log in logs:
        writer.writerow([
            str(log.id),
            log.created_at.isoformat(),
            str(log.user_id) if log.user_id else "",
            log.action,
            log.resource_type,
            str(log.resource_id) if log.resource_id else "",
            log.severity,
            str(log.ip_address) if log.ip_address else "",
            json.dumps(log.details) if log.details else "",
        ])
    
    output.seek(0)
    date_str = datetime.utcnow().strftime("%Y%m%d")
    filename = f"audit_logs_{date_str}.csv"
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/export/json")
@require_permission("audit_logs:export")
async def export_audit_logs_json(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(1000, le=10000),
):
    """Export audit logs as JSON for compliance."""
    query = db.query(AuditLog).filter(AuditLog.org_id == current_user.org_id)
    
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)
    
    logs = query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    
    export_data = {
        "exported_at": datetime.utcnow().isoformat(),
        "org_id": str(current_user.org_id),
        "total_records": len(logs),
        "logs": [
            {
                "id": str(log.id),
                "timestamp": log.created_at.isoformat(),
                "user_id": str(log.user_id) if log.user_id else None,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "severity": log.severity,
                "ip_address": str(log.ip_address) if log.ip_address else None,
                "user_agent": log.user_agent,
                "details": log.details,
                "old_values": log.old_values,
                "new_values": log.new_values,
            }
            for log in logs
        ]
    }
    
    date_str = datetime.utcnow().strftime("%Y%m%d")
    filename = f"audit_logs_{date_str}.json"
    
    return StreamingResponse(
        iter([json.dumps(export_data, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
