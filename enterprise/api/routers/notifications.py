"""Notification preferences and webhooks API endpoints."""

from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import and_

from enterprise.api.deps import get_db, get_current_user
from enterprise.db.models import User
from enterprise.db.models.notification import (
    NotificationPreference,
    WebhookConfig,
    NotificationLog,
    NotificationEventType,
)
from enterprise.core.rbac import require_permission

router = APIRouter(prefix="/notifications", tags=["notifications"])


# Schemas
class NotificationPreferenceCreate(BaseModel):
    email_enabled: bool = True
    email_address: Optional[EmailStr] = None
    subscribed_events: List[str] = Field(default_factory=list)
    digest_enabled: bool = False
    digest_hour_utc: int = Field(default=9, ge=0, le=23)
    mirror_ids: Optional[List[UUID]] = None


class NotificationPreferenceResponse(BaseModel):
    id: UUID
    user_id: UUID
    email_enabled: bool
    email_address: Optional[str]
    subscribed_events: List[str]
    digest_enabled: bool
    digest_hour_utc: int
    mirror_ids: Optional[List[UUID]]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class WebhookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    url: str = Field(..., min_length=1)
    method: str = Field(default="POST", pattern="^(POST|PUT)$")
    auth_type: Optional[str] = Field(default=None, pattern="^(bearer|basic|header)$")
    auth_value: Optional[str] = None
    headers: Optional[dict] = None
    subscribed_events: List[str] = Field(default_factory=list)
    payload_template: Optional[str] = None
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay_seconds: int = Field(default=60, ge=10, le=3600)


class WebhookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    method: Optional[str] = None
    auth_type: Optional[str] = None
    auth_value: Optional[str] = None
    headers: Optional[dict] = None
    subscribed_events: Optional[List[str]] = None
    payload_template: Optional[str] = None
    is_active: Optional[bool] = None
    max_retries: Optional[int] = None
    retry_delay_seconds: Optional[int] = None


class WebhookResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    description: Optional[str]
    url: str
    method: str
    auth_type: Optional[str]
    headers: Optional[dict]
    subscribed_events: List[str]
    is_active: bool
    last_triggered_at: Optional[datetime]
    last_error: Optional[str]
    failure_count: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class NotificationLogResponse(BaseModel):
    id: UUID
    channel: str
    event_type: str
    recipient: str
    subject: Optional[str]
    status: str
    error_message: Optional[str]
    attempts: int
    created_at: datetime
    sent_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class EventTypesResponse(BaseModel):
    event_types: List[dict]


# Preference endpoints
@router.get("/preferences", response_model=NotificationPreferenceResponse)
@require_permission("notifications:read")
async def get_my_preferences(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current user's notification preferences."""
    prefs = db.query(NotificationPreference).filter(
        and_(
            NotificationPreference.user_id == current_user.id,
            NotificationPreference.org_id == current_user.org_id,
        )
    ).first()
    
    if not prefs:
        # Create default preferences
        prefs = NotificationPreference(
            user_id=current_user.id,
            org_id=current_user.org_id,
            subscribed_events=[
                NotificationEventType.APPROVAL_PENDING.value,
                NotificationEventType.SCAN_FAILED.value,
            ],
        )
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    
    return NotificationPreferenceResponse.model_validate(prefs)


@router.put("/preferences", response_model=NotificationPreferenceResponse)
@require_permission("notifications:update")
async def update_my_preferences(
    data: NotificationPreferenceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update current user's notification preferences."""
    # Validate event types
    valid_events = {e.value for e in NotificationEventType}
    for event in data.subscribed_events:
        if event not in valid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event type: {event}"
            )
    
    prefs = db.query(NotificationPreference).filter(
        and_(
            NotificationPreference.user_id == current_user.id,
            NotificationPreference.org_id == current_user.org_id,
        )
    ).first()
    
    if not prefs:
        prefs = NotificationPreference(
            user_id=current_user.id,
            org_id=current_user.org_id,
        )
        db.add(prefs)
    
    prefs.email_enabled = data.email_enabled
    prefs.email_address = data.email_address
    prefs.subscribed_events = data.subscribed_events
    prefs.digest_enabled = data.digest_enabled
    prefs.digest_hour_utc = data.digest_hour_utc
    prefs.mirror_ids = data.mirror_ids
    
    db.commit()
    db.refresh(prefs)
    
    return NotificationPreferenceResponse.model_validate(prefs)


@router.get("/event-types", response_model=EventTypesResponse)
async def list_event_types():
    """List all available notification event types."""
    return EventTypesResponse(
        event_types=[
            {"value": e.value, "name": e.name.replace("_", " ").title()}
            for e in NotificationEventType
        ]
    )


# Webhook endpoints
@router.get("/webhooks", response_model=List[WebhookResponse])
@require_permission("webhooks:list")
async def list_webhooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    active_only: bool = Query(False),
):
    """List all webhooks for the organization."""
    query = db.query(WebhookConfig).filter(
        WebhookConfig.org_id == current_user.org_id
    )
    
    if active_only:
        query = query.filter(WebhookConfig.is_active == True)
    
    webhooks = query.order_by(WebhookConfig.name).all()
    return [WebhookResponse.model_validate(w) for w in webhooks]


@router.post("/webhooks", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
@require_permission("webhooks:create")
async def create_webhook(
    data: WebhookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new webhook."""
    # Validate event types
    valid_events = {e.value for e in NotificationEventType}
    for event in data.subscribed_events:
        if event not in valid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event type: {event}"
            )
    
    webhook = WebhookConfig(
        org_id=current_user.org_id,
        name=data.name,
        description=data.description,
        url=data.url,
        method=data.method,
        auth_type=data.auth_type,
        auth_value=data.auth_value,
        headers=data.headers or {},
        subscribed_events=data.subscribed_events,
        payload_template=data.payload_template,
        max_retries=data.max_retries,
        retry_delay_seconds=data.retry_delay_seconds,
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    
    return WebhookResponse.model_validate(webhook)


@router.get("/webhooks/{webhook_id}", response_model=WebhookResponse)
@require_permission("webhooks:read")
async def get_webhook(
    webhook_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific webhook."""
    webhook = db.query(WebhookConfig).filter(
        and_(
            WebhookConfig.id == webhook_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    ).first()
    
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    return WebhookResponse.model_validate(webhook)


@router.patch("/webhooks/{webhook_id}", response_model=WebhookResponse)
@require_permission("webhooks:update")
async def update_webhook(
    webhook_id: UUID,
    data: WebhookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a webhook."""
    webhook = db.query(WebhookConfig).filter(
        and_(
            WebhookConfig.id == webhook_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    ).first()
    
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # Validate event types if provided
    if data.subscribed_events is not None:
        valid_events = {e.value for e in NotificationEventType}
        for event in data.subscribed_events:
            if event not in valid_events:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid event type: {event}"
                )
    
    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(webhook, field, value)
    
    db.commit()
    db.refresh(webhook)
    
    return WebhookResponse.model_validate(webhook)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permission("webhooks:delete")
async def delete_webhook(
    webhook_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a webhook."""
    webhook = db.query(WebhookConfig).filter(
        and_(
            WebhookConfig.id == webhook_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    ).first()
    
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    db.delete(webhook)
    db.commit()
    
    return None


@router.post("/webhooks/{webhook_id}/test", response_model=dict)
@require_permission("webhooks:update")
async def test_webhook(
    webhook_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a test notification to a webhook."""
    from enterprise.services.notifications import NotificationService
    
    webhook = db.query(WebhookConfig).filter(
        and_(
            WebhookConfig.id == webhook_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    ).first()
    
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    service = NotificationService(db, current_user.org_id)
    
    test_context = {
        "package_name": "test-package",
        "package_version": "1.0.0",
        "package_type": "deb",
        "status": "test",
        "details": "This is a test notification from SafeMirror",
    }
    
    try:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        notif_id = loop.run_until_complete(
            service._send_webhook(
                webhook=webhook,
                event_type=NotificationEventType.SCAN_COMPLETED,
                context=test_context,
            )
        )
        
        return {"success": True, "notification_id": notif_id}
    except Exception as e:
        return {"success": False, "error": str(e)}


# Notification logs
@router.get("/logs", response_model=List[NotificationLogResponse])
@require_permission("notifications:read")
async def list_notification_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    channel: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List notification logs."""
    query = db.query(NotificationLog).filter(
        NotificationLog.org_id == current_user.org_id
    )
    
    if channel:
        query = query.filter(NotificationLog.channel == channel)
    if event_type:
        query = query.filter(NotificationLog.event_type == event_type)
    if status:
        query = query.filter(NotificationLog.status == status)
    
    logs = query.order_by(NotificationLog.created_at.desc()) \
        .offset((page - 1) * per_page).limit(per_page).all()
    
    return [NotificationLogResponse.model_validate(log) for log in logs]
