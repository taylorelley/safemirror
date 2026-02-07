"""Notification service for email and webhook delivery.

Handles:
- Email notifications for pending approvals
- Webhook notifications to external systems
- Daily digest compilation
- Retry logic for failed deliveries
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any, List
from uuid import UUID

import httpx
from jinja2 import Template
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from enterprise.core.config import get_settings
from enterprise.db.models.notification import (
    NotificationPreference,
    WebhookConfig,
    NotificationLog,
    NotificationChannel,
    NotificationEventType,
)
from enterprise.db.models.approval import ApprovalRequest
from enterprise.db.models import User

logger = logging.getLogger(__name__)
settings = get_settings()


# Email templates
EMAIL_TEMPLATES = {
    NotificationEventType.APPROVAL_PENDING: {
        "subject": "[SafeMirror] Package Pending Review: {package_name}",
        "body": """
A new package requires your review:

Package: {package_name} v{package_version}
Type: {package_type}
Mirror: {mirror_name}
Scan Result: {scan_summary}

Policy Evaluation:
- Decision: {policy_decision}
- Failed Rules: {failed_rules}

Please review at: {review_url}

---
SafeMirror Enterprise
        """,
    },
    NotificationEventType.APPROVAL_APPROVED: {
        "subject": "[SafeMirror] Package Approved: {package_name}",
        "body": """
Package has been approved:

Package: {package_name} v{package_version}
Type: {package_type}
Approved By: {approver_name}
Approved At: {approved_at}

The package is now available in the approved repository.

---
SafeMirror Enterprise
        """,
    },
    NotificationEventType.APPROVAL_REJECTED: {
        "subject": "[SafeMirror] Package Rejected: {package_name}",
        "body": """
Package has been rejected:

Package: {package_name} v{package_version}
Type: {package_type}
Rejected By: {rejecter_name}
Reason: {rejection_reason}

---
SafeMirror Enterprise
        """,
    },
    NotificationEventType.SCAN_FAILED: {
        "subject": "[SafeMirror] Scan Failed: {package_name}",
        "body": """
Package scan has failed:

Package: {package_name} v{package_version}
Error: {error_message}

Please investigate and retry the scan.

---
SafeMirror Enterprise
        """,
    },
    NotificationEventType.DAILY_DIGEST: {
        "subject": "[SafeMirror] Daily Digest - {date}",
        "body": """
SafeMirror Daily Digest for {date}

Summary:
- Pending Reviews: {pending_count}
- Approved Today: {approved_count}
- Rejected Today: {rejected_count}

Packages Pending Review:
{pending_list}

View all pending reviews at: {dashboard_url}

---
SafeMirror Enterprise
        """,
    },
}

# Webhook payload templates
WEBHOOK_TEMPLATES = {
    "slack": {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*{event_title}*\n{event_description}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": "*Package:*\n{package_name}"},
                    {"type": "mrkdwn", "text": "*Version:*\n{package_version}"},
                    {"type": "mrkdwn", "text": "*Type:*\n{package_type}"},
                    {"type": "mrkdwn", "text": "*Status:*\n{status}"},
                ]
            }
        ]
    },
    "teams": {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "{color}",
        "summary": "{event_title}",
        "sections": [{
            "activityTitle": "{event_title}",
            "facts": [
                {"name": "Package", "value": "{package_name}"},
                {"name": "Version", "value": "{package_version}"},
                {"name": "Type", "value": "{package_type}"},
                {"name": "Status", "value": "{status}"},
            ],
            "markdown": True
        }]
    },
    "generic": {
        "event": "{event_type}",
        "timestamp": "{timestamp}",
        "package": {
            "name": "{package_name}",
            "version": "{package_version}",
            "type": "{package_type}",
        },
        "status": "{status}",
        "details": "{details}",
    }
}


class NotificationService:
    """
    Service for sending notifications via email and webhooks.
    """
    
    def __init__(self, db: Session, org_id: UUID):
        """
        Initialize notification service.
        
        Args:
            db: Database session
            org_id: Organization ID
        """
        self.db = db
        self.org_id = org_id
        self.settings = get_settings()
    
    async def notify_pending_approval(
        self,
        approval_request: ApprovalRequest,
        policy_result: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Send notifications for a pending approval.
        
        Args:
            approval_request: The approval request
            policy_result: Optional policy evaluation result
            
        Returns:
            List of notification IDs
        """
        context = self._build_approval_context(approval_request, policy_result)
        return await self._send_event_notifications(
            event_type=NotificationEventType.APPROVAL_PENDING,
            context=context,
            approval_request_id=approval_request.id,
        )
    
    async def notify_approval_completed(
        self,
        approval_request: ApprovalRequest,
        approved: bool,
        comment: Optional[str] = None,
    ) -> List[str]:
        """
        Send notifications when approval is completed.
        
        Args:
            approval_request: The approval request
            approved: Whether it was approved or rejected
            comment: Optional comment/reason
            
        Returns:
            List of notification IDs
        """
        event_type = (
            NotificationEventType.APPROVAL_APPROVED if approved
            else NotificationEventType.APPROVAL_REJECTED
        )
        
        context = self._build_approval_context(approval_request)
        context["rejection_reason"] = comment or "No reason provided"
        
        return await self._send_event_notifications(
            event_type=event_type,
            context=context,
            approval_request_id=approval_request.id,
        )
    
    async def notify_scan_failed(
        self,
        package_name: str,
        package_version: str,
        error_message: str,
    ) -> List[str]:
        """
        Send notifications when a scan fails.
        
        Args:
            package_name: Package name
            package_version: Package version
            error_message: Error details
            
        Returns:
            List of notification IDs
        """
        context = {
            "package_name": package_name,
            "package_version": package_version,
            "error_message": error_message,
        }
        
        return await self._send_event_notifications(
            event_type=NotificationEventType.SCAN_FAILED,
            context=context,
        )
    
    async def send_daily_digest(self, user_id: UUID) -> Optional[str]:
        """
        Send daily digest to a user.
        
        Args:
            user_id: User ID to send digest to
            
        Returns:
            Notification ID if sent, None otherwise
        """
        # Get user preferences
        prefs = self.db.query(NotificationPreference).filter(
            and_(
                NotificationPreference.user_id == user_id,
                NotificationPreference.org_id == self.org_id,
                NotificationPreference.digest_enabled == True,
            )
        ).first()
        
        if not prefs:
            return None
        
        # Get user
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        
        # Build digest content
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Pending reviews
        pending = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.state == "needs_review",
            )
        ).all()
        
        # Approved/rejected today
        approved = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.state == "approved",
                ApprovalRequest.approved_at >= yesterday,
            )
        ).count()
        
        rejected = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.state == "rejected",
                ApprovalRequest.rejected_at >= yesterday,
            )
        ).count()
        
        # Build pending list
        pending_list = "\n".join([
            f"- {p.package_name} v{p.package_version} ({p.package_type})"
            for p in pending[:10]
        ])
        if len(pending) > 10:
            pending_list += f"\n... and {len(pending) - 10} more"
        
        context = {
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "pending_count": len(pending),
            "approved_count": approved,
            "rejected_count": rejected,
            "pending_list": pending_list or "No packages pending review",
            "dashboard_url": f"{self.settings.app_name}/approvals",
        }
        
        email = prefs.email_address or user.email
        if email:
            return await self._send_email(
                to_email=email,
                event_type=NotificationEventType.DAILY_DIGEST,
                context=context,
                user_id=user_id,
            )
        
        return None
    
    async def _send_event_notifications(
        self,
        event_type: NotificationEventType,
        context: Dict[str, Any],
        approval_request_id: Optional[UUID] = None,
    ) -> List[str]:
        """Send notifications for an event to all subscribers."""
        notification_ids = []
        
        # Get email subscribers
        email_prefs = self.db.query(NotificationPreference).filter(
            and_(
                NotificationPreference.org_id == self.org_id,
                NotificationPreference.email_enabled == True,
                NotificationPreference.digest_enabled == False,  # Not on digest
            )
        ).all()
        
        for pref in email_prefs:
            if event_type.value in (pref.subscribed_events or []):
                user = self.db.query(User).filter(User.id == pref.user_id).first()
                if user:
                    email = pref.email_address or user.email
                    if email:
                        notif_id = await self._send_email(
                            to_email=email,
                            event_type=event_type,
                            context=context,
                            user_id=pref.user_id,
                            approval_request_id=approval_request_id,
                        )
                        if notif_id:
                            notification_ids.append(notif_id)
        
        # Get webhook subscribers
        webhooks = self.db.query(WebhookConfig).filter(
            and_(
                WebhookConfig.org_id == self.org_id,
                WebhookConfig.is_active == True,
            )
        ).all()
        
        for webhook in webhooks:
            if event_type.value in (webhook.subscribed_events or []):
                notif_id = await self._send_webhook(
                    webhook=webhook,
                    event_type=event_type,
                    context=context,
                    approval_request_id=approval_request_id,
                )
                if notif_id:
                    notification_ids.append(notif_id)
        
        return notification_ids
    
    async def _send_email(
        self,
        to_email: str,
        event_type: NotificationEventType,
        context: Dict[str, Any],
        user_id: Optional[UUID] = None,
        approval_request_id: Optional[UUID] = None,
    ) -> Optional[str]:
        """Send an email notification."""
        template = EMAIL_TEMPLATES.get(event_type)
        if not template:
            logger.warning(f"No email template for event type: {event_type}")
            return None
        
        # Render template
        subject = template["subject"].format(**context)
        body = template["body"].format(**context)
        
        # Create log entry
        log = NotificationLog(
            org_id=self.org_id,
            channel=NotificationChannel.EMAIL.value,
            event_type=event_type.value,
            recipient=to_email,
            user_id=user_id,
            approval_request_id=approval_request_id,
            subject=subject,
            body=body,
            status="pending",
        )
        self.db.add(log)
        self.db.flush()
        
        # Send email
        try:
            await self._deliver_email(to_email, subject, body)
            log.status = "sent"
            log.sent_at = datetime.utcnow()
            log.attempts = 1
        except Exception as e:
            logger.exception(f"Failed to send email to {to_email}")
            log.status = "failed"
            log.error_message = str(e)
            log.attempts = 1
        
        self.db.commit()
        return str(log.id)
    
    async def _deliver_email(self, to_email: str, subject: str, body: str) -> None:
        """Actually deliver the email via SMTP."""
        if not self.settings.smtp_host:
            logger.warning("SMTP not configured, skipping email delivery")
            return
        
        try:
            import aiosmtplib
            
            msg = MIMEMultipart()
            msg["From"] = f"{self.settings.smtp_from_name} <{self.settings.smtp_from_email}>"
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            
            await aiosmtplib.send(
                msg,
                hostname=self.settings.smtp_host,
                port=self.settings.smtp_port,
                username=self.settings.smtp_user,
                password=self.settings.smtp_password,
                use_tls=self.settings.smtp_use_tls,
            )
        except ImportError:
            # Fall back to smtplib if aiosmtplib not available
            import smtplib
            
            msg = MIMEMultipart()
            msg["From"] = f"{self.settings.smtp_from_name} <{self.settings.smtp_from_email}>"
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port) as server:
                if self.settings.smtp_use_tls:
                    server.starttls()
                if self.settings.smtp_user:
                    server.login(self.settings.smtp_user, self.settings.smtp_password)
                server.send_message(msg)
    
    async def _send_webhook(
        self,
        webhook: WebhookConfig,
        event_type: NotificationEventType,
        context: Dict[str, Any],
        approval_request_id: Optional[UUID] = None,
    ) -> Optional[str]:
        """Send a webhook notification."""
        # Build payload
        if webhook.payload_template:
            try:
                template = Template(webhook.payload_template)
                payload = json.loads(template.render(**context))
            except Exception as e:
                logger.warning(f"Failed to render webhook template: {e}")
                payload = self._build_default_webhook_payload(event_type, context)
        else:
            payload = self._build_default_webhook_payload(event_type, context)
        
        # Create log entry
        log = NotificationLog(
            org_id=self.org_id,
            channel=NotificationChannel.WEBHOOK.value,
            event_type=event_type.value,
            recipient=webhook.name,
            webhook_id=webhook.id,
            approval_request_id=approval_request_id,
            payload=payload,
            status="pending",
        )
        self.db.add(log)
        self.db.flush()
        
        # Send webhook
        try:
            await self._deliver_webhook(webhook, payload)
            log.status = "sent"
            log.sent_at = datetime.utcnow()
            log.attempts = 1
            webhook.last_triggered_at = datetime.utcnow()
            webhook.failure_count = 0
            webhook.last_error = None
        except Exception as e:
            logger.exception(f"Failed to send webhook to {webhook.url}")
            log.status = "failed"
            log.error_message = str(e)
            log.attempts = 1
            webhook.failure_count += 1
            webhook.last_error = str(e)
        
        self.db.commit()
        return str(log.id)
    
    async def _deliver_webhook(self, webhook: WebhookConfig, payload: Dict[str, Any]) -> None:
        """Actually deliver the webhook."""
        headers = dict(webhook.headers or {})
        headers["Content-Type"] = "application/json"
        
        # Add authentication
        if webhook.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {webhook.auth_value}"
        elif webhook.auth_type == "basic":
            import base64
            encoded = base64.b64encode(webhook.auth_value.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        elif webhook.auth_type == "header":
            # Assume auth_value is JSON with header name and value
            try:
                auth = json.loads(webhook.auth_value)
                headers[auth["name"]] = auth["value"]
            except Exception:
                pass
        
        async with httpx.AsyncClient(timeout=self.settings.webhook_timeout) as client:
            if webhook.method.upper() == "PUT":
                response = await client.put(webhook.url, json=payload, headers=headers)
            else:
                response = await client.post(webhook.url, json=payload, headers=headers)
            
            response.raise_for_status()
    
    def _build_default_webhook_payload(
        self,
        event_type: NotificationEventType,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build default webhook payload."""
        return {
            "event": event_type.value,
            "timestamp": datetime.utcnow().isoformat(),
            "organization_id": str(self.org_id),
            "data": context,
        }
    
    def _build_approval_context(
        self,
        approval_request: ApprovalRequest,
        policy_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build context for approval notifications."""
        context = {
            "package_name": approval_request.package_name,
            "package_version": approval_request.package_version,
            "package_type": approval_request.package_type,
            "mirror_name": approval_request.mirror.name if approval_request.mirror else "N/A",
            "status": approval_request.state,
            "review_url": f"{self.settings.app_name}/approvals/{approval_request.id}",
        }
        
        if policy_result:
            context["policy_decision"] = policy_result.get("decision", "unknown")
            context["scan_summary"] = f"{policy_result.get('passed_rules', 0)} passed, {len(policy_result.get('failed_rules', []))} failed"
            context["failed_rules"] = ", ".join([
                r.get("rule_type", "unknown") for r in policy_result.get("failed_rules", [])
            ]) or "None"
        else:
            context["policy_decision"] = "N/A"
            context["scan_summary"] = "N/A"
            context["failed_rules"] = "N/A"
        
        # Approval details
        if approval_request.approver:
            context["approver_name"] = approval_request.approver.name or approval_request.approver.email
            context["approved_at"] = approval_request.approved_at.isoformat() if approval_request.approved_at else "N/A"
        else:
            context["approver_name"] = "N/A"
            context["approved_at"] = "N/A"
        
        if approval_request.rejecter:
            context["rejecter_name"] = approval_request.rejecter.name or approval_request.rejecter.email
        else:
            context["rejecter_name"] = "N/A"
        
        return context


# Helper function for sync code
def send_notification_sync(
    db: Session,
    org_id: UUID,
    event_type: NotificationEventType,
    context: Dict[str, Any],
    approval_request_id: Optional[UUID] = None,
) -> List[str]:
    """Synchronous wrapper for sending notifications."""
    service = NotificationService(db, org_id)
    
    # Run async in a new event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(
        service._send_event_notifications(
            event_type=event_type,
            context=context,
            approval_request_id=approval_request_id,
        )
    )
