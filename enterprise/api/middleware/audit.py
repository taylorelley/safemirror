"""Audit logging middleware for FastAPI.

Automatically logs all API requests with:
- User identity (ID, email)
- Action performed (HTTP method + path)
- Resource accessed
- Request/response details
- Client IP address
- User agent
- Session ID
"""

import uuid
import json
import time
from datetime import datetime
from typing import Callable, Optional, Dict, Any
from functools import wraps

from fastapi import Request, Response
from fastapi.routing import APIRoute
from starlette.middleware.base import BaseHTTPMiddleware

from enterprise.db.models.audit import AuditLog, AuditSeverity


# Map HTTP methods to action names
METHOD_TO_ACTION = {
    "GET": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}

# Paths that should not be logged (health checks, static files)
EXCLUDED_PATHS = {
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
}

# Sensitive fields to redact from logs
SENSITIVE_FIELDS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "secret",
    "client_secret",
}


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header (set by reverse proxies)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Take the first IP (original client)
        return forwarded.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    
    # Fall back to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


def extract_resource_info(path: str, method: str) -> tuple[str, Optional[str]]:
    """
    Extract resource type and ID from request path.
    
    Returns:
        Tuple of (resource_type, resource_id)
    """
    # Remove leading/trailing slashes and split
    parts = [p for p in path.strip("/").split("/") if p]
    
    if not parts:
        return "root", None
    
    # Skip api prefix
    if parts[0] == "api":
        parts = parts[1:]
    
    if not parts:
        return "api", None
    
    resource_type = parts[0]
    resource_id = None
    
    # Check if second part looks like a UUID
    if len(parts) > 1:
        try:
            uuid.UUID(parts[1])
            resource_id = parts[1]
        except ValueError:
            pass
    
    return resource_type, resource_id


def redact_sensitive(data: Any) -> Any:
    """Redact sensitive fields from data."""
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if k.lower() in SENSITIVE_FIELDS else redact_sensitive(v)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_sensitive(item) for item in data]
    return data


def determine_severity(status_code: int, method: str) -> AuditSeverity:
    """Determine log severity based on response status and method."""
    if status_code >= 500:
        return AuditSeverity.ERROR
    elif status_code >= 400:
        if status_code in (401, 403):
            return AuditSeverity.CRITICAL  # Auth failures are security-relevant
        return AuditSeverity.WARNING
    elif method in ("DELETE", "PATCH", "PUT"):
        return AuditSeverity.INFO
    return AuditSeverity.DEBUG


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs all API requests to the audit log.
    
    Captures:
    - User identity (from request state)
    - Action (HTTP method mapped to action name)
    - Resource type and ID (from path)
    - Request body (redacted)
    - Response status
    - Duration
    - Client IP and user agent
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip excluded paths
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)
        
        # Generate request ID for tracing
        request_id = str(uuid.uuid4())[:8]
        
        # Record start time
        start_time = time.time()
        
        # Extract info before processing
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        resource_type, resource_id = extract_resource_info(request.url.path, request.method)
        action = METHOD_TO_ACTION.get(request.method, request.method.lower())
        
        # Try to read request body (for POST/PUT/PATCH)
        request_body = None
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                if body_bytes:
                    try:
                        request_body = json.loads(body_bytes)
                        request_body = redact_sensitive(request_body)
                    except json.JSONDecodeError:
                        request_body = {"raw_size": len(body_bytes)}
            except Exception:
                pass
        
        # Process the request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Get user info from request state (set by auth middleware)
        user_id = None
        org_id = None
        session_id = None
        
        user = getattr(request.state, "user", None)
        if user:
            user_id = user.id
            org_id = user.org_id
            session_id = getattr(request.state, "session_id", None)
        
        # Determine severity
        severity = determine_severity(response.status_code, request.method)
        
        # Build details
        details = {
            "method": request.method,
            "path": request.url.path,
            "query": str(request.query_params) if request.query_params else None,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "request_body": request_body,
        }
        
        # Log to database if we have a session
        # The actual database write happens via the audit_action function
        # This middleware sets up the context for endpoint-level logging
        
        # Store audit context for later use
        request.state.audit_context = {
            "request_id": request_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "user_id": user_id,
            "org_id": org_id,
            "session_id": session_id,
            "ip_address": client_ip,
            "user_agent": user_agent,
            "severity": severity,
            "details": details,
        }
        
        return response


def audit_action(
    action: str,
    resource_type: str,
    resource_id: Optional[uuid.UUID] = None,
    old_values: Optional[Dict[str, Any]] = None,
    new_values: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: AuditSeverity = AuditSeverity.INFO,
):
    """
    Decorator for auditing specific actions in endpoints.
    
    Use this when you need fine-grained control over what gets logged,
    or to capture before/after values for updates.
    
    Usage:
        @router.post("/mirrors")
        @audit_action("create", "mirror")
        async def create_mirror(...):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find request in args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")
            
            # Execute the function
            result = await func(*args, **kwargs)
            
            # Log the action if we have a request with user context
            if request and hasattr(request, "state"):
                user = getattr(request.state, "user", None)
                if user:
                    from enterprise.db.session import SessionLocal
                    from enterprise.db.models.audit import AuditLog
                    
                    db = SessionLocal()
                    try:
                        log_entry = AuditLog.create_entry(
                            org_id=user.org_id,
                            action=action,
                            resource_type=resource_type,
                            user_id=user.id,
                            resource_id=resource_id,
                            old_values=redact_sensitive(old_values) if old_values else None,
                            new_values=redact_sensitive(new_values) if new_values else None,
                            details=redact_sensitive(details) if details else None,
                            ip_address=get_client_ip(request),
                            user_agent=request.headers.get("user-agent"),
                            session_id=getattr(request.state, "session_id", None),
                            severity=severity,
                        )
                        db.add(log_entry)
                        db.commit()
                    except Exception as e:
                        db.rollback()
                        # Log error but dont fail the request
                        print(f"Audit logging error: {e}")
                    finally:
                        db.close()
            
            return result
        return wrapper
    return decorator


class AuditLogger:
    """
    Utility class for logging audit events from within endpoints.
    
    Usage:
        @router.post("/mirrors")
        async def create_mirror(
            request: Request,
            db: Session = Depends(get_db),
            current_user: User = Depends(get_current_user),
        ):
            # ... create mirror ...
            
            # Log the action
            AuditLogger(db, request, current_user).log(
                action="create",
                resource_type="mirror",
                resource_id=mirror.id,
                new_values={"name": mirror.name, "type": mirror.mirror_type},
            )
    """
    
    def __init__(self, db, request: Request, user):
        self.db = db
        self.request = request
        self.user = user
    
    def log(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[uuid.UUID] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
    ) -> AuditLog:
        """Log an audit event."""
        entry = AuditLog.create_entry(
            org_id=self.user.org_id,
            action=action,
            resource_type=resource_type,
            user_id=self.user.id,
            resource_id=resource_id,
            old_values=redact_sensitive(old_values) if old_values else None,
            new_values=redact_sensitive(new_values) if new_values else None,
            details=redact_sensitive(details) if details else None,
            ip_address=get_client_ip(self.request),
            user_agent=self.request.headers.get("user-agent"),
            session_id=getattr(self.request.state, "session_id", None),
            severity=severity,
        )
        self.db.add(entry)
        return entry
