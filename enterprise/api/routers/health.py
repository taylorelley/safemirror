"""Health check endpoints for SafeMirror Enterprise.

Provides Kubernetes-compatible health probes:
- /health: Basic health check
- /health/live: Liveness probe (is the app running?)
- /health/ready: Readiness probe (is the app ready to serve traffic?)

Checks:
- Database connectivity
- Redis connectivity
- Disk space
- Memory usage
"""

import os
import psutil
from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import redis

from enterprise.api.deps import get_db
from enterprise.core.config import get_settings

router = APIRouter(tags=["health"])
settings = get_settings()

# Thresholds
DISK_WARNING_PERCENT = 85
DISK_CRITICAL_PERCENT = 95
MEMORY_WARNING_PERCENT = 85
MEMORY_CRITICAL_PERCENT = 95


def check_database(db: Session) -> Dict[str, Any]:
    """Check database connectivity and basic stats."""
    try:
        # Simple query to verify connectivity
        result = db.execute(text("SELECT 1"))
        result.fetchone()
        
        # Get database version
        version_result = db.execute(text("SELECT version()"))
        version = version_result.fetchone()[0]
        
        return {
            "status": "healthy",
            "latency_ms": 0,  # Could add timing here
            "version": version.split()[0:2] if version else "unknown",
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }


def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity."""
    try:
        r = redis.from_url(
            settings.redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        r.ping()
        info = r.info("server")
        r.close()
        
        return {
            "status": "healthy",
            "version": info.get("redis_version", "unknown"),
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }


def check_disk() -> Dict[str, Any]:
    """Check disk space."""
    try:
        disk = psutil.disk_usage("/")
        percent_used = disk.percent
        
        status = "healthy"
        if percent_used >= DISK_CRITICAL_PERCENT:
            status = "critical"
        elif percent_used >= DISK_WARNING_PERCENT:
            status = "warning"
        
        return {
            "status": status,
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "percent_used": percent_used,
        }
    except Exception as e:
        return {
            "status": "unknown",
            "error": str(e),
        }


def check_memory() -> Dict[str, Any]:
    """Check memory usage."""
    try:
        memory = psutil.virtual_memory()
        percent_used = memory.percent
        
        status = "healthy"
        if percent_used >= MEMORY_CRITICAL_PERCENT:
            status = "critical"
        elif percent_used >= MEMORY_WARNING_PERCENT:
            status = "warning"
        
        return {
            "status": status,
            "total_gb": round(memory.total / (1024**3), 2),
            "available_gb": round(memory.available / (1024**3), 2),
            "percent_used": percent_used,
        }
    except Exception as e:
        return {
            "status": "unknown",
            "error": str(e),
        }


@router.get("/health")
async def health_check():
    """
    Basic health check endpoint.
    
    Returns 200 if the application is running.
    Used for simple uptime monitoring.
    """
    return {
        "status": "healthy",
        "version": "0.2.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/health/live")
async def liveness_probe():
    """
    Kubernetes liveness probe.
    
    Returns 200 if the application is running.
    Failure means the container should be restarted.
    
    This check should be fast and not depend on external services.
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "alive",
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@router.get("/health/ready")
async def readiness_probe(db: Session = Depends(get_db)):
    """
    Kubernetes readiness probe.
    
    Returns 200 if the application is ready to serve traffic.
    Checks database and Redis connectivity.
    
    Failure means traffic should not be routed to this instance.
    """
    checks = {
        "database": check_database(db),
        "redis": check_redis(),
    }
    
    # Determine overall status
    unhealthy = [name for name, check in checks.items() if check["status"] == "unhealthy"]
    
    if unhealthy:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "checks": checks,
                "failed": unhealthy,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ready",
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@router.get("/health/detailed")
async def detailed_health_check(db: Session = Depends(get_db)):
    """
    Detailed health check with all system metrics.
    
    Includes database, Redis, disk, and memory checks.
    Useful for monitoring and debugging.
    """
    checks = {
        "database": check_database(db),
        "redis": check_redis(),
        "disk": check_disk(),
        "memory": check_memory(),
    }
    
    # Determine overall status
    statuses = [check.get("status", "unknown") for check in checks.values()]
    
    if "unhealthy" in statuses or "critical" in statuses:
        overall_status = "unhealthy"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE
    elif "warning" in statuses:
        overall_status = "degraded"
        http_status = status.HTTP_200_OK
    else:
        overall_status = "healthy"
        http_status = status.HTTP_200_OK
    
    return JSONResponse(
        status_code=http_status,
        content={
            "status": overall_status,
            "version": "0.2.0",
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )
