"""Celery tasks for package scanning.

Provides async task processing for:
- Individual package scans
- Batch directory scans
- Periodic re-scans
"""

from typing import Optional, List, Dict, Any
from uuid import UUID
import logging

from celery import Celery, shared_task
from sqlalchemy.orm import Session

from enterprise.db.session import SessionLocal
from enterprise.services.scanner_integration import ScannerIntegrationService
from enterprise.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Initialize Celery
celery_app = Celery(
    'safemirror',
    broker=settings.celery_broker_url if hasattr(settings, 'celery_broker_url') else 'redis://localhost:6379/0',
    backend=settings.celery_result_backend if hasattr(settings, 'celery_result_backend') else 'redis://localhost:6379/0',
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_routes={
        'enterprise.workers.scanner_tasks.scan_package': {'queue': 'scans'},
        'enterprise.workers.scanner_tasks.scan_directory': {'queue': 'scans'},
    },
    task_default_queue='default',
)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def scan_package(
    self,
    package_path: str,
    org_id: str,
    user_id: str,
    mirror_id: Optional[str] = None,
    policy_id: Optional[str] = None,
    auto_approve: bool = True,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Async task to scan a single package.
    
    Args:
        package_path: Path to the package file
        org_id: Organization ID
        user_id: User ID requesting the scan
        mirror_id: Optional mirror ID
        policy_id: Optional policy ID
        auto_approve: Whether to auto-approve if policy passes
        extra_metadata: Additional metadata
        
    Returns:
        Scan result dictionary
    """
    db = SessionLocal()
    try:
        service = ScannerIntegrationService(
            db=db,
            org_id=UUID(org_id),
            user_id=UUID(user_id),
        )
        
        result = service.scan_and_ingest_package(
            package_path=package_path,
            mirror_id=UUID(mirror_id) if mirror_id else None,
            policy_id=UUID(policy_id) if policy_id else None,
            auto_approve=auto_approve,
            extra_metadata=extra_metadata,
        )
        
        logger.info(f"Scan completed for {package_path}: {result['scan']['status']}")
        return result
        
    except Exception as e:
        logger.exception(f"Scan failed for {package_path}")
        # Retry on transient errors
        if "connection" in str(e).lower() or "timeout" in str(e).lower():
            raise self.retry(exc=e)
        raise
        
    finally:
        db.close()


@shared_task(bind=True, max_retries=1)
def scan_directory(
    self,
    directory_path: str,
    org_id: str,
    user_id: str,
    mirror_id: Optional[str] = None,
    policy_id: Optional[str] = None,
    auto_approve: bool = True,
    package_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Async task to scan all packages in a directory.
    
    Args:
        directory_path: Path to directory
        org_id: Organization ID
        user_id: User ID
        mirror_id: Optional mirror ID
        policy_id: Optional policy ID
        auto_approve: Whether to auto-approve
        package_types: Optional list of package types to scan
        
    Returns:
        Summary of scan results
    """
    db = SessionLocal()
    try:
        service = ScannerIntegrationService(
            db=db,
            org_id=UUID(org_id),
            user_id=UUID(user_id),
        )
        
        result = service.scan_directory(
            directory_path=directory_path,
            mirror_id=UUID(mirror_id) if mirror_id else None,
            policy_id=UUID(policy_id) if policy_id else None,
            auto_approve=auto_approve,
            package_types=package_types,
        )
        
        logger.info(
            f"Directory scan completed: {result['successful']}/{result['total']} packages"
        )
        return result
        
    except Exception as e:
        logger.exception(f"Directory scan failed for {directory_path}")
        raise
        
    finally:
        db.close()


@shared_task
def rescan_package(
    package_id: str,
    org_id: str,
    user_id: str,
    policy_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Async task to re-scan an existing package.
    
    Args:
        package_id: Package ID to re-scan
        org_id: Organization ID
        user_id: User ID
        policy_id: Optional new policy ID
        
    Returns:
        Updated scan result
    """
    db = SessionLocal()
    try:
        service = ScannerIntegrationService(
            db=db,
            org_id=UUID(org_id),
            user_id=UUID(user_id),
        )
        
        result = service.rescan_package(
            package_id=UUID(package_id),
            policy_id=UUID(policy_id) if policy_id else None,
        )
        
        logger.info(f"Re-scan completed for package {package_id}")
        return result
        
    except Exception as e:
        logger.exception(f"Re-scan failed for package {package_id}")
        raise
        
    finally:
        db.close()


@shared_task
def batch_rescan_packages(
    package_ids: List[str],
    org_id: str,
    user_id: str,
    policy_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Re-scan multiple packages (e.g., after vuln DB update).
    
    Args:
        package_ids: List of package IDs
        org_id: Organization ID
        user_id: User ID
        policy_id: Optional policy ID
        
    Returns:
        Summary of results
    """
    results = {
        "total": len(package_ids),
        "successful": 0,
        "failed": 0,
        "errors": [],
    }
    
    for pkg_id in package_ids:
        try:
            rescan_package.delay(
                package_id=pkg_id,
                org_id=org_id,
                user_id=user_id,
                policy_id=policy_id,
            )
            results["successful"] += 1
        except Exception as e:
            results["failed"] += 1
            results["errors"].append({"package_id": pkg_id, "error": str(e)})
    
    return results


# Periodic task for scanning new packages in mirror directories
@celery_app.task
def scan_mirror_updates(mirror_id: str) -> Dict[str, Any]:
    """
    Scan for new packages in a mirror's source directory.
    
    This task should be scheduled periodically for each active mirror.
    """
    from enterprise.db.models import Mirror
    
    db = SessionLocal()
    try:
        mirror = db.query(Mirror).filter(Mirror.id == UUID(mirror_id)).first()
        if not mirror:
            return {"error": f"Mirror {mirror_id} not found"}
        
        if not mirror.is_active:
            return {"skipped": "Mirror is inactive"}
        
        # Get the mirror's package source directory from config
        source_dir = mirror.config.get("source_directory")
        if not source_dir:
            return {"error": "Mirror has no source directory configured"}
        
        # Use a system user for scheduled scans
        system_user_id = mirror.config.get("system_user_id")
        if not system_user_id:
            return {"error": "No system user configured for mirror"}
        
        service = ScannerIntegrationService(
            db=db,
            org_id=mirror.org_id,
            user_id=UUID(system_user_id),
        )
        
        result = service.scan_directory(
            directory_path=source_dir,
            mirror_id=mirror.id,
            policy_id=mirror.policy_id,
            auto_approve=mirror.auto_approve,
        )
        
        # Update mirror sync status
        from datetime import datetime
        mirror.last_sync_at = datetime.utcnow()
        mirror.is_syncing = False
        if result["failed"] > 0:
            mirror.last_sync_error = f"{result['failed']} packages failed to scan"
        else:
            mirror.last_sync_error = None
        
        db.commit()
        
        return result
        
    finally:
        db.close()
