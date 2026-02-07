"""Approval service for managing package approval workflows.

Provides high-level API for interacting with the approval state machine,
including database persistence and audit logging.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from .states import (
    ApprovalState,
    ApprovalTransition,
    PENDING_REVIEW_STATES,
    APPROVED_STATES,
    BLOCKED_STATES,
)
from .machine import ApprovalStateMachine, TransitionError, PermissionDeniedError


class ApprovalService:
    """
    High-level service for managing package approvals.
    
    Handles:
    - Creating and tracking approval requests
    - Performing state transitions with persistence
    - Querying approval status
    - Batch operations
    - Expiration handling
    """
    
    def __init__(self, db: Session, org_id: UUID):
        """
        Initialize the approval service.
        
        Args:
            db: Database session
            org_id: Organization ID for scoping
        """
        self.db = db
        self.org_id = org_id
    
    def create_approval_request(
        self,
        package_id: UUID,
        package_name: str,
        package_version: str,
        package_type: str,
        *,
        mirror_id: Optional[UUID] = None,
        scan_id: Optional[UUID] = None,
        requested_by: Optional[UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a new approval request for a package.
        
        Returns:
            Dictionary with approval request details
        """
        from enterprise.db.models.approval import ApprovalRequest
        
        request = ApprovalRequest(
            id=uuid.uuid4(),
            org_id=self.org_id,
            package_id=package_id,
            package_name=package_name,
            package_version=package_version,
            package_type=package_type,
            mirror_id=mirror_id,
            scan_id=scan_id,
            requested_by=requested_by,
            state=ApprovalState.PENDING.value,
            extra_data=metadata or {},
        )
        
        self.db.add(request)
        self.db.flush()
        
        return self._request_to_dict(request)
    
    def get_approval_request(self, request_id: UUID) -> Optional[Dict[str, Any]]:
        """Get an approval request by ID."""
        from enterprise.db.models.approval import ApprovalRequest
        
        request = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.id == request_id,
                ApprovalRequest.org_id == self.org_id,
            )
        ).first()
        
        return self._request_to_dict(request) if request else None
    
    def transition(
        self,
        request_id: UUID,
        transition: ApprovalTransition,
        *,
        user_id: UUID,
        user_permissions: List[str],
        comment: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Perform a state transition on an approval request.
        
        Args:
            request_id: ID of the approval request
            transition: Transition to perform
            user_id: ID of user performing the transition
            user_permissions: Users permission list
            comment: Optional comment
            metadata: Additional metadata
            
        Returns:
            Updated approval request
            
        Raises:
            ValueError: If request not found
            TransitionError: If transition invalid
            PermissionDeniedError: If user lacks permission
        """
        from enterprise.db.models.approval import ApprovalRequest, ApprovalHistory
        
        request = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.id == request_id,
                ApprovalRequest.org_id == self.org_id,
            )
        ).with_for_update().first()
        
        if not request:
            raise ValueError(f"Approval request {request_id} not found")
        
        # Create state machine
        machine = ApprovalStateMachine(
            entity_id=request_id,
            current_state=ApprovalState(request.state),
            org_id=self.org_id,
            user_permissions=user_permissions,
        )
        
        # Perform transition
        old_state = request.state
        new_state = machine.transition(
            transition,
            comment=comment,
            user_id=user_id,
            extra_data=metadata,
        )
        
        # Update request
        request.state = new_state.value
        request.updated_at = datetime.utcnow()
        
        # Record history
        history = ApprovalHistory(
            id=uuid.uuid4(),
            request_id=request_id,
            from_state=old_state,
            to_state=new_state.value,
            transition=transition.value,
            user_id=user_id,
            comment=comment,
            extra_data=metadata or {},
        )
        self.db.add(history)
        
        # Handle terminal states
        if new_state in APPROVED_STATES:
            request.approved_at = datetime.utcnow()
            request.approved_by = user_id
        elif new_state in BLOCKED_STATES:
            request.rejected_at = datetime.utcnow()
            request.rejected_by = user_id
        
        self.db.flush()
        
        return self._request_to_dict(request)
    
    def list_pending_reviews(
        self,
        *,
        mirror_id: Optional[UUID] = None,
        package_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get approval requests awaiting review."""
        from enterprise.db.models.approval import ApprovalRequest
        
        query = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.state.in_([s.value for s in PENDING_REVIEW_STATES]),
            )
        )
        
        if mirror_id:
            query = query.filter(ApprovalRequest.mirror_id == mirror_id)
        if package_type:
            query = query.filter(ApprovalRequest.package_type == package_type)
        
        query = query.order_by(ApprovalRequest.created_at.asc())
        query = query.offset(offset).limit(limit)
        
        return [self._request_to_dict(r) for r in query.all()]
    
    def batch_approve(
        self,
        request_ids: List[UUID],
        *,
        user_id: UUID,
        user_permissions: List[str],
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Approve multiple requests in a batch.
        
        Returns:
            Summary of results
        """
        results = {"approved": [], "failed": []}
        
        for request_id in request_ids:
            try:
                self.transition(
                    request_id,
                    ApprovalTransition.APPROVE,
                    user_id=user_id,
                    user_permissions=user_permissions,
                    comment=comment,
                )
                results["approved"].append(str(request_id))
            except Exception as e:
                results["failed"].append({
                    "id": str(request_id),
                    "error": str(e),
                })
        
        return results
    
    def batch_reject(
        self,
        request_ids: List[UUID],
        *,
        user_id: UUID,
        user_permissions: List[str],
        comment: str,  # Required for rejections
    ) -> Dict[str, Any]:
        """
        Reject multiple requests in a batch.
        
        Returns:
            Summary of results
        """
        results = {"rejected": [], "failed": []}
        
        for request_id in request_ids:
            try:
                self.transition(
                    request_id,
                    ApprovalTransition.REJECT,
                    user_id=user_id,
                    user_permissions=user_permissions,
                    comment=comment,
                )
                results["rejected"].append(str(request_id))
            except Exception as e:
                results["failed"].append({
                    "id": str(request_id),
                    "error": str(e),
                })
        
        return results
    
    def expire_stale_requests(self, max_age_hours: int = 168) -> int:
        """
        Expire approval requests that have been pending too long.
        
        Args:
            max_age_hours: Maximum age in hours (default: 7 days)
            
        Returns:
            Number of requests expired
        """
        from enterprise.db.models.approval import ApprovalRequest
        
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        stale_requests = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.state.in_([s.value for s in PENDING_REVIEW_STATES]),
                ApprovalRequest.created_at < cutoff,
            )
        ).all()
        
        count = 0
        for request in stale_requests:
            request.state = ApprovalState.EXPIRED.value
            request.updated_at = datetime.utcnow()
            count += 1
        
        self.db.flush()
        return count
    
    def is_package_approved(self, package_id: UUID) -> bool:
        """Check if a package has an approved approval request."""
        from enterprise.db.models.approval import ApprovalRequest
        
        approved = self.db.query(ApprovalRequest).filter(
            and_(
                ApprovalRequest.org_id == self.org_id,
                ApprovalRequest.package_id == package_id,
                ApprovalRequest.state.in_([s.value for s in APPROVED_STATES]),
            )
        ).first()
        
        return approved is not None
    
    def _request_to_dict(self, request) -> Dict[str, Any]:
        """Convert an ApprovalRequest model to dictionary."""
        return {
            "id": str(request.id),
            "org_id": str(request.org_id),
            "package_id": str(request.package_id) if request.package_id else None,
            "package_name": request.package_name,
            "package_version": request.package_version,
            "package_type": request.package_type,
            "mirror_id": str(request.mirror_id) if request.mirror_id else None,
            "scan_id": str(request.scan_id) if request.scan_id else None,
            "state": request.state,
            "requested_by": str(request.requested_by) if request.requested_by else None,
            "approved_by": str(request.approved_by) if request.approved_by else None,
            "approved_at": request.approved_at.isoformat() if request.approved_at else None,
            "rejected_by": str(request.rejected_by) if request.rejected_by else None,
            "rejected_at": request.rejected_at.isoformat() if request.rejected_at else None,
            "extra_data": request.extra_data,
            "created_at": request.created_at.isoformat() if request.created_at else None,
            "updated_at": request.updated_at.isoformat() if request.updated_at else None,
        }
