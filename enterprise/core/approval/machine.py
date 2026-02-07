"""Approval state machine implementation.

Handles state transitions with validation, permission checking, and audit logging.
"""

from datetime import datetime
from typing import Optional, Dict, Any, Callable
from uuid import UUID
import uuid

from sqlalchemy.orm import Session

from .states import (
    ApprovalState, 
    ApprovalTransition,
    TransitionRule,
    can_transition,
    get_transition_rule,
    get_target_state,
    TERMINAL_STATES,
)


class TransitionError(Exception):
    """Raised when a state transition is invalid."""
    
    def __init__(self, message: str, from_state: ApprovalState, transition: ApprovalTransition):
        super().__init__(message)
        self.from_state = from_state
        self.transition = transition


class PermissionDeniedError(Exception):
    """Raised when user lacks permission for a transition."""
    
    def __init__(self, required_permission: str):
        super().__init__(f"Permission denied: requires {required_permission}")
        self.required_permission = required_permission


class ApprovalStateMachine:
    """
    State machine for package approval workflow.
    
    Manages transitions between approval states with:
    - Validation of valid transitions
    - Permission checking for protected transitions
    - Audit logging of all state changes
    - Callback hooks for side effects
    """
    
    def __init__(
        self,
        entity_id: UUID,
        current_state: ApprovalState,
        org_id: UUID,
        *,
        user_permissions: Optional[list[str]] = None,
    ):
        """
        Initialize the state machine.
        
        Args:
            entity_id: ID of the entity (package, scan, etc.)
            current_state: Current approval state
            org_id: Organization ID for scoping
            user_permissions: List of permission strings for the acting user
        """
        self.entity_id = entity_id
        self._state = current_state
        self.org_id = org_id
        self.user_permissions = set(user_permissions or [])
        self._transition_history: list[Dict[str, Any]] = []
        self._callbacks: Dict[ApprovalTransition, list[Callable]] = {}
    
    @property
    def state(self) -> ApprovalState:
        """Current state of the entity."""
        return self._state
    
    @property
    def is_terminal(self) -> bool:
        """Check if current state is terminal (no further transitions)."""
        return self._state in TERMINAL_STATES
    
    def can_perform(self, transition: ApprovalTransition) -> bool:
        """Check if a transition can be performed from current state."""
        if not can_transition(self._state, transition):
            return False
        
        rule = get_transition_rule(self._state, transition)
        if rule and rule.requires_permission:
            if not self._has_permission(rule.requires_permission):
                return False
        
        return True
    
    def get_available_transitions(self) -> list[ApprovalTransition]:
        """Get list of transitions available from current state."""
        available = []
        for transition in ApprovalTransition:
            if self.can_perform(transition):
                available.append(transition)
        return available
    
    def transition(
        self,
        transition: ApprovalTransition,
        *,
        comment: Optional[str] = None,
        user_id: Optional[UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalState:
        """
        Perform a state transition.
        
        Args:
            transition: The transition to perform
            comment: Optional comment (required for some transitions)
            user_id: ID of user performing the transition
            metadata: Additional metadata to record
            
        Returns:
            The new state after transition
            
        Raises:
            TransitionError: If the transition is invalid
            PermissionDeniedError: If user lacks required permission
        """
        # Validate transition is possible from current state
        if not can_transition(self._state, transition):
            raise TransitionError(
                f"Cannot perform {transition.value} from state {self._state.value}",
                self._state,
                transition,
            )
        
        rule = get_transition_rule(self._state, transition)
        if not rule:
            raise TransitionError(
                f"No rule found for transition {transition.value}",
                self._state,
                transition,
            )
        
        # Check permission
        if rule.requires_permission:
            if not self._has_permission(rule.requires_permission):
                raise PermissionDeniedError(rule.requires_permission)
        
        # Check required comment
        if rule.requires_comment and not comment:
            raise TransitionError(
                f"Transition {transition.value} requires a comment",
                self._state,
                transition,
            )
        
        # Record the transition
        from_state = self._state
        to_state = rule.to_state
        
        transition_record = {
            "id": uuid.uuid4(),
            "entity_id": self.entity_id,
            "from_state": from_state.value,
            "to_state": to_state.value,
            "transition": transition.value,
            "user_id": user_id,
            "comment": comment,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow(),
        }
        self._transition_history.append(transition_record)
        
        # Update state
        self._state = to_state
        
        # Execute callbacks
        self._execute_callbacks(transition, transition_record)
        
        return self._state
    
    def register_callback(
        self,
        transition: ApprovalTransition,
        callback: Callable[[Dict[str, Any]], None],
    ) -> None:
        """
        Register a callback to be executed after a transition.
        
        Args:
            transition: The transition to hook
            callback: Function to call with transition record
        """
        if transition not in self._callbacks:
            self._callbacks[transition] = []
        self._callbacks[transition].append(callback)
    
    def get_history(self) -> list[Dict[str, Any]]:
        """Get the transition history for this entity."""
        return self._transition_history.copy()
    
    def _has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        if not self.user_permissions:
            return False
        
        # Check exact match
        if permission in self.user_permissions:
            return True
        
        # Check wildcard permissions
        if "*:*" in self.user_permissions:
            return True
        
        resource = permission.split(":")[0]
        if f"{resource}:*" in self.user_permissions:
            return True
        
        return False
    
    def _execute_callbacks(self, transition: ApprovalTransition, record: Dict[str, Any]) -> None:
        """Execute registered callbacks for a transition."""
        callbacks = self._callbacks.get(transition, [])
        for callback in callbacks:
            try:
                callback(record)
            except Exception as e:
                # Log but dont fail the transition
                # In production, use proper logging
                print(f"Callback error for {transition}: {e}")
