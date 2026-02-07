"""Approval workflow module for SafeMirror Enterprise.

Implements the package approval state machine and policy evaluation.
"""

from .states import ApprovalState, ApprovalTransition, VALID_TRANSITIONS
from .machine import ApprovalStateMachine
from .service import ApprovalService

__all__ = [
    "ApprovalState",
    "ApprovalTransition", 
    "VALID_TRANSITIONS",
    "ApprovalStateMachine",
    "ApprovalService",
]
