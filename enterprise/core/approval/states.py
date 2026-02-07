"""Approval workflow states and transitions.

State Machine Diagram:
    
    ┌──────────┐
    │ PENDING  │ ← Initial state (new package/scan)
    └────┬─────┘
         │
    ┌────▼─────┐    ┌───────────┐
    │ SCANNING │───►│  FAILED   │ (scan error)
    └────┬─────┘    └───────────┘
         │
    ┌────▼─────┐
    │ SCANNED  │ (scan complete)
    └────┬─────┘
         │
         ├─────────────────────┐
         │                     │
    ┌────▼─────┐         ┌─────▼──────┐
    │AUTO_APRV │         │NEEDS_REVIEW│
    └────┬─────┘         └─────┬──────┘
         │                     │
         │               ┌─────┴─────┐
         │               │           │
    ┌────▼─────┐   ┌─────▼────┐ ┌────▼─────┐
    │ APPROVED │   │ APPROVED │ │ REJECTED │
    └──────────┘   └──────────┘ └──────────┘

Additional states:
- EXPIRED: Approval request timed out
- REVOKED: Previously approved, now revoked
"""

from enum import Enum
from typing import Set, Dict, Optional, NamedTuple
from datetime import datetime


class ApprovalState(str, Enum):
    """States in the package approval workflow."""
    
    # Initial states
    PENDING = "pending"           # Package registered, awaiting scan
    
    # Scanning states
    SCANNING = "scanning"         # Scan in progress
    SCANNED = "scanned"          # Scan complete, awaiting policy evaluation
    FAILED = "failed"            # Scan failed (error, timeout, etc.)
    
    # Review states  
    AUTO_APPROVED = "auto_approved"   # Passed policy, auto-approved
    NEEDS_REVIEW = "needs_review"     # Policy requires manual review
    
    # Terminal states
    APPROVED = "approved"        # Manually approved by authorized user
    REJECTED = "rejected"        # Rejected by authorized user
    EXPIRED = "expired"          # Review period expired
    REVOKED = "revoked"          # Previously approved, now revoked


class ApprovalTransition(str, Enum):
    """Actions that trigger state transitions."""
    
    # Scan lifecycle
    START_SCAN = "start_scan"        # PENDING → SCANNING
    COMPLETE_SCAN = "complete_scan"  # SCANNING → SCANNED
    FAIL_SCAN = "fail_scan"          # SCANNING → FAILED
    RETRY_SCAN = "retry_scan"        # FAILED → PENDING
    
    # Policy evaluation
    AUTO_APPROVE = "auto_approve"    # SCANNED → AUTO_APPROVED
    REQUIRE_REVIEW = "require_review" # SCANNED → NEEDS_REVIEW
    
    # Manual actions
    APPROVE = "approve"              # NEEDS_REVIEW → APPROVED
    REJECT = "reject"                # NEEDS_REVIEW → REJECTED
    
    # Lifecycle
    EXPIRE = "expire"                # NEEDS_REVIEW → EXPIRED
    REVOKE = "revoke"                # APPROVED/AUTO_APPROVED → REVOKED
    RESET = "reset"                  # Any → PENDING (admin only)


class TransitionRule(NamedTuple):
    """Defines a valid state transition."""
    from_state: ApprovalState
    to_state: ApprovalState
    transition: ApprovalTransition
    requires_permission: Optional[str] = None
    requires_comment: bool = False


# Define all valid transitions
TRANSITION_RULES: list[TransitionRule] = [
    # Scan lifecycle
    TransitionRule(ApprovalState.PENDING, ApprovalState.SCANNING, ApprovalTransition.START_SCAN),
    TransitionRule(ApprovalState.SCANNING, ApprovalState.SCANNED, ApprovalTransition.COMPLETE_SCAN),
    TransitionRule(ApprovalState.SCANNING, ApprovalState.FAILED, ApprovalTransition.FAIL_SCAN),
    TransitionRule(ApprovalState.FAILED, ApprovalState.PENDING, ApprovalTransition.RETRY_SCAN, "scans:execute"),
    
    # Policy evaluation (system-triggered)
    TransitionRule(ApprovalState.SCANNED, ApprovalState.AUTO_APPROVED, ApprovalTransition.AUTO_APPROVE),
    TransitionRule(ApprovalState.SCANNED, ApprovalState.NEEDS_REVIEW, ApprovalTransition.REQUIRE_REVIEW),
    
    # Manual review
    TransitionRule(ApprovalState.NEEDS_REVIEW, ApprovalState.APPROVED, ApprovalTransition.APPROVE, 
                   "approvals:approve", requires_comment=False),
    TransitionRule(ApprovalState.NEEDS_REVIEW, ApprovalState.REJECTED, ApprovalTransition.REJECT,
                   "approvals:reject", requires_comment=True),
    
    # Lifecycle management
    TransitionRule(ApprovalState.NEEDS_REVIEW, ApprovalState.EXPIRED, ApprovalTransition.EXPIRE),
    TransitionRule(ApprovalState.APPROVED, ApprovalState.REVOKED, ApprovalTransition.REVOKE,
                   "approvals:reject", requires_comment=True),
    TransitionRule(ApprovalState.AUTO_APPROVED, ApprovalState.REVOKED, ApprovalTransition.REVOKE,
                   "approvals:reject", requires_comment=True),
]

# Build lookup tables for efficient access
VALID_TRANSITIONS: Dict[ApprovalState, Set[ApprovalTransition]] = {}
TRANSITION_TARGETS: Dict[tuple[ApprovalState, ApprovalTransition], TransitionRule] = {}

for rule in TRANSITION_RULES:
    # Populate valid transitions from each state
    if rule.from_state not in VALID_TRANSITIONS:
        VALID_TRANSITIONS[rule.from_state] = set()
    VALID_TRANSITIONS[rule.from_state].add(rule.transition)
    
    # Populate transition target lookup
    TRANSITION_TARGETS[(rule.from_state, rule.transition)] = rule


# Terminal states (no outgoing transitions except admin reset)
TERMINAL_STATES: Set[ApprovalState] = {
    ApprovalState.APPROVED,
    ApprovalState.REJECTED,
    ApprovalState.EXPIRED,
    ApprovalState.REVOKED,
}

# States that require human attention
PENDING_REVIEW_STATES: Set[ApprovalState] = {
    ApprovalState.NEEDS_REVIEW,
}

# States that indicate successful approval
APPROVED_STATES: Set[ApprovalState] = {
    ApprovalState.APPROVED,
    ApprovalState.AUTO_APPROVED,
}

# States that indicate the package is blocked
BLOCKED_STATES: Set[ApprovalState] = {
    ApprovalState.REJECTED,
    ApprovalState.REVOKED,
    ApprovalState.EXPIRED,
}


def can_transition(from_state: ApprovalState, transition: ApprovalTransition) -> bool:
    """Check if a transition is valid from the given state."""
    valid = VALID_TRANSITIONS.get(from_state, set())
    return transition in valid


def get_transition_rule(from_state: ApprovalState, transition: ApprovalTransition) -> Optional[TransitionRule]:
    """Get the transition rule for a state/action combination."""
    return TRANSITION_TARGETS.get((from_state, transition))


def get_target_state(from_state: ApprovalState, transition: ApprovalTransition) -> Optional[ApprovalState]:
    """Get the target state for a transition."""
    rule = get_transition_rule(from_state, transition)
    return rule.to_state if rule else None
