"""Tests for approval workflow state machine."""

import pytest
from uuid import uuid4
from datetime import datetime

from enterprise.core.approval.states import (
    ApprovalState, ApprovalTransition,
    VALID_TRANSITIONS, TERMINAL_STATES,
    PENDING_REVIEW_STATES, APPROVED_STATES, BLOCKED_STATES,
    can_transition, get_target_state, get_transition_rule,
)
from enterprise.core.approval.machine import (
    ApprovalStateMachine, TransitionError, PermissionDeniedError,
)


class TestApprovalStates:
    """Test approval state definitions."""
    
    def test_all_states_defined(self):
        """Test that all expected states exist."""
        expected_states = [
            "pending", "scanning", "scanned", "failed",
            "auto_approved", "needs_review",
            "approved", "rejected", "expired", "revoked",
        ]
        for state_name in expected_states:
            assert hasattr(ApprovalState, state_name.upper())
    
    def test_terminal_states(self):
        """Test terminal state definitions."""
        assert ApprovalState.APPROVED in TERMINAL_STATES
        assert ApprovalState.REJECTED in TERMINAL_STATES
        assert ApprovalState.EXPIRED in TERMINAL_STATES
        assert ApprovalState.REVOKED in TERMINAL_STATES
        
        assert ApprovalState.PENDING not in TERMINAL_STATES
        assert ApprovalState.SCANNING not in TERMINAL_STATES
    
    def test_pending_review_states(self):
        """Test pending review state definitions."""
        assert ApprovalState.NEEDS_REVIEW in PENDING_REVIEW_STATES
        assert ApprovalState.PENDING not in PENDING_REVIEW_STATES
        assert ApprovalState.APPROVED not in PENDING_REVIEW_STATES
    
    def test_approved_states(self):
        """Test approved state definitions."""
        assert ApprovalState.APPROVED in APPROVED_STATES
        assert ApprovalState.AUTO_APPROVED in APPROVED_STATES
        assert ApprovalState.NEEDS_REVIEW not in APPROVED_STATES
    
    def test_blocked_states(self):
        """Test blocked state definitions."""
        assert ApprovalState.REJECTED in BLOCKED_STATES
        assert ApprovalState.REVOKED in BLOCKED_STATES
        assert ApprovalState.EXPIRED in BLOCKED_STATES
        assert ApprovalState.APPROVED not in BLOCKED_STATES


class TestApprovalTransitions:
    """Test valid state transitions."""
    
    def test_pending_transitions(self):
        """Test valid transitions from PENDING state."""
        assert can_transition(ApprovalState.PENDING, ApprovalTransition.START_SCAN)
        assert not can_transition(ApprovalState.PENDING, ApprovalTransition.APPROVE)
        assert not can_transition(ApprovalState.PENDING, ApprovalTransition.COMPLETE_SCAN)
    
    def test_scanning_transitions(self):
        """Test valid transitions from SCANNING state."""
        assert can_transition(ApprovalState.SCANNING, ApprovalTransition.COMPLETE_SCAN)
        assert can_transition(ApprovalState.SCANNING, ApprovalTransition.FAIL_SCAN)
        assert not can_transition(ApprovalState.SCANNING, ApprovalTransition.APPROVE)
    
    def test_scanned_transitions(self):
        """Test valid transitions from SCANNED state."""
        assert can_transition(ApprovalState.SCANNED, ApprovalTransition.AUTO_APPROVE)
        assert can_transition(ApprovalState.SCANNED, ApprovalTransition.REQUIRE_REVIEW)
        assert not can_transition(ApprovalState.SCANNED, ApprovalTransition.APPROVE)
    
    def test_needs_review_transitions(self):
        """Test valid transitions from NEEDS_REVIEW state."""
        assert can_transition(ApprovalState.NEEDS_REVIEW, ApprovalTransition.APPROVE)
        assert can_transition(ApprovalState.NEEDS_REVIEW, ApprovalTransition.REJECT)
        assert can_transition(ApprovalState.NEEDS_REVIEW, ApprovalTransition.EXPIRE)
        assert not can_transition(ApprovalState.NEEDS_REVIEW, ApprovalTransition.START_SCAN)
    
    def test_approved_transitions(self):
        """Test valid transitions from APPROVED state."""
        assert can_transition(ApprovalState.APPROVED, ApprovalTransition.REVOKE)
        assert not can_transition(ApprovalState.APPROVED, ApprovalTransition.APPROVE)
        assert not can_transition(ApprovalState.APPROVED, ApprovalTransition.START_SCAN)
    
    def test_terminal_states_no_outgoing(self):
        """Test terminal states have limited outgoing transitions."""
        assert not can_transition(ApprovalState.REJECTED, ApprovalTransition.APPROVE)
        assert not can_transition(ApprovalState.EXPIRED, ApprovalTransition.APPROVE)
        # REVOKED is terminal but we already tested APPROVED can be revoked
    
    def test_get_target_state(self):
        """Test getting target state from transition."""
        target = get_target_state(ApprovalState.PENDING, ApprovalTransition.START_SCAN)
        assert target == ApprovalState.SCANNING
        
        target = get_target_state(ApprovalState.NEEDS_REVIEW, ApprovalTransition.APPROVE)
        assert target == ApprovalState.APPROVED
        
        target = get_target_state(ApprovalState.PENDING, ApprovalTransition.APPROVE)
        assert target is None  # Invalid transition
    
    def test_transition_rule_permissions(self):
        """Test transition rules have correct permission requirements."""
        # Approve requires permission
        rule = get_transition_rule(ApprovalState.NEEDS_REVIEW, ApprovalTransition.APPROVE)
        assert rule is not None
        assert rule.requires_permission == "approvals:approve"
        
        # Reject requires comment
        rule = get_transition_rule(ApprovalState.NEEDS_REVIEW, ApprovalTransition.REJECT)
        assert rule is not None
        assert rule.requires_comment is True
        
        # System transitions don't require permissions
        rule = get_transition_rule(ApprovalState.SCANNING, ApprovalTransition.COMPLETE_SCAN)
        assert rule is not None
        assert rule.requires_permission is None


class TestApprovalStateMachine:
    """Test ApprovalStateMachine class."""
    
    def test_initial_state(self):
        """Test initial state is correct."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
        )
        assert machine.state == ApprovalState.PENDING
        assert not machine.is_terminal
    
    def test_available_transitions(self):
        """Test getting available transitions."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        available = machine.get_available_transitions()
        assert ApprovalTransition.START_SCAN in available
        assert ApprovalTransition.APPROVE not in available
    
    def test_simple_transition(self):
        """Test performing a simple transition."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
        )
        
        new_state = machine.transition(ApprovalTransition.START_SCAN)
        assert new_state == ApprovalState.SCANNING
        assert machine.state == ApprovalState.SCANNING
    
    def test_invalid_transition_raises(self):
        """Test that invalid transition raises error."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
        )
        
        with pytest.raises(TransitionError):
            machine.transition(ApprovalTransition.APPROVE)
    
    def test_permission_required_transition(self):
        """Test transition requiring permission."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.NEEDS_REVIEW,
            org_id=uuid4(),
            user_permissions=[],  # No permissions
        )
        
        with pytest.raises(PermissionDeniedError):
            machine.transition(ApprovalTransition.APPROVE)
    
    def test_permission_granted_transition(self):
        """Test transition with permission granted."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.NEEDS_REVIEW,
            org_id=uuid4(),
            user_permissions=["approvals:approve"],
        )
        
        new_state = machine.transition(ApprovalTransition.APPROVE)
        assert new_state == ApprovalState.APPROVED
    
    def test_wildcard_permission(self):
        """Test transition with wildcard permission."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.NEEDS_REVIEW,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        
        new_state = machine.transition(ApprovalTransition.APPROVE)
        assert new_state == ApprovalState.APPROVED
    
    def test_comment_required_transition(self):
        """Test transition requiring comment."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.NEEDS_REVIEW,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        
        # Should fail without comment
        with pytest.raises(TransitionError):
            machine.transition(ApprovalTransition.REJECT)
        
        # Should succeed with comment
        machine2 = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.NEEDS_REVIEW,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        new_state = machine2.transition(ApprovalTransition.REJECT, comment="Security issue found")
        assert new_state == ApprovalState.REJECTED
    
    def test_transition_history(self):
        """Test that transition history is recorded."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
        )
        
        machine.transition(ApprovalTransition.START_SCAN)
        machine.transition(ApprovalTransition.COMPLETE_SCAN)
        machine.transition(ApprovalTransition.REQUIRE_REVIEW)
        
        history = machine.get_history()
        assert len(history) == 3
        assert history[0]["from_state"] == "pending"
        assert history[0]["to_state"] == "scanning"
    
    def test_is_terminal(self):
        """Test terminal state detection."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.APPROVED,
            org_id=uuid4(),
        )
        assert machine.is_terminal
        
        machine2 = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.NEEDS_REVIEW,
            org_id=uuid4(),
        )
        assert not machine2.is_terminal
    
    def test_callback_execution(self):
        """Test callback is executed on transition."""
        callback_called = []
        
        def my_callback(record):
            callback_called.append(record)
        
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
        )
        machine.register_callback(ApprovalTransition.START_SCAN, my_callback)
        
        machine.transition(ApprovalTransition.START_SCAN)
        
        assert len(callback_called) == 1
        assert callback_called[0]["transition"] == "start_scan"


class TestWorkflowScenarios:
    """Test complete workflow scenarios."""
    
    def test_happy_path_auto_approve(self):
        """Test happy path: scan → auto-approve."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        
        # Scan lifecycle
        machine.transition(ApprovalTransition.START_SCAN)
        assert machine.state == ApprovalState.SCANNING
        
        machine.transition(ApprovalTransition.COMPLETE_SCAN)
        assert machine.state == ApprovalState.SCANNED
        
        # Policy says auto-approve
        machine.transition(ApprovalTransition.AUTO_APPROVE)
        assert machine.state == ApprovalState.AUTO_APPROVED
        assert machine.is_terminal is False  # Can still be revoked
    
    def test_happy_path_manual_review(self):
        """Test happy path: scan → review → approve."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        
        machine.transition(ApprovalTransition.START_SCAN)
        machine.transition(ApprovalTransition.COMPLETE_SCAN)
        machine.transition(ApprovalTransition.REQUIRE_REVIEW)
        
        assert machine.state == ApprovalState.NEEDS_REVIEW
        
        machine.transition(ApprovalTransition.APPROVE, user_id=uuid4())
        assert machine.state == ApprovalState.APPROVED
        assert machine.is_terminal
    
    def test_rejection_path(self):
        """Test rejection path: scan → review → reject."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        
        machine.transition(ApprovalTransition.START_SCAN)
        machine.transition(ApprovalTransition.COMPLETE_SCAN)
        machine.transition(ApprovalTransition.REQUIRE_REVIEW)
        
        machine.transition(
            ApprovalTransition.REJECT, 
            comment="Critical vulnerability CVE-2024-1234",
            user_id=uuid4(),
        )
        
        assert machine.state == ApprovalState.REJECTED
        assert machine.is_terminal
    
    def test_scan_failure_retry(self):
        """Test scan failure and retry."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.PENDING,
            org_id=uuid4(),
            user_permissions=["scans:execute"],
        )
        
        machine.transition(ApprovalTransition.START_SCAN)
        machine.transition(ApprovalTransition.FAIL_SCAN)
        
        assert machine.state == ApprovalState.FAILED
        
        machine.transition(ApprovalTransition.RETRY_SCAN)
        assert machine.state == ApprovalState.PENDING
    
    def test_revocation_after_approval(self):
        """Test revoking an approved package."""
        machine = ApprovalStateMachine(
            entity_id=uuid4(),
            current_state=ApprovalState.APPROVED,
            org_id=uuid4(),
            user_permissions=["*:*"],
        )
        
        machine.transition(
            ApprovalTransition.REVOKE,
            comment="New critical vulnerability discovered",
            user_id=uuid4(),
        )
        
        assert machine.state == ApprovalState.REVOKED
        assert machine.is_terminal
