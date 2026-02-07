"""Policy evaluation engine for SafeMirror Enterprise.

Evaluates scan results against security policies to determine
if packages should be auto-approved, require review, or be rejected.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from uuid import UUID
from datetime import datetime

from sqlalchemy.orm import Session

from .rules import Rule, RuleType, RuleOperator, evaluate_rule


class PolicyDecision(str, Enum):
    """Decision outcome from policy evaluation."""
    
    APPROVE = "approve"      # Package passes all rules, can be auto-approved
    REVIEW = "review"        # Package needs manual review
    REJECT = "reject"        # Package fails hard rules, auto-reject


@dataclass
class RuleResult:
    """Result of evaluating a single rule."""
    rule: Rule
    passed: bool
    reason: Optional[str] = None


@dataclass
class PolicyResult:
    """
    Result of evaluating a policy against scan results.
    """
    policy_id: UUID
    policy_name: str
    decision: PolicyDecision
    passed_rules: List[RuleResult] = field(default_factory=list)
    failed_rules: List[RuleResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    evaluated_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def all_passed(self) -> bool:
        """Check if all rules passed."""
        return len(self.failed_rules) == 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for storage."""
        return {
            "policy_id": str(self.policy_id),
            "policy_name": self.policy_name,
            "decision": self.decision.value,
            "passed_rules": len(self.passed_rules),
            "failed_rules": [
                {
                    "rule_type": r.rule.rule_type.value,
                    "reason": r.reason,
                }
                for r in self.failed_rules
            ],
            "warnings": self.warnings,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class PolicyEngine:
    """
    Evaluates packages/scans against security policies.
    
    Policies define rules that packages must satisfy. The engine
    evaluates all applicable rules and returns a decision:
    - APPROVE: All rules pass, package can be auto-approved
    - REVIEW: Soft failures or no policy, needs manual review
    - REJECT: Hard failures, package should be rejected
    """
    
    def __init__(self, db: Session):
        """
        Initialize the policy engine.
        
        Args:
            db: Database session for loading policies
        """
        self.db = db
    
    def evaluate(
        self,
        scan_results: Dict[str, Any],
        package_metadata: Dict[str, Any],
        policy_id: Optional[UUID] = None,
        mirror_id: Optional[UUID] = None,
        org_id: Optional[UUID] = None,
    ) -> PolicyResult:
        """
        Evaluate scan results against a policy.
        
        Args:
            scan_results: Results from package scan
            package_metadata: Package metadata (name, version, etc.)
            policy_id: Specific policy to evaluate against
            mirror_id: Mirror ID to get default policy
            org_id: Organization ID for org-level default policy
            
        Returns:
            PolicyResult with decision and rule results
        """
        # Load the applicable policy
        policy = self._get_policy(policy_id, mirror_id, org_id)
        
        if not policy:
            # No policy = needs review (fail-safe)
            return PolicyResult(
                policy_id=UUID("00000000-0000-0000-0000-000000000000"),
                policy_name="No Policy",
                decision=PolicyDecision.REVIEW,
                warnings=["No applicable policy found; manual review required"],
            )
        
        # Build evaluation context
        context = self._build_context(scan_results, package_metadata)
        
        # Parse and evaluate rules
        rules = self._parse_rules(policy.rules)
        passed_rules = []
        failed_rules = []
        warnings = []
        
        for rule in rules:
            passed, reason = evaluate_rule(rule, context)
            result = RuleResult(rule=rule, passed=passed, reason=reason)
            
            if passed:
                passed_rules.append(result)
            else:
                failed_rules.append(result)
        
        # Determine decision
        decision = self._determine_decision(policy, passed_rules, failed_rules)
        
        return PolicyResult(
            policy_id=policy.id,
            policy_name=policy.name,
            decision=decision,
            passed_rules=passed_rules,
            failed_rules=failed_rules,
            warnings=warnings,
        )
    
    def evaluate_batch(
        self,
        items: List[Dict[str, Any]],
        policy_id: Optional[UUID] = None,
    ) -> List[PolicyResult]:
        """
        Evaluate multiple packages/scans against a policy.
        
        Args:
            items: List of dicts with scan_results and package_metadata
            policy_id: Policy to evaluate against
            
        Returns:
            List of PolicyResults
        """
        return [
            self.evaluate(
                scan_results=item.get("scan_results", {}),
                package_metadata=item.get("package_metadata", {}),
                policy_id=policy_id,
            )
            for item in items
        ]
    
    def _get_policy(
        self,
        policy_id: Optional[UUID],
        mirror_id: Optional[UUID],
        org_id: Optional[UUID],
    ):
        """Get the applicable policy in order of precedence."""
        from enterprise.db.models.policy import Policy
        from enterprise.db.models.mirror import Mirror
        
        # Direct policy ID takes precedence
        if policy_id:
            return self.db.query(Policy).filter(
                Policy.id == policy_id,
                Policy.enabled == True,
            ).first()
        
        # Check mirror-level default policy
        if mirror_id:
            mirror = self.db.query(Mirror).filter(Mirror.id == mirror_id).first()
            if mirror and mirror.policy_id:
                return self.db.query(Policy).filter(
                    Policy.id == mirror.policy_id,
                    Policy.enabled == True,
                ).first()
        
        # Fall back to org-level default policy
        if org_id:
            return self.db.query(Policy).filter(
                Policy.org_id == org_id,
                Policy.enabled == True,
                Policy.name == "Default Policy",
            ).first()
        
        return None
    
    def _build_context(
        self,
        scan_results: Dict[str, Any],
        package_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build evaluation context from scan results and metadata."""
        # Extract vulnerability info
        vulnerabilities = scan_results.get("vulnerabilities", [])
        cves = [v.get("cve_id") for v in vulnerabilities if v.get("cve_id")]
        severities = [v.get("severity", "none").lower() for v in vulnerabilities]
        cvss_scores = [v.get("cvss_score", 0) for v in vulnerabilities if v.get("cvss_score")]
        
        # Determine max severity
        severity_order = ["critical", "high", "medium", "low", "info", "none"]
        max_severity = "none"
        for sev in severity_order:
            if sev in severities:
                max_severity = sev
                break
        
        return {
            # Package info
            "package_name": package_metadata.get("name", ""),
            "package_version": package_metadata.get("version", ""),
            "package_type": package_metadata.get("package_type", ""),
            "license": package_metadata.get("license", ""),
            "maintainer": package_metadata.get("maintainer", ""),
            
            # Vulnerability summary
            "cves": cves,
            "cve_count": len(cves),
            "max_severity": max_severity,
            "max_cvss": max(cvss_scores) if cvss_scores else 0,
            "vulnerabilities": vulnerabilities,
            
            # Scan results
            "has_binaries": scan_results.get("has_binaries", False),
            "dangerous_patterns": scan_results.get("dangerous_patterns", []),
            "risk_score": scan_results.get("risk_score", 0),
            "scan_status": scan_results.get("status", "unknown"),
            
            # Include all raw data for custom rules
            **scan_results,
            **package_metadata,
        }
    
    def _parse_rules(self, rules_config: Dict[str, Any]) -> List[Rule]:
        """Parse rules from policy configuration."""
        rules = []
        
        # Handle list format
        if isinstance(rules_config, list):
            for rule_data in rules_config:
                try:
                    rules.append(Rule.from_dict(rule_data))
                except (ValueError, KeyError):
                    continue
        
        # Handle dict format with shorthand rules
        elif isinstance(rules_config, dict):
            # Severity threshold
            if "max_severity" in rules_config:
                rules.append(Rule(
                    rule_type=RuleType.SEVERITY_MAX,
                    operator=RuleOperator.LESS_THAN_OR_EQUAL,
                    value=rules_config["max_severity"],
                ))
            
            # Max CVE count
            if "max_cve_count" in rules_config:
                rules.append(Rule(
                    rule_type=RuleType.CVE_COUNT_MAX,
                    operator=RuleOperator.LESS_THAN_OR_EQUAL,
                    value=rules_config["max_cve_count"],
                ))
            
            # Max CVSS score
            if "max_cvss" in rules_config:
                rules.append(Rule(
                    rule_type=RuleType.CVSS_MAX,
                    operator=RuleOperator.LESS_THAN_OR_EQUAL,
                    value=rules_config["max_cvss"],
                ))
            
            # Block specific CVEs
            if "blocked_cves" in rules_config:
                rules.append(Rule(
                    rule_type=RuleType.CVE_BLOCKLIST,
                    operator=RuleOperator.NOT_IN,
                    value=rules_config["blocked_cves"],
                ))
            
            # License allowlist
            if "allowed_licenses" in rules_config:
                rules.append(Rule(
                    rule_type=RuleType.LICENSE_ALLOWLIST,
                    operator=RuleOperator.IN,
                    value=rules_config["allowed_licenses"],
                ))
            
            # Allow binaries
            if "allow_binaries" in rules_config:
                rules.append(Rule(
                    rule_type=RuleType.BINARY_ALLOWED,
                    operator=RuleOperator.EQUALS,
                    value=rules_config["allow_binaries"],
                ))
            
            # Check dangerous patterns
            if rules_config.get("check_dangerous_patterns", False):
                rules.append(Rule(
                    rule_type=RuleType.SCRIPT_PATTERNS,
                    operator=RuleOperator.NOT_EXISTS,
                    value=None,
                ))
        
        return rules
    
    def _determine_decision(
        self,
        policy,
        passed_rules: List[RuleResult],
        failed_rules: List[RuleResult],
    ) -> PolicyDecision:
        """Determine the policy decision based on rule results."""
        if not failed_rules:
            # All rules passed - check policy settings
            policy_settings = policy.rules if isinstance(policy.rules, dict) else {}
            
            # Auto-approve if policy allows and all passed
            if policy_settings.get("auto_approve", False):
                return PolicyDecision.APPROVE
            else:
                # Passed but needs review (default safe behavior)
                return PolicyDecision.REVIEW
        
        # Check severity of failures
        hard_failures = []
        soft_failures = []
        
        for result in failed_rules:
            # Severity and CVE rules are hard failures
            if result.rule.rule_type in [
                RuleType.SEVERITY_MAX,
                RuleType.CVE_BLOCKLIST,
                RuleType.CVSS_MAX,
                RuleType.PACKAGE_BLOCKLIST,
            ]:
                hard_failures.append(result)
            else:
                soft_failures.append(result)
        
        if hard_failures:
            return PolicyDecision.REJECT
        
        # Only soft failures = needs review
        return PolicyDecision.REVIEW


# Default policies for quick setup
DEFAULT_POLICIES = {
    "strict": {
        "name": "Strict Security",
        "description": "Strict security policy - no critical or high vulnerabilities",
        "rules": {
            "max_severity": "medium",
            "max_cvss": 6.9,
            "max_cve_count": 10,
            "allow_binaries": True,
            "check_dangerous_patterns": True,
            "auto_approve": False,  # Always require review
        },
    },
    "moderate": {
        "name": "Moderate Security",
        "description": "Moderate security policy - allows high severity with review",
        "rules": {
            "max_severity": "high",
            "max_cvss": 8.9,
            "max_cve_count": 25,
            "allow_binaries": True,
            "check_dangerous_patterns": True,
            "auto_approve": False,
        },
    },
    "permissive": {
        "name": "Permissive",
        "description": "Permissive policy - only blocks critical vulnerabilities",
        "rules": {
            "max_severity": "critical",
            "max_cvss": 10.0,
            "allow_binaries": True,
            "check_dangerous_patterns": False,
            "auto_approve": True,  # Auto-approve if passes
        },
    },
}
