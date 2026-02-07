"""Policy rule definitions for SafeMirror Enterprise.

Rules define conditions that scan results must match.
Policies are collections of rules with AND/OR logic.
"""

from enum import Enum
from typing import Any, Dict, Optional, List
from dataclasses import dataclass


class RuleType(str, Enum):
    """Types of policy rules."""
    
    # Vulnerability rules
    SEVERITY_MAX = "severity_max"           # Max allowed severity (critical, high, medium, low)
    CVE_COUNT_MAX = "cve_count_max"         # Max number of CVEs
    CVE_BLOCKLIST = "cve_blocklist"         # Block specific CVEs
    CVSS_MAX = "cvss_max"                   # Max CVSS score
    
    # License rules
    LICENSE_ALLOWLIST = "license_allowlist" # Only allow specific licenses
    LICENSE_BLOCKLIST = "license_blocklist" # Block specific licenses
    
    # Package rules
    PACKAGE_BLOCKLIST = "package_blocklist" # Block specific packages
    PACKAGE_ALLOWLIST = "package_allowlist" # Only allow specific packages
    MAINTAINER_ALLOWLIST = "maintainer_allowlist"  # Only allow packages from specific maintainers
    
    # Age/freshness rules
    PACKAGE_AGE_MAX_DAYS = "package_age_max_days"  # Max package age
    
    # Binary/script rules
    BINARY_ALLOWED = "binary_allowed"       # Allow binaries
    SCRIPT_PATTERNS = "script_patterns"     # Check for dangerous script patterns
    
    # Custom rules
    CUSTOM_FIELD = "custom_field"           # Check custom metadata field


class RuleOperator(str, Enum):
    """Operators for rule comparisons."""
    
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"           # Regex match
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


@dataclass
class Rule:
    """
    A single policy rule.
    
    Defines a condition that must be satisfied for a package/scan
    to pass policy evaluation.
    """
    rule_type: RuleType
    operator: RuleOperator
    value: Any
    field: Optional[str] = None  # For custom field rules
    message: Optional[str] = None  # Custom failure message
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization."""
        return {
            "rule_type": self.rule_type.value,
            "operator": self.operator.value,
            "value": self.value,
            "field": self.field,
            "message": self.message,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        """Create rule from dictionary."""
        return cls(
            rule_type=RuleType(data["rule_type"]),
            operator=RuleOperator(data["operator"]),
            value=data["value"],
            field=data.get("field"),
            message=data.get("message"),
        )


# Severity level ordering (higher = more severe)
SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "none": 0,
}


def compare_severity(actual: str, threshold: str) -> bool:
    """
    Check if actual severity is at or below threshold.
    
    Returns True if actual is acceptable (at or below threshold).
    """
    actual_level = SEVERITY_LEVELS.get(actual.lower(), 0)
    threshold_level = SEVERITY_LEVELS.get(threshold.lower(), 0)
    return actual_level <= threshold_level


def evaluate_rule(rule: Rule, context: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Evaluate a single rule against scan context.
    
    Args:
        rule: The rule to evaluate
        context: Scan results and package metadata
        
    Returns:
        Tuple of (passed, reason)
    """
    try:
        if rule.rule_type == RuleType.SEVERITY_MAX:
            max_severity = context.get("max_severity", "none")
            passed = compare_severity(max_severity, rule.value)
            if not passed:
                return False, f"Max severity {max_severity} exceeds threshold {rule.value}"
            return True, None
        
        elif rule.rule_type == RuleType.CVE_COUNT_MAX:
            cve_count = len(context.get("cves", []))
            passed = cve_count <= rule.value
            if not passed:
                return False, f"CVE count {cve_count} exceeds maximum {rule.value}"
            return True, None
        
        elif rule.rule_type == RuleType.CVE_BLOCKLIST:
            cves = set(context.get("cves", []))
            blocked = set(rule.value) if isinstance(rule.value, list) else {rule.value}
            found_blocked = cves & blocked
            if found_blocked:
                return False, f"Blocked CVEs found: {', '.join(found_blocked)}"
            return True, None
        
        elif rule.rule_type == RuleType.CVSS_MAX:
            max_cvss = context.get("max_cvss", 0)
            passed = max_cvss <= rule.value
            if not passed:
                return False, f"CVSS score {max_cvss} exceeds maximum {rule.value}"
            return True, None
        
        elif rule.rule_type == RuleType.LICENSE_ALLOWLIST:
            license_value = context.get("license", "").lower()
            allowed = [l.lower() for l in rule.value] if isinstance(rule.value, list) else [rule.value.lower()]
            # Allow if any allowed license matches
            passed = any(l in license_value for l in allowed) if license_value else False
            if not passed:
                return False, f"License \"{context.get(license, unknown)}\" not in allowlist"
            return True, None
        
        elif rule.rule_type == RuleType.LICENSE_BLOCKLIST:
            license_value = context.get("license", "").lower()
            blocked = [l.lower() for l in rule.value] if isinstance(rule.value, list) else [rule.value.lower()]
            found = any(l in license_value for l in blocked)
            if found:
                return False, f"License \"{context.get(license)}\" is blocked"
            return True, None
        
        elif rule.rule_type == RuleType.PACKAGE_BLOCKLIST:
            package_name = context.get("package_name", "").lower()
            blocked = [p.lower() for p in rule.value] if isinstance(rule.value, list) else [rule.value.lower()]
            if package_name in blocked:
                return False, f"Package \"{package_name}\" is blocked"
            return True, None
        
        elif rule.rule_type == RuleType.BINARY_ALLOWED:
            has_binaries = context.get("has_binaries", False)
            if has_binaries and not rule.value:
                return False, "Package contains binaries but binaries are not allowed"
            return True, None
        
        elif rule.rule_type == RuleType.SCRIPT_PATTERNS:
            dangerous_patterns = context.get("dangerous_patterns", [])
            if dangerous_patterns:
                return False, f"Dangerous script patterns found: {', '.join(dangerous_patterns[:5])}"
            return True, None
        
        elif rule.rule_type == RuleType.CUSTOM_FIELD:
            if not rule.field:
                return False, "Custom field rule missing field name"
            
            actual = context.get(rule.field)
            return _compare_values(actual, rule.operator, rule.value)
        
        # Default: unknown rule type passes (fail-open for forward compatibility)
        return True, None
        
    except Exception as e:
        return False, f"Rule evaluation error: {str(e)}"


def _compare_values(actual: Any, operator: RuleOperator, expected: Any) -> tuple[bool, Optional[str]]:
    """Compare values using the specified operator."""
    try:
        if operator == RuleOperator.EQUALS:
            passed = actual == expected
        elif operator == RuleOperator.NOT_EQUALS:
            passed = actual != expected
        elif operator == RuleOperator.GREATER_THAN:
            passed = actual > expected
        elif operator == RuleOperator.GREATER_THAN_OR_EQUAL:
            passed = actual >= expected
        elif operator == RuleOperator.LESS_THAN:
            passed = actual < expected
        elif operator == RuleOperator.LESS_THAN_OR_EQUAL:
            passed = actual <= expected
        elif operator == RuleOperator.IN:
            passed = actual in expected
        elif operator == RuleOperator.NOT_IN:
            passed = actual not in expected
        elif operator == RuleOperator.CONTAINS:
            passed = expected in actual if actual else False
        elif operator == RuleOperator.NOT_CONTAINS:
            passed = expected not in actual if actual else True
        elif operator == RuleOperator.EXISTS:
            passed = actual is not None
        elif operator == RuleOperator.NOT_EXISTS:
            passed = actual is None
        else:
            return False, f"Unknown operator: {operator}"
        
        if not passed:
            return False, f"Comparison failed: {actual} {operator.value} {expected}"
        return True, None
        
    except Exception as e:
        return False, f"Comparison error: {str(e)}"
