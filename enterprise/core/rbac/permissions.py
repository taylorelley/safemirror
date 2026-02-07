"""Permission model for SafeMirror Enterprise RBAC.

Defines all resources, actions, and permission combinations.
Uses a matrix approach: permissions = actions × resources.

Permission string format: "resource:action"
Examples:
  - mirrors:read
  - packages:approve
  - roles:manage
  - audit_logs:export
"""

from enum import Enum
from typing import NamedTuple, FrozenSet


class Resource(str, Enum):
    """Resources that can be protected by permissions."""
    
    # Core scanning resources
    MIRRORS = "mirrors"           # Package mirror configurations
    PACKAGES = "packages"         # Scanned packages
    SCANS = "scans"               # Scan jobs and results
    
    # Approval workflow resources
    APPROVALS = "approvals"       # Package approval decisions
    POLICIES = "policies"         # Approval policies / security rules
    
    # User management resources
    USERS = "users"               # User accounts
    ROLES = "roles"               # Role definitions
    API_KEYS = "api_keys"         # API key management
    
    # Audit and compliance
    AUDIT_LOGS = "audit_logs"     # System audit trail
    REPORTS = "reports"           # Compliance reports
    
    # System administration
    ORGANIZATION = "organization" # Organization settings
    SSO_CONFIG = "sso_config"     # SSO/SAML/OIDC configuration
    SYSTEM = "system"             # System-wide settings


class Action(str, Enum):
    """Actions that can be performed on resources."""
    
    # Standard CRUD actions
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    
    # Specialized actions
    APPROVE = "approve"           # Approve packages/requests
    REJECT = "reject"             # Reject packages/requests
    EXPORT = "export"             # Export data (CSV, JSON, PDF)
    MANAGE = "manage"             # Full management (create/update/delete)
    EXECUTE = "execute"           # Execute scans
    CONFIGURE = "configure"       # System configuration
    ASSIGN = "assign"             # Assign roles to users


class Permission(NamedTuple):
    """A permission is a combination of resource and action."""
    resource: Resource
    action: Action
    
    def __str__(self) -> str:
        return f"{self.resource.value}:{self.action.value}"
    
    @classmethod
    def from_string(cls, perm_str: str) -> "Permission":
        """Parse a permission string like 'mirrors:read'."""
        parts = perm_str.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid permission format: {perm_str}")
        return cls(Resource(parts[0]), Action(parts[1]))


# Permission definitions matrix
# Maps each resource to its valid actions
PERMISSION_MATRIX: dict[Resource, FrozenSet[Action]] = {
    Resource.MIRRORS: frozenset([
        Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, 
        Action.LIST, Action.CONFIGURE,
    ]),
    Resource.PACKAGES: frozenset([
        Action.READ, Action.LIST, Action.APPROVE, Action.REJECT, Action.DELETE,
    ]),
    Resource.SCANS: frozenset([
        Action.CREATE, Action.READ, Action.LIST, Action.EXECUTE, Action.DELETE,
    ]),
    Resource.APPROVALS: frozenset([
        Action.READ, Action.LIST, Action.APPROVE, Action.REJECT,
    ]),
    Resource.POLICIES: frozenset([
        Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, Action.LIST,
    ]),
    Resource.USERS: frozenset([
        Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, 
        Action.LIST, Action.MANAGE,
    ]),
    Resource.ROLES: frozenset([
        Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, 
        Action.LIST, Action.MANAGE, Action.ASSIGN,
    ]),
    Resource.API_KEYS: frozenset([
        Action.CREATE, Action.READ, Action.DELETE, Action.LIST,
    ]),
    Resource.AUDIT_LOGS: frozenset([
        Action.READ, Action.LIST, Action.EXPORT,
    ]),
    Resource.REPORTS: frozenset([
        Action.CREATE, Action.READ, Action.LIST, Action.EXPORT,
    ]),
    Resource.ORGANIZATION: frozenset([
        Action.READ, Action.UPDATE, Action.CONFIGURE,
    ]),
    Resource.SSO_CONFIG: frozenset([
        Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, Action.CONFIGURE,
    ]),
    Resource.SYSTEM: frozenset([
        Action.READ, Action.CONFIGURE, Action.MANAGE,
    ]),
}


def _generate_permission_definitions() -> dict[str, Permission]:
    """Generate all valid permission combinations from the matrix."""
    permissions = {}
    for resource, actions in PERMISSION_MATRIX.items():
        for action in actions:
            perm = Permission(resource, action)
            permissions[str(perm)] = perm
    return permissions


# All valid permissions as a dictionary: "resource:action" -> Permission
PERMISSION_DEFINITIONS = _generate_permission_definitions()


# Convenience sets for common permission patterns
READONLY_ACTIONS = frozenset([Action.READ, Action.LIST])
WRITE_ACTIONS = frozenset([Action.CREATE, Action.UPDATE, Action.DELETE])
APPROVAL_ACTIONS = frozenset([Action.APPROVE, Action.REJECT])
ADMIN_ACTIONS = frozenset([Action.MANAGE, Action.CONFIGURE, Action.ASSIGN])


def is_valid_permission(perm_str: str) -> bool:
    """Check if a permission string is valid."""
    return perm_str in PERMISSION_DEFINITIONS


def get_permissions_for_resource(resource: Resource) -> list[str]:
    """Get all valid permission strings for a resource."""
    return [
        str(Permission(resource, action))
        for action in PERMISSION_MATRIX.get(resource, set())
    ]


def get_all_permissions() -> list[str]:
    """Get all valid permission strings."""
    return list(PERMISSION_DEFINITIONS.keys())
