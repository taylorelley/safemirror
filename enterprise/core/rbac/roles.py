"""Default role definitions for SafeMirror Enterprise.

Defines the 5 standard roles with their permission sets:
1. Admin - Full system access
2. Developer - Package viewing and scan execution
3. Security Analyst - Approval workflow and policy management  
4. Auditor - Read-only access with audit log export
5. Viewer - Basic read-only access
"""

from typing import Dict, List
from .permissions import Resource, Action, Permission


def _build_permissions(*perms: tuple) -> List[str]:
    """Build permission strings from (Resource, Action) tuples."""
    return [str(Permission(r, a)) for r, a in perms]


# Admin: Full access to everything
ADMIN_PERMISSIONS = [
    "*:*"  # Global wildcard - all permissions
]

# Developer: Work with packages and scans, basic access to mirrors
DEVELOPER_PERMISSIONS = _build_permissions(
    # Mirrors - read only
    (Resource.MIRRORS, Action.READ),
    (Resource.MIRRORS, Action.LIST),
    
    # Packages - full read access
    (Resource.PACKAGES, Action.READ),
    (Resource.PACKAGES, Action.LIST),
    
    # Scans - can execute and view scans
    (Resource.SCANS, Action.CREATE),
    (Resource.SCANS, Action.READ),
    (Resource.SCANS, Action.LIST),
    (Resource.SCANS, Action.EXECUTE),
    
    # Approvals - can view pending approvals
    (Resource.APPROVALS, Action.READ),
    (Resource.APPROVALS, Action.LIST),
    
    # Own API keys
    (Resource.API_KEYS, Action.CREATE),
    (Resource.API_KEYS, Action.READ),
    (Resource.API_KEYS, Action.LIST),
    (Resource.API_KEYS, Action.DELETE),
    
    # Reports - view only
    (Resource.REPORTS, Action.READ),
    (Resource.REPORTS, Action.LIST),
)

# Security Analyst: Approval workflow, policy management, security focus
SECURITY_ANALYST_PERMISSIONS = _build_permissions(
    # Mirrors - full access for configuration
    (Resource.MIRRORS, Action.CREATE),
    (Resource.MIRRORS, Action.READ),
    (Resource.MIRRORS, Action.UPDATE),
    (Resource.MIRRORS, Action.DELETE),
    (Resource.MIRRORS, Action.LIST),
    (Resource.MIRRORS, Action.CONFIGURE),
    
    # Packages - full access including approval
    (Resource.PACKAGES, Action.READ),
    (Resource.PACKAGES, Action.LIST),
    (Resource.PACKAGES, Action.APPROVE),
    (Resource.PACKAGES, Action.REJECT),
    (Resource.PACKAGES, Action.DELETE),
    
    # Scans - full access
    (Resource.SCANS, Action.CREATE),
    (Resource.SCANS, Action.READ),
    (Resource.SCANS, Action.LIST),
    (Resource.SCANS, Action.EXECUTE),
    (Resource.SCANS, Action.DELETE),
    
    # Approvals - full workflow access
    (Resource.APPROVALS, Action.READ),
    (Resource.APPROVALS, Action.LIST),
    (Resource.APPROVALS, Action.APPROVE),
    (Resource.APPROVALS, Action.REJECT),
    
    # Policies - can manage security policies
    (Resource.POLICIES, Action.CREATE),
    (Resource.POLICIES, Action.READ),
    (Resource.POLICIES, Action.UPDATE),
    (Resource.POLICIES, Action.DELETE),
    (Resource.POLICIES, Action.LIST),
    
    # Audit logs - can view and export
    (Resource.AUDIT_LOGS, Action.READ),
    (Resource.AUDIT_LOGS, Action.LIST),
    (Resource.AUDIT_LOGS, Action.EXPORT),
    
    # Reports - full access
    (Resource.REPORTS, Action.CREATE),
    (Resource.REPORTS, Action.READ),
    (Resource.REPORTS, Action.LIST),
    (Resource.REPORTS, Action.EXPORT),
    
    # API keys - own keys only
    (Resource.API_KEYS, Action.CREATE),
    (Resource.API_KEYS, Action.READ),
    (Resource.API_KEYS, Action.LIST),
    (Resource.API_KEYS, Action.DELETE),
)

# Auditor: Read-only with audit log export capability
AUDITOR_PERMISSIONS = _build_permissions(
    # Mirrors - read only
    (Resource.MIRRORS, Action.READ),
    (Resource.MIRRORS, Action.LIST),
    
    # Packages - read only
    (Resource.PACKAGES, Action.READ),
    (Resource.PACKAGES, Action.LIST),
    
    # Scans - read only
    (Resource.SCANS, Action.READ),
    (Resource.SCANS, Action.LIST),
    
    # Approvals - read only
    (Resource.APPROVALS, Action.READ),
    (Resource.APPROVALS, Action.LIST),
    
    # Policies - read only
    (Resource.POLICIES, Action.READ),
    (Resource.POLICIES, Action.LIST),
    
    # Users - read only (for audit context)
    (Resource.USERS, Action.READ),
    (Resource.USERS, Action.LIST),
    
    # Roles - read only
    (Resource.ROLES, Action.READ),
    (Resource.ROLES, Action.LIST),
    
    # Audit logs - full access including export
    (Resource.AUDIT_LOGS, Action.READ),
    (Resource.AUDIT_LOGS, Action.LIST),
    (Resource.AUDIT_LOGS, Action.EXPORT),
    
    # Reports - full access
    (Resource.REPORTS, Action.CREATE),
    (Resource.REPORTS, Action.READ),
    (Resource.REPORTS, Action.LIST),
    (Resource.REPORTS, Action.EXPORT),
    
    # Organization - read only
    (Resource.ORGANIZATION, Action.READ),
)

# Viewer: Minimal read-only access
VIEWER_PERMISSIONS = _build_permissions(
    # Mirrors - list and view
    (Resource.MIRRORS, Action.READ),
    (Resource.MIRRORS, Action.LIST),
    
    # Packages - list and view
    (Resource.PACKAGES, Action.READ),
    (Resource.PACKAGES, Action.LIST),
    
    # Scans - list and view
    (Resource.SCANS, Action.READ),
    (Resource.SCANS, Action.LIST),
    
    # Approvals - list and view (to see what's pending)
    (Resource.APPROVALS, Action.READ),
    (Resource.APPROVALS, Action.LIST),
    
    # Reports - read only
    (Resource.REPORTS, Action.READ),
    (Resource.REPORTS, Action.LIST),
)


# Default roles configuration
DEFAULT_ROLES: Dict[str, dict] = {
    "admin": {
        "name": "Admin",
        "description": "Full system access with all permissions",
        "permissions": ADMIN_PERMISSIONS,
        "is_system": True,
    },
    "developer": {
        "name": "Developer",
        "description": "Can view packages, execute scans, and manage own API keys",
        "permissions": DEVELOPER_PERMISSIONS,
        "is_system": True,
    },
    "security_analyst": {
        "name": "Security Analyst",
        "description": "Manages approval workflows, policies, and security configurations",
        "permissions": SECURITY_ANALYST_PERMISSIONS,
        "is_system": True,
    },
    "auditor": {
        "name": "Auditor",
        "description": "Read-only access with audit log and report export capabilities",
        "permissions": AUDITOR_PERMISSIONS,
        "is_system": True,
    },
    "viewer": {
        "name": "Viewer",
        "description": "Basic read-only access to packages, scans, and reports",
        "permissions": VIEWER_PERMISSIONS,
        "is_system": True,
    },
}


def get_default_role_permissions(role_key: str) -> List[str]:
    """Get permissions list for a default role."""
    role = DEFAULT_ROLES.get(role_key)
    if not role:
        raise ValueError(f"Unknown default role: {role_key}")
    return role["permissions"]


def get_all_default_roles() -> Dict[str, dict]:
    """Get all default role definitions."""
    return DEFAULT_ROLES.copy()
