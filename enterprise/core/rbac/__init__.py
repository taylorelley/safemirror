"""RBAC (Role-Based Access Control) module for SafeMirror Enterprise.

This module defines the permission model, role definitions, and access control utilities.
"""

from .permissions import Permission, Resource, Action, PERMISSION_DEFINITIONS
from .checker import PermissionChecker, has_permission, require_permission

__all__ = [
    "Permission",
    "Resource", 
    "Action",
    "PERMISSION_DEFINITIONS",
    "PermissionChecker",
    "has_permission",
    "require_permission",
]
