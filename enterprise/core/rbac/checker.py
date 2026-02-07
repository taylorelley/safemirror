"""Permission checking utilities for SafeMirror Enterprise.

Provides decorators and utilities for enforcing RBAC permissions.
"""

from functools import wraps
from typing import Callable, Optional, Union, List
from uuid import UUID

from fastapi import HTTPException, status, Request

from .permissions import Permission, Resource, Action, is_valid_permission


class PermissionChecker:
    """Checks if a user has specific permissions based on their role."""
    
    def __init__(self, user_permissions: list[str], org_id: Optional[UUID] = None):
        """
        Initialize with user's permissions list.
        
        Args:
            user_permissions: List of permission strings from user's role
            org_id: User's organization ID for scoped checks
        """
        self.permissions = set(user_permissions)
        self.org_id = org_id
    
    def has_permission(self, permission: Union[str, Permission]) -> bool:
        """Check if user has a specific permission."""
        perm_str = str(permission) if isinstance(permission, Permission) else permission
        
        # Wildcard check: resource:* grants all actions on resource
        if perm_str in self.permissions:
            return True
            
        # Check for wildcard permission on resource
        if ":" in perm_str:
            resource = perm_str.split(":")[0]
            if f"{resource}:*" in self.permissions:
                return True
            # Global admin wildcard
            if "*:*" in self.permissions:
                return True
        
        return False
    
    def has_any_permission(self, permissions: List[Union[str, Permission]]) -> bool:
        """Check if user has any of the given permissions."""
        return any(self.has_permission(p) for p in permissions)
    
    def has_all_permissions(self, permissions: List[Union[str, Permission]]) -> bool:
        """Check if user has all of the given permissions."""
        return all(self.has_permission(p) for p in permissions)
    
    def can_access_resource(self, resource: Resource, action: Action) -> bool:
        """Check if user can perform action on resource."""
        return self.has_permission(Permission(resource, action))
    
    def get_accessible_resources(self, action: Action) -> list[Resource]:
        """Get list of resources the user can perform the action on."""
        accessible = []
        for resource in Resource:
            if self.can_access_resource(resource, action):
                accessible.append(resource)
        return accessible


def has_permission(user, permission: Union[str, Permission]) -> bool:
    """
    Check if a user has a specific permission.
    
    Args:
        user: User model instance with role relationship
        permission: Permission string or Permission object
        
    Returns:
        True if user has the permission
    """
    if not user or not user.role:
        return False
    
    checker = PermissionChecker(user.role.permissions or [])
    return checker.has_permission(permission)


def require_permission(*permissions: Union[str, Permission], require_all: bool = False):
    """
    Decorator factory for FastAPI endpoints requiring specific permissions.
    
    Args:
        permissions: One or more permission strings or Permission objects
        require_all: If True, user must have ALL permissions. Default: any one.
    
    Usage:
        @router.get("/mirrors")
        @require_permission("mirrors:list")
        async def list_mirrors(current_user: User = Depends(get_current_user)):
            ...
            
        @router.delete("/mirrors/{id}")
        @require_permission("mirrors:delete", "mirrors:manage")
        async def delete_mirror(id: UUID, current_user: User = Depends(get_current_user)):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the current_user in kwargs (injected by FastAPI Depends)
            current_user = kwargs.get("current_user")
            if not current_user:
                # Try to find it in args for methods
                for arg in args:
                    if hasattr(arg, "role") and hasattr(arg, "org_id"):
                        current_user = arg
                        break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if not current_user.role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User has no assigned role"
                )
            
            checker = PermissionChecker(current_user.role.permissions or [])
            
            perm_strs = [str(p) if isinstance(p, Permission) else p for p in permissions]
            
            if require_all:
                has_access = checker.has_all_permissions(perm_strs)
            else:
                has_access = checker.has_any_permission(perm_strs)
            
            if not has_access:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {', '.join(perm_strs)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_resource_access(resource: Resource, action: Action):
    """
    Shorthand decorator for checking resource access.
    
    Usage:
        @router.get("/scans")
        @require_resource_access(Resource.SCANS, Action.LIST)
        async def list_scans(current_user: User = Depends(get_current_user)):
            ...
    """
    return require_permission(Permission(resource, action))


class PermissionDependency:
    """
    FastAPI dependency for permission checking.
    
    Usage:
        @router.get("/mirrors", dependencies=[Depends(PermissionDependency("mirrors:list"))])
        async def list_mirrors():
            ...
    """
    
    def __init__(self, *permissions: Union[str, Permission], require_all: bool = False):
        self.permissions = permissions
        self.require_all = require_all
    
    async def __call__(self, request: Request):
        # Import here to avoid circular imports
        from enterprise.api.deps import get_current_user, get_db
        from sqlalchemy.orm import Session
        
        # This would need to be adapted based on how request context is managed
        # For now, we assume the user is available in request.state
        current_user = getattr(request.state, "user", None)
        
        if not current_user or not current_user.role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        checker = PermissionChecker(current_user.role.permissions or [])
        perm_strs = [str(p) if isinstance(p, Permission) else p for p in self.permissions]
        
        if self.require_all:
            has_access = checker.has_all_permissions(perm_strs)
        else:
            has_access = checker.has_any_permission(perm_strs)
        
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {', '.join(perm_strs)}"
            )
        
        return True
