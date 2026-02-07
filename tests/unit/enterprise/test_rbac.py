"""Tests for RBAC permission system."""

import pytest
from uuid import uuid4

from enterprise.core.rbac.permissions import (
    Permission, Resource, Action, 
    PERMISSION_DEFINITIONS, is_valid_permission,
    get_permissions_for_resource, get_all_permissions,
)
from enterprise.core.rbac.checker import (
    PermissionChecker, has_permission, 

)
from enterprise.core.rbac.roles import (
    DEFAULT_ROLES, get_default_role_permissions,
    ADMIN_PERMISSIONS, DEVELOPER_PERMISSIONS,
    SECURITY_ANALYST_PERMISSIONS, AUDITOR_PERMISSIONS,
    VIEWER_PERMISSIONS,
)


class TestPermissionModel:
    """Test permission definitions."""
    
    def test_permission_string_format(self):
        """Test permission string format."""
        perm = Permission(Resource.MIRRORS, Action.READ)
        assert str(perm) == "mirrors:read"
    
    def test_permission_from_string(self):
        """Test parsing permission from string."""
        perm = Permission.from_string("packages:approve")
        assert perm.resource == Resource.PACKAGES
        assert perm.action == Action.APPROVE
    
    def test_invalid_permission_format(self):
        """Test parsing invalid permission string."""
        with pytest.raises(ValueError):
            Permission.from_string("invalid")
        
        with pytest.raises(ValueError):
            Permission.from_string("too:many:parts")
    
    def test_is_valid_permission(self):
        """Test permission validation."""
        assert is_valid_permission("mirrors:read")
        assert is_valid_permission("packages:approve")
        assert not is_valid_permission("invalid:permission")
        assert not is_valid_permission("mirrors:fly")  # Invalid action
    
    def test_all_permissions_generated(self):
        """Test that all permissions are generated from matrix."""
        all_perms = get_all_permissions()
        assert len(all_perms) >= 50  # We defined 60 permissions
        assert "mirrors:read" in all_perms
        assert "packages:approve" in all_perms
        assert "audit_logs:export" in all_perms
    
    def test_permissions_for_resource(self):
        """Test getting permissions for a specific resource."""
        mirror_perms = get_permissions_for_resource(Resource.MIRRORS)
        assert "mirrors:read" in mirror_perms
        assert "mirrors:create" in mirror_perms
        assert "mirrors:configure" in mirror_perms
        assert "packages:read" not in mirror_perms


class TestPermissionChecker:
    """Test PermissionChecker class."""
    
    def test_has_permission_exact_match(self):
        """Test exact permission matching."""
        checker = PermissionChecker(["mirrors:read", "mirrors:list"])
        assert checker.has_permission("mirrors:read")
        assert checker.has_permission("mirrors:list")
        assert not checker.has_permission("mirrors:create")
    
    def test_has_permission_resource_wildcard(self):
        """Test resource wildcard (resource:*)."""
        checker = PermissionChecker(["mirrors:*"])
        assert checker.has_permission("mirrors:read")
        assert checker.has_permission("mirrors:create")
        assert checker.has_permission("mirrors:delete")
        assert not checker.has_permission("packages:read")
    
    def test_has_permission_global_wildcard(self):
        """Test global wildcard (*:*)."""
        checker = PermissionChecker(["*:*"])
        assert checker.has_permission("mirrors:read")
        assert checker.has_permission("packages:approve")
        assert checker.has_permission("audit_logs:export")
        assert checker.has_permission("anything:anyperm")
    
    def test_has_any_permission(self):
        """Test checking for any of multiple permissions."""
        checker = PermissionChecker(["mirrors:read"])
        assert checker.has_any_permission(["mirrors:read", "mirrors:create"])
        assert not checker.has_any_permission(["packages:read", "scans:execute"])
    
    def test_has_all_permissions(self):
        """Test checking for all of multiple permissions."""
        checker = PermissionChecker(["mirrors:read", "mirrors:list", "mirrors:create"])
        assert checker.has_all_permissions(["mirrors:read", "mirrors:list"])
        assert not checker.has_all_permissions(["mirrors:read", "mirrors:delete"])
    
    def test_can_access_resource(self):
        """Test resource access checking."""
        checker = PermissionChecker(["packages:approve", "packages:reject"])
        assert checker.can_access_resource(Resource.PACKAGES, Action.APPROVE)
        assert not checker.can_access_resource(Resource.PACKAGES, Action.DELETE)
    
    def test_get_accessible_resources(self):
        """Test getting accessible resources for an action."""
        checker = PermissionChecker(["mirrors:read", "packages:read", "scans:read"])
        readable = checker.get_accessible_resources(Action.READ)
        assert Resource.MIRRORS in readable
        assert Resource.PACKAGES in readable
        assert Resource.SCANS in readable
        assert Resource.AUDIT_LOGS not in readable


class TestDefaultRoles:
    """Test default role definitions."""
    
    def test_all_default_roles_defined(self):
        """Test that all 5 default roles are defined."""
        assert len(DEFAULT_ROLES) == 5
        assert "admin" in DEFAULT_ROLES
        assert "developer" in DEFAULT_ROLES
        assert "security_analyst" in DEFAULT_ROLES
        assert "auditor" in DEFAULT_ROLES
        assert "viewer" in DEFAULT_ROLES
    
    def test_admin_has_full_access(self):
        """Test that admin role has full access."""
        assert ADMIN_PERMISSIONS == ["*:*"]
        checker = PermissionChecker(ADMIN_PERMISSIONS)
        assert checker.has_permission("anything:anypermission")
    
    def test_developer_permissions(self):
        """Test developer role permissions."""
        checker = PermissionChecker(DEVELOPER_PERMISSIONS)
        
        # Should have
        assert checker.has_permission("mirrors:read")
        assert checker.has_permission("scans:execute")
        assert checker.has_permission("api_keys:create")
        
        # Should not have
        assert not checker.has_permission("mirrors:create")
        assert not checker.has_permission("packages:approve")
        assert not checker.has_permission("users:manage")
    
    def test_security_analyst_permissions(self):
        """Test security analyst role permissions."""
        checker = PermissionChecker(SECURITY_ANALYST_PERMISSIONS)
        
        # Should have
        assert checker.has_permission("packages:approve")
        assert checker.has_permission("packages:reject")
        assert checker.has_permission("policies:create")
        assert checker.has_permission("audit_logs:export")
        
        # Should not have
        assert not checker.has_permission("users:manage")
        assert not checker.has_permission("organization:configure")
    
    def test_auditor_is_readonly(self):
        """Test auditor role is read-only with export capability."""
        checker = PermissionChecker(AUDITOR_PERMISSIONS)
        
        # Should have read access
        assert checker.has_permission("mirrors:read")
        assert checker.has_permission("packages:read")
        assert checker.has_permission("audit_logs:read")
        assert checker.has_permission("audit_logs:export")
        
        # Should not have write access
        assert not checker.has_permission("mirrors:create")
        assert not checker.has_permission("packages:approve")
        assert not checker.has_permission("policies:update")
    
    def test_viewer_minimal_access(self):
        """Test viewer role has minimal read access."""
        checker = PermissionChecker(VIEWER_PERMISSIONS)
        
        # Should have basic read
        assert checker.has_permission("mirrors:read")
        assert checker.has_permission("packages:read")
        
        # Should not have approval or audit export
        assert not checker.has_permission("packages:approve")
        assert not checker.has_permission("audit_logs:export")
        assert not checker.has_permission("policies:read")
    
    def test_get_default_role_permissions(self):
        """Test getting permissions for a default role."""
        admin_perms = get_default_role_permissions("admin")
        assert admin_perms == ["*:*"]
        
        viewer_perms = get_default_role_permissions("viewer")
        assert len(viewer_perms) > 0
        assert "mirrors:read" in viewer_perms
    
    def test_invalid_role_raises(self):
        """Test that getting unknown role raises error."""
        with pytest.raises(ValueError):
            get_default_role_permissions("unknown_role")


class TestRoleSeparation:
    """Test that roles have proper separation of concerns."""
    
    def test_only_admin_can_manage_users(self):
        """Test only admin can manage users."""
        admin = PermissionChecker(ADMIN_PERMISSIONS)
        developer = PermissionChecker(DEVELOPER_PERMISSIONS)
        analyst = PermissionChecker(SECURITY_ANALYST_PERMISSIONS)
        auditor = PermissionChecker(AUDITOR_PERMISSIONS)
        viewer = PermissionChecker(VIEWER_PERMISSIONS)
        
        assert admin.has_permission("users:manage")
        assert not developer.has_permission("users:manage")
        assert not analyst.has_permission("users:manage")
        assert not auditor.has_permission("users:manage")
        assert not viewer.has_permission("users:manage")
    
    def test_only_analyst_and_admin_can_approve(self):
        """Test only security analyst and admin can approve packages."""
        admin = PermissionChecker(ADMIN_PERMISSIONS)
        developer = PermissionChecker(DEVELOPER_PERMISSIONS)
        analyst = PermissionChecker(SECURITY_ANALYST_PERMISSIONS)
        auditor = PermissionChecker(AUDITOR_PERMISSIONS)
        viewer = PermissionChecker(VIEWER_PERMISSIONS)
        
        assert admin.has_permission("packages:approve")
        assert analyst.has_permission("packages:approve")
        assert not developer.has_permission("packages:approve")
        assert not auditor.has_permission("packages:approve")
        assert not viewer.has_permission("packages:approve")
    
    def test_developer_can_execute_scans(self):
        """Test developer can execute scans."""
        developer = PermissionChecker(DEVELOPER_PERMISSIONS)
        analyst = PermissionChecker(SECURITY_ANALYST_PERMISSIONS)
        auditor = PermissionChecker(AUDITOR_PERMISSIONS)
        viewer = PermissionChecker(VIEWER_PERMISSIONS)
        
        assert developer.has_permission("scans:execute")
        assert analyst.has_permission("scans:execute")
        assert not auditor.has_permission("scans:execute")
        assert not viewer.has_permission("scans:execute")
    
    def test_auditor_can_export_logs(self):
        """Test auditor can export audit logs."""
        developer = PermissionChecker(DEVELOPER_PERMISSIONS)
        analyst = PermissionChecker(SECURITY_ANALYST_PERMISSIONS)
        auditor = PermissionChecker(AUDITOR_PERMISSIONS)
        viewer = PermissionChecker(VIEWER_PERMISSIONS)
        
        assert auditor.has_permission("audit_logs:export")
        assert analyst.has_permission("audit_logs:export")
        assert not developer.has_permission("audit_logs:export")
        assert not viewer.has_permission("audit_logs:export")
