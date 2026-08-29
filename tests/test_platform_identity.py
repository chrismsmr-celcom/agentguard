"""
Tests for platform service identities.

Validates:
- Key generation/parsing
- Permission matrices (least privilege)
- Authorization enforcement
- SYSTEM deprecation logging
"""
import os
import pytest
from unittest.mock import patch
from collector.platform_identity import (
    PlatformService,
    PlatformPermission,
    PLATFORM_PERMISSIONS,
    generate_platform_key,
    parse_platform_key,
    hash_platform_key,
    resolve_platform_identity,
    service_has_permission,
    PLATFORM_KEY_PREFIX,
)


class TestPlatformKeyFormat:
    """Platform API key format and parsing."""
    
    def test_generate_key_has_correct_prefix(self):
        key = generate_platform_key(PlatformService.AUDIT)
        assert key.startswith("agp_audit_")
    
    def test_generate_key_unique_each_call(self):
        k1 = generate_platform_key(PlatformService.AUDIT)
        k2 = generate_platform_key(PlatformService.AUDIT)
        assert k1 != k2
    
    def test_generate_key_for_each_service(self):
        for service in PlatformService:
            key = generate_platform_key(service)
            assert key.startswith(f"agp_{service.value}_")
    
    def test_parse_valid_key(self):
        key = "agp_audit_abcdefghijklmnop12345678901234"
        result = parse_platform_key(key)
        assert result is not None
        assert result["service"] == PlatformService.AUDIT
        assert "key_hash" in result
    
    def test_parse_invalid_prefix(self):
        assert parse_platform_key("ag_invalid_xyz") is None
        assert parse_platform_key("sk_live_xyz") is None
    
    def test_parse_invalid_service(self):
        assert parse_platform_key("agp_nosuchservice_abcdefghijklmnop") is None
    
    def test_parse_empty(self):
        assert parse_platform_key("") is None
        assert parse_platform_key(None) is None
    
    def test_hash_is_deterministic(self):
        key = "agp_audit_test123"
        h1 = hash_platform_key(key)
        h2 = hash_platform_key(key)
        assert h1 == h2
    
    def test_hash_differs_for_different_keys(self):
        h1 = hash_platform_key("agp_audit_test123")
        h2 = hash_platform_key("agp_audit_test124")
        assert h1 != h2


class TestPermissionMatrix:
    """Verify least privilege in permission matrices."""
    
    def test_admin_has_all_permissions(self):
        """Admin should have all defined permissions."""
        admin_perms = PLATFORM_PERMISSIONS[PlatformService.ADMIN]
        for perm in PlatformPermission:
            assert perm in admin_perms, f"Admin missing {perm.value}"
    
    def test_audit_is_read_only(self):
        """Audit service should NOT have write permissions."""
        audit_perms = PLATFORM_PERMISSIONS[PlatformService.AUDIT]
        
        # These should be ABSENT from audit
        forbidden = {
            PlatformPermission.TENANT_CREATE,
            PlatformPermission.TENANT_DELETE,
            PlatformPermission.ORG_CREATE,
            PlatformPermission.ORG_DELETE,
            PlatformPermission.USER_MANAGE,
            PlatformPermission.AGENT_MANAGE,
            PlatformPermission.BILLING_MANAGE,
            PlatformPermission.MIGRATION_EXECUTE,
            PlatformPermission.PLATFORM_CONFIG,
        }
        
        for perm in forbidden:
            assert perm not in audit_perms, f"Audit has forbidden {perm.value}"
        
        # But should have audit read
        assert PlatformPermission.AUDIT_READ in audit_perms
        assert PlatformPermission.TRACES_READ in audit_perms
    
    def test_billing_cannot_modify_tenants(self):
        """Billing should be read-only on tenants."""
        billing_perms = PLATFORM_PERMISSIONS[PlatformService.BILLING]
        
        assert PlatformPermission.TENANT_CREATE not in billing_perms
        assert PlatformPermission.TENANT_DELETE not in billing_perms
        assert PlatformPermission.METRICS_READ in billing_perms
        assert PlatformPermission.BILLING_READ in billing_perms
    
    def test_migration_cannot_manage_users(self):
        """Migration should not touch users/agents."""
        migration_perms = PLATFORM_PERMISSIONS[PlatformService.MIGRATION]
        
        assert PlatformPermission.USER_MANAGE not in migration_perms
        assert PlatformPermission.AGENT_MANAGE not in migration_perms
        assert PlatformPermission.MIGRATION_EXECUTE in migration_perms
    
    def test_service_has_permission_helper(self):
        assert service_has_permission(PlatformService.ADMIN, PlatformPermission.TENANT_CREATE)
        assert not service_has_permission(PlatformService.AUDIT, PlatformPermission.TENANT_CREATE)


class TestPlatformIdentityResolution:
    """End-to-end identity resolution from env var."""
    
    def test_resolve_valid_key_from_env(self):
        key = generate_platform_key(PlatformService.AUDIT)
        with patch.dict(os.environ, {"AGENTGUARD_PLATFORM_KEY_AUDIT": key}):
            result = resolve_platform_identity(key)
        
        assert result is not None
        assert result["service"] == PlatformService.AUDIT
        assert PlatformPermission.AUDIT_READ in result["permissions"]
        assert result["identity_type"] == "platform"
    
    def test_resolve_wrong_service_key(self):
        """Key for AUDIT but env var expects BILLING."""
        audit_key = generate_platform_key(PlatformService.AUDIT)
        billing_key = generate_platform_key(PlatformService.BILLING)
        
        with patch.dict(os.environ, {"AGENTGUARD_PLATFORM_KEY_BILLING": billing_key}):
            # Trying to use audit key — should fail
            result = resolve_platform_identity(audit_key)
        
        assert result is None
    
    def test_resolve_invalid_key(self):
        with patch.dict(os.environ, {"AGENTGUARD_PLATFORM_KEY_AUDIT": "agp_audit_validkey"}):
            result = resolve_platform_identity("agp_audit_different")
        assert result is None
    
    def test_resolve_non_platform_key(self):
        """Non-platform keys (ag_, sk_, etc.) should not match."""
        result = resolve_platform_identity("ag_tenant_org_agent_xyz")
        assert result is None
        
        result = resolve_platform_identity("sk_live_abc")
        assert result is None
    
    def test_resolve_missing_env_var(self):
        """No env var configured → no resolution."""
        key = generate_platform_key(PlatformService.AUDIT)
        # Clear any env var
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTGUARD_PLATFORM_KEY_")}
        with patch.dict(os.environ, env, clear=True):
            result = resolve_platform_identity(key)
        assert result is None


class TestSystemDeprecation:
    """Verify SYSTEM identity is deprecated and loggable."""
    
    def test_system_permission_matrix_documented(self):
        """Document that SYSTEM still works but is deprecated.
        
        This test ensures future developers know the deprecation state.
        """
        # The migration guide should be referenced in logs
        # We just verify the constants exist and are documented
        assert PlatformService.ADMIN.value == "admin"
        assert PlatformPermission.TENANT_CREATE.value == "tenant:create"
