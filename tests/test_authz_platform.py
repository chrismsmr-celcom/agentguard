"""Tests for platform identity authorization in authz kernel."""
import os
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, g

from collector.authz import authorize, Action


@pytest.fixture
def app():
    """Create Flask app context for g access."""
    app = Flask(__name__)
    with app.app_context():
        yield app


class TestPlatformAuthorization:
    """Platform identity authorization via authz kernel."""
    
    def test_platform_audit_can_read_traces(self, app):
        """Audit service can read traces."""
        from collector.platform_identity import (
            PlatformService, PlatformPermission
        )
        
        with app.app_context():
            g.platform_identity = {
                "service": PlatformService.AUDIT,
                "service_name": "audit",
                "permissions": {
                    PlatformPermission.AUDIT_READ,
                    PlatformPermission.TRACES_READ,
                },
                "identity_type": "platform",
            }
            
            assert authorize(actor=None, action=Action.TRACES_READ)
            assert authorize(actor=None, action=Action.AUDIT_READ)
    
    def test_platform_audit_cannot_create_tenant(self, app):
        """Audit service CANNOT create tenants (read-only)."""
        from collector.platform_identity import (
            PlatformService, PlatformPermission
        )
        
        with app.app_context():
            g.platform_identity = {
                "service": PlatformService.AUDIT,
                "service_name": "audit",
                "permissions": {
                    PlatformPermission.AUDIT_READ,
                    PlatformPermission.TRACES_READ,
                },
                "identity_type": "platform",
            }
            
            assert not authorize(actor=None, action=Action.TENANT_CREATE)
            assert not authorize(actor=None, action=Action.USER_CREATE)
    
    def test_platform_billing_can_read_metrics(self, app):
        """Billing service can read metrics."""
        from collector.platform_identity import (
            PlatformService, PlatformPermission
        )
        
        with app.app_context():
            g.platform_identity = {
                "service": PlatformService.BILLING,
                "service_name": "billing",
                "permissions": {
                    PlatformPermission.METRICS_READ,
                    PlatformPermission.BILLING_READ,
                },
                "identity_type": "platform",
            }
            
            assert authorize(actor=None, action=Action.METRICS_READ)
            assert authorize(actor=None, action=Action.BILLING_VIEW)
            # Cannot write traces
            assert not authorize(actor=None, action=Action.TRACES_WRITE)


class TestSystemDeprecation:
    """SYSTEM identity deprecation behavior."""
    
    def test_system_allowed_by_default_with_warning(self, app):
        """SYSTEM still works in Phase 1/2 but logs deprecation."""
        from identity import IdentityType, Role
        
        actor = MagicMock()
        actor.identity_type = IdentityType.SYSTEM
        actor.role = Role.ADMIN
        actor.tenant_id = "default"
        actor.org_id = "default"
        
        with app.app_context():
            # Default: SYSTEM still ALLOWED
            result = authorize(actor=actor, action=Action.TENANT_CREATE)
            assert result is True
    
    def test_system_blocked_when_toggle_enabled(self, app):
        """SYSTEM blocked when AGENTGUARD_DISABLE_LEGACY_SYSTEM=true."""
        from identity import IdentityType, Role
        
        actor = MagicMock()
        actor.identity_type = IdentityType.SYSTEM
        actor.role = Role.ADMIN
        actor.tenant_id = "default"
        actor.org_id = "default"
        
        with patch.dict(os.environ, {"AGENTGUARD_DISABLE_LEGACY_SYSTEM": "true"}):
            with app.app_context():
                result = authorize(actor=actor, action=Action.TENANT_CREATE)
                assert result is False
