from enum import Enum


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    AUDIT = "audit"
    BILLING = "billing"


ROLE_PERMISSIONS = {
    "viewer": {
        Permission.READ,
    },

    "developer": {
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
    },

    "admin": {
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
        Permission.ADMIN,
        Permission.AUDIT,
    },

    "audit": {
        Permission.READ,
        Permission.AUDIT,
    },

    "billing": {
        Permission.READ,
        Permission.BILLING,
    },
}


def has_permission(
    role: str,
    permission: Permission,
) -> bool:
    permissions = ROLE_PERMISSIONS.get(
        role,
        set(),
    )

    return permission in permissions
