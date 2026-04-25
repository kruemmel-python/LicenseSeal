from __future__ import annotations

ROLES = {"admin", "legal", "developer", "viewer"}


def can(role: str, action: str) -> bool:
    matrix = {
        "admin": {"read", "write", "manage", "webhook"},
        "legal": {"read", "write", "webhook"},
        "developer": {"read", "write"},
        "viewer": {"read"},
    }
    return action in matrix.get(role, set())
