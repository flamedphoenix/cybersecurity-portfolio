"""
B24: Role-Based Access Control (RBAC) Implementation
=====================================================
This module implements a Role-Based Access Control system with:
- Users assigned to one or more roles
- Roles granted specific permissions
- Access decisions based on role-permission mappings
- An audit log recording all access attempts

Roles defined:
    admin   — full access to all resources
    editor  — can read and write content, cannot manage users or view reports
    viewer  — read-only access to content
    auditor — can view reports and logs, cannot modify anything

Permissions defined:
    user:read       — view user accounts
    user:write      — create/modify user accounts
    user:delete     — delete user accounts
    content:read    — view content
    content:write   — create/edit content
    content:delete  — delete content
    report:view     — view reports and analytics
    log:view        — view audit logs
    system:config   — modify system configuration
"""

from datetime import datetime
from typing import Optional


# ── Permission definitions ────────────────────────────────────────────────────

PERMISSIONS = {
    "user:read",
    "user:write",
    "user:delete",
    "content:read",
    "content:write",
    "content:delete",
    "report:view",
    "log:view",
    "system:config",
}

# ── Role-to-permission mappings ───────────────────────────────────────────────

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "user:read",
        "user:write",
        "user:delete",
        "content:read",
        "content:write",
        "content:delete",
        "report:view",
        "log:view",
        "system:config",
    },
    "editor": {
        "content:read",
        "content:write",
        "content:delete",
    },
    "viewer": {
        "content:read",
    },
    "auditor": {
        "report:view",
        "log:view",
        "user:read",
        "content:read",
    },
}


# ── Core RBAC classes ─────────────────────────────────────────────────────────

class AuditLog:
    """Records all access control decisions for accountability."""

    def __init__(self):
        self._entries: list[dict] = []

    def record(self, username: str, permission: str, granted: bool, reason: str = ""):
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": username,
            "permission": permission,
            "decision": "GRANTED" if granted else "DENIED",
            "reason": reason,
        }
        self._entries.append(entry)

    def get_entries(self) -> list[dict]:
        return list(self._entries)

    def print_log(self):
        print("\n" + "=" * 70)
        print("AUDIT LOG")
        print("=" * 70)
        if not self._entries:
            print("  No entries.")
        for e in self._entries:
            status = "✓" if e["decision"] == "GRANTED" else "✗"
            print(f"  [{e['timestamp']}] {status} {e['user']:<12} "
                  f"{e['permission']:<20} {e['decision']}"
                  + (f" — {e['reason']}" if e["reason"] else ""))
        print("=" * 70)


class User:
    """Represents a user with one or more assigned roles."""

    def __init__(self, username: str, roles: list[str]):
        for role in roles:
            if role not in ROLE_PERMISSIONS:
                raise ValueError(f"Unknown role: '{role}'. "
                                 f"Valid roles: {list(ROLE_PERMISSIONS.keys())}")
        self.username = username
        self.roles = set(roles)

    def get_permissions(self) -> set[str]:
        """Return the union of all permissions across all assigned roles."""
        permissions: set[str] = set()
        for role in self.roles:
            permissions |= ROLE_PERMISSIONS.get(role, set())
        return permissions

    def __repr__(self):
        return f"User('{self.username}', roles={sorted(self.roles)})"


class RBACSystem:
    """
    Core RBAC engine.

    Manages users and enforces access control decisions.
    All decisions are recorded in the audit log.
    """

    def __init__(self):
        self._users: dict[str, User] = {}
        self.audit_log = AuditLog()

    def add_user(self, username: str, roles: list[str]) -> User:
        """Register a new user with the given roles."""
        if username in self._users:
            raise ValueError(f"User '{username}' already exists.")
        user = User(username, roles)
        self._users[username] = user
        print(f"  [+] User '{username}' added with roles: {sorted(user.roles)}")
        return user

    def remove_user(self, username: str):
        """Remove a user from the system."""
        if username not in self._users:
            raise KeyError(f"User '{username}' not found.")
        del self._users[username]
        print(f"  [-] User '{username}' removed.")

    def assign_role(self, username: str, role: str):
        """Add a role to an existing user."""
        user = self._get_user(username)
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: '{role}'.")
        user.roles.add(role)
        print(f"  [~] Role '{role}' assigned to '{username}'.")

    def revoke_role(self, username: str, role: str):
        """Remove a role from an existing user."""
        user = self._get_user(username)
        user.roles.discard(role)
        print(f"  [~] Role '{role}' revoked from '{username}'.")

    def check_permission(self, username: str, permission: str) -> bool:
        """
        Check whether a user has a specific permission.
        Records the decision in the audit log.
        Returns True if access is granted, False if denied.
        """
        if permission not in PERMISSIONS:
            raise ValueError(f"Unknown permission: '{permission}'.")

        try:
            user = self._get_user(username)
        except KeyError:
            self.audit_log.record(username, permission, False, "user not found")
            return False

        granted = permission in user.get_permissions()
        reason = f"roles={sorted(user.roles)}" if granted else \
                 f"roles={sorted(user.roles)} lack this permission"
        self.audit_log.record(username, permission, granted, reason)
        return granted

    def enforce(self, username: str, permission: str, action_description: str = ""):
        """
        Enforce access control — prints result and returns bool.
        Convenience wrapper around check_permission for demonstrations.
        """
        granted = self.check_permission(username, permission)
        status = "GRANTED" if granted else "DENIED"
        action = f" [{action_description}]" if action_description else ""
        marker = "✓" if granted else "✗"
        print(f"  {marker} {username:<12} → {permission:<22} {status}{action}")
        return granted

    def get_user_summary(self, username: str):
        """Print a summary of a user's roles and permissions."""
        user = self._get_user(username)
        perms = sorted(user.get_permissions())
        print(f"\n  User: {username}")
        print(f"  Roles: {sorted(user.roles)}")
        print(f"  Permissions ({len(perms)}):")
        for p in perms:
            print(f"    - {p}")

    def _get_user(self, username: str) -> User:
        if username not in self._users:
            raise KeyError(f"User '{username}' not found.")
        return self._users[username]


# ── Demonstration ─────────────────────────────────────────────────────────────

def run_demo():
    print("\n" + "=" * 70)
    print("B24: Role-Based Access Control (RBAC) — Demonstration")
    print("=" * 70)

    rbac = RBACSystem()

    # ── Setup users ───────────────────────────────────────────────────────────
    print("\n── Setting up users ──────────────────────────────────────────────")
    rbac.add_user("alice",   roles=["admin"])
    rbac.add_user("bob",     roles=["editor"])
    rbac.add_user("charlie", roles=["viewer"])
    rbac.add_user("diana",   roles=["auditor"])
    rbac.add_user("eve",     roles=["editor", "auditor"])  # multiple roles

    # ── User summaries ────────────────────────────────────────────────────────
    print("\n── User permission summaries ─────────────────────────────────────")
    for name in ["alice", "bob", "charlie", "diana", "eve"]:
        rbac.get_user_summary(name)

    # ── Access control tests ──────────────────────────────────────────────────
    print("\n\n── Test 1: Admin access (alice) ──────────────────────────────────")
    rbac.enforce("alice", "user:delete",    "delete a user account")
    rbac.enforce("alice", "system:config",  "modify system settings")
    rbac.enforce("alice", "content:write",  "edit an article")
    rbac.enforce("alice", "report:view",    "view analytics dashboard")

    print("\n── Test 2: Editor access (bob) ───────────────────────────────────")
    rbac.enforce("bob", "content:read",    "read an article")
    rbac.enforce("bob", "content:write",   "write an article")
    rbac.enforce("bob", "content:delete",  "delete an article")
    rbac.enforce("bob", "user:read",       "view user accounts")      # denied
    rbac.enforce("bob", "report:view",     "view reports")             # denied
    rbac.enforce("bob", "system:config",   "modify system settings")  # denied

    print("\n── Test 3: Viewer access (charlie) ───────────────────────────────")
    rbac.enforce("charlie", "content:read",   "read an article")
    rbac.enforce("charlie", "content:write",  "try to edit an article")  # denied
    rbac.enforce("charlie", "content:delete", "try to delete content")   # denied
    rbac.enforce("charlie", "user:read",      "try to view users")       # denied

    print("\n── Test 4: Auditor access (diana) ────────────────────────────────")
    rbac.enforce("diana", "report:view",    "view monthly report")
    rbac.enforce("diana", "log:view",       "view audit logs")
    rbac.enforce("diana", "user:read",      "view user list")
    rbac.enforce("diana", "content:write",  "try to edit content")    # denied
    rbac.enforce("diana", "system:config",  "try to change settings") # denied

    print("\n── Test 5: Multi-role user (eve: editor + auditor) ───────────────")
    rbac.enforce("eve", "content:write", "write an article")   # from editor
    rbac.enforce("eve", "report:view",   "view reports")        # from auditor
    rbac.enforce("eve", "log:view",      "view audit logs")     # from auditor
    rbac.enforce("eve", "user:delete",   "try to delete user")  # denied — neither role has this

    print("\n── Test 6: Dynamic role changes ──────────────────────────────────")
    print("  Promoting charlie from viewer to editor...")
    rbac.assign_role("charlie", "editor")
    rbac.enforce("charlie", "content:write",  "edit after promotion")   # now granted
    rbac.enforce("charlie", "report:view",    "view report after promo") # still denied

    print("\n  Revoking editor role from charlie...")
    rbac.revoke_role("charlie", "editor")
    rbac.enforce("charlie", "content:write",  "edit after demotion")    # denied again

    print("\n── Test 7: Non-existent user ─────────────────────────────────────")
    rbac.enforce("mallory", "content:read", "attempt by unknown user")  # denied

    # ── Print audit log ───────────────────────────────────────────────────────
    rbac.audit_log.print_log()

    # ── Summary ───────────────────────────────────────────────────────────────
    log = rbac.audit_log.get_entries()
    granted = sum(1 for e in log if e["decision"] == "GRANTED")
    denied = sum(1 for e in log if e["decision"] == "DENIED")
    print(f"\nSummary: {len(log)} access attempts — "
          f"{granted} granted, {denied} denied")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_demo()
