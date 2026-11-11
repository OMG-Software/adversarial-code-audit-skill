"""Synthetic fixture. Read-only: never import or run."""

SESSIONS = {
    "s-alice": {"user": "alice", "tenant": "tenant-a"},
    "s-bob": {"user": "bob", "tenant": "tenant-b"},
}


def principal_for(session_id):
    return SESSIONS.get(session_id)


def same_tenant(principal, record):
    """The one tenant check. Every handler that returns a record must call it."""
    return record is not None and record["tenant"] == principal["tenant"]
