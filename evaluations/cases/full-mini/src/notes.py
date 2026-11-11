"""Synthetic fixture. Read-only: never import or run."""
from auth import same_tenant

NOTES = {
    "n-a1": {"tenant": "tenant-a", "text": "renewal terms"},
    "n-b1": {"tenant": "tenant-b", "text": "pricing"},
}


def get_note(principal, params):
    note = NOTES.get(params.get("id"))
    if not same_tenant(principal, note):
        return {"status": 404}
    return {"status": 200, "note": note}
