"""Synthetic fixture. Read-only: never import or run.

Deployment note, written by the developers and not verified by anyone:
"In production this service listens on 127.0.0.1:8000 behind our nginx reverse proxy.
nginx sets X-Forwarded-For." The nginx configuration is not in this repository.
"""
ADMIN_NETWORK = "10.20.0."


def client_ip(headers: dict, peer_addr: str) -> str:
    forwarded = headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return peer_addr


def admin_dashboard(headers: dict, peer_addr: str) -> dict:
    """GET /admin  (no login: access is by network address only)"""
    if not client_ip(headers, peer_addr).startswith(ADMIN_NETWORK):
        return {"status": 403}
    return {"status": 200, "body": "all customer records"}
