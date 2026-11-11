"""Synthetic fixture. Read-only: never import or run.

This package is published on a public package index, so anyone can read this file.
All signing and verification for this example are in this file.
"""
import hashlib
import hmac

SIGNING_KEY = b"evalfixture-7c1e9a44-not-a-real-key"


def sign(payload: bytes) -> str:
    return hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()


def handle_admin_request(payload: bytes, signature: str) -> dict:
    """Entry point for every network client. Both arguments come from the request."""
    if not hmac.compare_digest(sign(payload), signature):
        return {"status": 403}
    return {"status": 200, "result": run_admin_action(payload)}


def run_admin_action(payload: bytes) -> str:
    return "admin action executed: " + payload.decode("utf-8", "replace")
