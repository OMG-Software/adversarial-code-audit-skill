"""Synthetic fixture. Read-only: never import or run.

Every route of the service is in ROUTES. The login flow that fills the session store is not part of this example.
"""
from auth import principal_for
from invoices import export_invoices_csv, get_invoice
from notes import get_note

ROUTES = {
    ("GET", "/invoices/{id}"): get_invoice,
    ("GET", "/invoices/export"): export_invoices_csv,
    ("GET", "/notes/{id}"): get_note,
}


def dispatch(method, path_template, session_id, params):
    """Entry point for every network request. `params` holds the path and query values the client sent."""
    principal = principal_for(session_id)
    if principal is None:
        return {"status": 401}
    handler = ROUTES.get((method, path_template))
    if handler is None:
        return {"status": 404}
    return handler(principal, params)
