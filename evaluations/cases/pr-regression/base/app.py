"""All routes require authentication. Tenant IDs come from trusted identity.
Invoices and notes are private to their tenant. IDs are not capabilities.
The client can request any ID. No other access filters exist.
"""

INVOICES = {"i-b": {"tenant": "b", "secret": "invoice-b"}}
NOTES = {"n-b": {"tenant": "b", "secret": "note-b"}}


def get_invoice(principal, object_id):
    return INVOICES[object_id]


def get_note(principal, object_id):
    note = NOTES[object_id]
    if note["tenant"] != principal["tenant"]:
        return {"status": 403}
    return note


ROUTES = {"invoice": get_invoice, "note": get_note}


def dispatch(principal, route, object_id):
    return ROUTES[route](principal, object_id)
