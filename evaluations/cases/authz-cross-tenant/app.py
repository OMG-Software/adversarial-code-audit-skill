"""Complete synthetic route. Invoices are private to their tenant.

Authenticated principals cannot set or change their tenant_id. Every external
request enters dispatch(). A principal can supply any invoice_id, including
inv-b. This module contains all authorization and storage controls.
"""

INVOICES = {"inv-b": {"tenant_id": "tenant-b", "private_total": 700}}


def read_invoice(principal, invoice_id):
    return INVOICES[invoice_id]


ROUTES = {"GET /invoice": read_invoice}


def dispatch(principal, route, invoice_id):
    return ROUTES[route](principal, invoice_id)
