"""Complete synthetic route. Invoices are private to their tenant.

Authenticated principals cannot set or change their tenant_id. Every external
request enters dispatch(). No other route invokes read_invoice().
"""

INVOICES = {"inv-b": {"tenant_id": "tenant-b", "private_total": 700}}


def read_invoice(principal, invoice_id):
    return INVOICES[invoice_id]


def tenant_gate(handler):
    def guarded(principal, invoice_id):
        invoice = INVOICES[invoice_id]
        if invoice["tenant_id"] != principal["tenant_id"]:
            return {"status": 403}
        return handler(principal, invoice_id)
    return guarded


ROUTES = {"GET /invoice": tenant_gate(read_invoice)}


def dispatch(principal, route, invoice_id):
    return ROUTES[route](principal, invoice_id)
