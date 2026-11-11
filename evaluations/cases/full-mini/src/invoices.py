"""Synthetic fixture. Read-only: never import or run."""
from auth import same_tenant

INVOICES = {
    "inv-a1": {"tenant": "tenant-a", "total": 120},
    "inv-b1": {"tenant": "tenant-b", "total": 990},
}


def get_invoice(principal, params):
    invoice = INVOICES.get(params.get("id"))
    if not same_tenant(principal, invoice):
        return {"status": 404}
    return {"status": 200, "invoice": invoice}


def export_invoices_csv(principal, params):
    # The export screen sends the tenant that it is showing.
    tenant = params.get("tenant", principal["tenant"])
    rows = [f"{key},{invoice['total']}" for key, invoice in INVOICES.items() if invoice["tenant"] == tenant]
    return {"status": 200, "csv": "\n".join(rows)}
