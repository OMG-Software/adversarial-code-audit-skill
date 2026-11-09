"""Complete synthetic private-record route and policy.

An authenticated principal may read only records in its own tenant.
Tenant identity is trusted. Client-supplied record IDs are not capabilities.
All requests use dispatch; no other storage or authorization layers exist.
"""

RECORDS = {"record-b": {"tenant": "b", "private_text": "tenant-b-only"}}


def read_record(principal, record_id):
    return RECORDS[record_id]


def dispatch(principal, record_id):
    return read_record(principal, record_id)
