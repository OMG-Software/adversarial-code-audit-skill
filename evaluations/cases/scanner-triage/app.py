"""Synthetic fixture. Read-only: never import or run.

A JSON API. All routing, queries and response handling for this example are in this file.
`db.execute(sql, params)` binds each entry of `params` as a value. It never rewrites `sql`.
"""
import hashlib

PRINCIPALS = {"alice": "tenant-a", "bob": "tenant-b"}


def etag_for(body: bytes) -> str:
    # Scanner alert 1: "weak hash MD5".
    return hashlib.md5(body).hexdigest()


def json_response(body: bytes) -> dict:
    # Scanner alert 2: "missing Content-Security-Policy header".
    return {
        "status": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
            "ETag": etag_for(body),
        },
        "body": body,
    }


def list_items(db, principal: str, query: dict) -> dict:
    """GET /items?sort=<column>  (any authenticated principal)"""
    tenant = PRINCIPALS[principal]
    sort = query.get("sort", "name")
    # Scanner alert 3: "SQL built with string concatenation".
    sql = "SELECT name, price FROM items WHERE tenant = ? ORDER BY " + sort
    rows = db.execute(sql, (tenant,))
    return json_response(repr(rows).encode())
