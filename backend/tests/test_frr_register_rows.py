"""The register served from indexed rows answers exactly what the stored
document answered, for every filter and page, and older exports still serve."""

from __future__ import annotations

import pytest

from tests.test_frr_intake import (  # noqa: F401  (env is a fixture)
    ANALYST, _fresh, _settle, _upload, connect, env, pytestmark,
)

QUERIES = [{}, {"flagged_only": "false"}, {"band": "critical"}, {"band": "medium"}, {"check": "unused"},
           {"check": "shadowed", "flagged_only": "false"}, {"limit": 3, "offset": 2}, {"limit": 2, "offset": 50}]


def _doc_answer(c, eid, q):
    """Force the document path by hiding the head, then restore it."""
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("SELECT review_head FROM ztpa.exports WHERE export_id = %s", [eid])
        head = cur.fetchone()["review_head"]
        cur.execute("UPDATE ztpa.exports SET review_head = NULL WHERE export_id = %s", [eid])
    conn.commit()
    try:
        return c.get(f"/api/exports/{eid}/review", params=q, headers=ANALYST).json()
    finally:
        from psycopg.types.json import Jsonb
        with conn.cursor() as cur:
            cur.execute("UPDATE ztpa.exports SET review_head = %s WHERE export_id = %s", [Jsonb(head), eid])
        conn.commit()
        conn.close()


def test_rows_and_document_agree_for_every_query(env) -> None:
    c = env
    eid = _settle(c, _upload(c, _fresh()).json()["export"]["export_id"])["export_id"]
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM ztpa.review_entries WHERE export_id = %s", [eid])
        assert cur.fetchone()["n"] == 10
    conn.close()
    for q in QUERIES:
        rows = c.get(f"/api/exports/{eid}/review", params=q, headers=ANALYST).json()
        doc = _doc_answer(c, eid, q)
        assert rows["total"] == doc["total"], q
        assert [e["rule_uid"] for e in rows["items"]] == [e["rule_uid"] for e in doc["items"]], q
        assert rows["items"] == doc["items"], q
        assert rows["stats"] == doc["stats"] and rows["limitations"] == doc["limitations"]
        assert rows["nat_findings"] == doc["nat_findings"]
