"""Two-stage human review of a change package, end to end through the API on a
real database: the happy path, every refusal, scoping, four eyes."""

from __future__ import annotations

import pytest

from tests.test_frr_intake import (  # noqa: F401  (env is a fixture)
    ANALYST, _URL, _fresh, _settle, _upload, connect, env, pytestmark,
)

ADMIN = {"x-npr-role": "admin", "x-npr-email": "root@example.com", "x-npr-sub": "sub-root"}
OWNER = {"x-npr-role": "viewer", "x-npr-email": "olivia@example.com", "x-npr-sub": "sub-olivia"}
APPROVER = {"x-npr-role": "viewer", "x-npr-email": "sam@example.com", "x-npr-sub": "sub-sam"}
NOBODY = {"x-npr-role": "analyst", "x-npr-email": "nik@example.com", "x-npr-sub": "sub-nik"}
INPUT = {"allowed_sources": ["10.20.5.0/24"], "allowed_services": ["tcp/22"],
         "business_justification": "jump hosts only"}


@pytest.fixture()
def matrix(env):
    """Olivia owns every layer; Sam approves. Removed afterwards."""
    for who, duty in (("olivia@example.com", "network_owner"), ("sam@example.com", "security_approver")):
        r = env.post("/api/admin/frr/approvers", json={"principal": who, "duty": duty}, headers=ADMIN)
        assert r.status_code == 201, r.text
    yield env
    c = connect()
    with c.cursor() as cur:
        cur.execute("DELETE FROM ztpa.frr_approvers WHERE principal LIKE '%@example.com'")
    c.commit()
    c.close()


def _accepted_export(client) -> str:
    r = _upload(client, _fresh())
    row = _settle(client, r.json()["export"]["export_id"])
    assert row["status"] == "accepted"
    return row["export_id"]


def _draft(client, export_id, **params):
    return client.post(f"/api/exports/{export_id}/change-package", params=params, headers=ANALYST)


def _decide_all(client, pkg):
    for it in pkg["items"]:
        body = {"decision": "accept"}
        if it["requires_owner_input"]:
            body["input"] = INPUT
        r = client.put(f"/api/change-packages/{pkg['package_id']}/items/{it['item_id']}",
                       json=body, headers=OWNER)
        assert r.status_code == 200, r.text


def test_the_full_two_stage_flow(matrix) -> None:
    c = matrix
    pkg = _draft(c, _accepted_export(c)).json()
    assert pkg["status"] == "draft" and len(pkg["items"]) == 7
    pid = pkg["package_id"]

    narrow = next(i for i in pkg["items"] if i["proposal"] == "time_bound_and_narrow")
    r = c.put(f"/api/change-packages/{pid}/items/{narrow['item_id']}", json={"decision": "accept"},
              headers=OWNER)
    assert r.status_code == 422 and "allowed_sources" in r.text

    assert c.post(f"/api/change-packages/{pid}/validate", json={}, headers=OWNER).status_code == 409
    _decide_all(c, pkg)
    assert c.post(f"/api/change-packages/{pid}/decision", json={"decision": "approve"},
                  headers=APPROVER).status_code == 409                     # not validated yet
    v = c.post(f"/api/change-packages/{pid}/validate", json={"note": "checked"}, headers=OWNER)
    assert v.status_code == 200 and v.json()["status"] == "owner_validated"

    # The owner cannot approve their own validation, even holding the approver duty.
    c.post("/api/admin/frr/approvers", json={"principal": "olivia@example.com",
                                             "duty": "security_approver"}, headers=ADMIN)
    r = c.post(f"/api/change-packages/{pid}/decision", json={"decision": "approve"}, headers=OWNER)
    assert r.status_code == 403 and "four eyes" in r.text

    assert c.get(f"/api/change-packages/{pid}/runbook", headers=APPROVER).status_code == 409
    a = c.post(f"/api/change-packages/{pid}/decision", json={"decision": "approve", "note": "ok"},
               headers=APPROVER)
    assert a.status_code == 200 and a.json()["status"] == "approved"

    book = c.get(f"/api/change-packages/{pid}/runbook", headers=ANALYST).text
    assert "approved  by sam@example.com" in book and "validated by olivia@example.com" in book
    assert "mgmt_cli delete access-rule uid rule-7" in book and "# ROLLBACK:" in book
    assert '"allowed_sources":["10.20.5.0/24"]' in book
    assert "revisit_after" not in book                                        # no-op items omitted

    # Every transition is in the audit trail.
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("SELECT action FROM ztpa.audit_log WHERE subject LIKE %s", [f"{pid}%"])
        actions = {r["action"] for r in cur.fetchall()}
    conn.close()
    assert {"frr_package_drafted", "frr_item_decided", "frr_package_validated",
            "frr_package_approved"} <= actions


def test_no_duty_no_decision(matrix) -> None:
    c = matrix
    pkg = _draft(c, _accepted_export(c)).json()
    it = pkg["items"][0]
    r = c.put(f"/api/change-packages/{pkg['package_id']}/items/{it['item_id']}",
              json={"decision": "reject", "note": "x"}, headers=NOBODY)
    assert r.status_code == 403 and "network_owner" in r.text
    r = c.put(f"/api/change-packages/{pkg['package_id']}/items/{it['item_id']}",
              json={"decision": "reject"}, headers=OWNER)
    assert r.status_code == 422 and "note" in r.text


def test_a_layer_scoped_owner_cannot_decide_other_layers(matrix) -> None:
    c = matrix
    c.delete("/api/admin/frr/approvers", params={"principal": "olivia@example.com",
                                                 "duty": "network_owner", "scope": "*"}, headers=ADMIN)
    c.post("/api/admin/frr/approvers", json={"principal": "olivia@example.com",
                                             "duty": "network_owner", "scope": "Other-Layer"},
           headers=ADMIN)
    pkg = _draft(c, _accepted_export(c)).json()
    it = pkg["items"][0]
    r = c.put(f"/api/change-packages/{pkg['package_id']}/items/{it['item_id']}",
              json={"decision": "reject", "note": "x"}, headers=OWNER)
    assert r.status_code == 403 and "Network" in r.text


def test_redrafting_supersedes_and_rejection_needs_a_note(matrix) -> None:
    c = matrix
    eid = _accepted_export(c)
    first = _draft(c, eid).json()
    assert _draft(c, eid).status_code == 409
    second = _draft(c, eid, supersede="true").json()
    assert c.get(f"/api/change-packages/{first['package_id']}", headers=ANALYST).json()["status"] == "superseded"
    _decide_all(c, second)
    c.post(f"/api/change-packages/{second['package_id']}/validate", json={}, headers=OWNER)
    r = c.post(f"/api/change-packages/{second['package_id']}/decision", json={"decision": "reject"},
               headers=APPROVER)
    assert r.status_code == 422
    r = c.post(f"/api/change-packages/{second['package_id']}/decision",
               json={"decision": "reject", "note": "narrowing too broad"}, headers=APPROVER)
    assert r.json()["status"] == "rejected"


def test_only_accepted_exports_and_permitted_roles_draft(matrix) -> None:
    c = matrix
    bad = _upload(c, _fresh(exported_at="2020-01-01T00:00:00Z")).json()["export"]["export_id"]
    _settle(c, bad)
    assert _draft(c, bad).status_code == 409
    assert c.post(f"/api/exports/{bad}/change-package", headers=OWNER).status_code == 403
    assert c.get("/api/admin/frr/approvers", headers=ANALYST).status_code == 403
    assert c.get("/api/change-packages/not-a-uuid", headers=ANALYST).status_code == 404


def test_four_eyes_is_a_database_constraint(matrix) -> None:
    import psycopg
    c = matrix
    pkg = _draft(c, _accepted_export(c)).json()
    conn = connect()
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.cursor() as cur:
            cur.execute("UPDATE ztpa.change_packages SET status='approved', validated_by='x', "
                        "decided_by='x' WHERE package_id = %s", [pkg["package_id"]])
    conn.rollback()
    conn.close()


def test_large_packages_page_their_items_with_facets(matrix, monkeypatch) -> None:
    from src.frr import workflow
    monkeypatch.setattr(workflow, "ITEMS_INLINE", 3)                     # make the fixture package "large"
    c = matrix
    pkg = _draft(c, _accepted_export(c)).json()
    assert pkg["items_inline"] is False and "items" not in pkg
    f = pkg["facets"]
    assert f["total"] == 7 and f["undecided"] == 7 and sum(f["by_band"].values()) == 7
    page1 = c.get(f"/api/change-packages/{pkg['package_id']}/items", params={"limit": 4}, headers=ANALYST).json()
    page2 = c.get(f"/api/change-packages/{pkg['package_id']}/items", params={"limit": 4, "offset": 4},
                  headers=ANALYST).json()
    assert page1["total"] == 7 and len(page1["items"]) == 4 and len(page2["items"]) == 3
    assert not {i["item_id"] for i in page1["items"]} & {i["item_id"] for i in page2["items"]}
    assert page1["items"][0]["band"] == "critical"
    crit = c.get(f"/api/change-packages/{pkg['package_id']}/items", params={"band": "critical"}, headers=ANALYST).json()
    assert crit["total"] == f["by_band"]["critical"]
    it = page1["items"][0]
    c.put(f"/api/change-packages/{pkg['package_id']}/items/{it['item_id']}",
          json={"decision": "reject", "note": "known exception"}, headers=OWNER)
    left = c.get(f"/api/change-packages/{pkg['package_id']}/items", params={"decided": "false"}, headers=ANALYST).json()
    assert left["total"] == 6
    assert c.get(f"/api/change-packages/{pkg['package_id']}", headers=ANALYST).json()["facets"]["undecided"] == 6
