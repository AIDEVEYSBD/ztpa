"""Context datasets: CSV parsing and validation (offline), and on a real database
the load, the CMDB owner lookup and flow-based narrowing suggestions."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from src.frr import context as cx

CMDB = b"""Network,Owner,Application,Environment,Zone,Criticality
10.30.0.0/24,dc-team@example.com,Core DC,prod,dc,high
10.10.1.10,web-team@example.com,Storefront,prod,dmz,high
10.40.0.10-10.40.0.20,ops@example.com,Jump hosts,prod,mgmt,medium
"""


def _flows(now: datetime) -> bytes:
    recent = (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
    old = (now - timedelta(days=400)).strftime("%Y-%m-%d %H:%M:%S")
    rows = ["Start Active,Last Active,Subject IP Address,Peer IP Address,Peer Port/Protocol,Flows"]
    for i in range(1, 6):
        rows.append(f"{recent},{recent},10.20.5.{i},10.30.0.7,22/TCP,{10 * i}")
    rows.append(f"{recent},{recent},10.20.9.4,10.30.0.8,3389/TCP,3")
    rows.append(f"{old},{old},10.99.0.1,10.30.0.7,22/TCP,500")            # outside the window
    rows.append(f"{recent},{recent},10.20.5.1,10.30.0.7,22/TCP,1")         # aggregates with the first
    return ("\n".join(rows) + "\n").encode()


def test_cmdb_parses_cidrs_hosts_and_ranges() -> None:
    rows, summary = cx.parse("cmdb", CMDB)
    nets = [r[0] for r in rows]
    assert "10.30.0.0/24" in nets and "10.10.1.10/32" in nets and "10.40.0.16/30" in nets
    assert summary == {"rows": 3, "networks": 6, "skipped_rows": 0}


def test_stealthwatch_flows_aggregate_per_conversation() -> None:
    rows, summary = cx.parse("flows", _flows(datetime.now(timezone.utc)))
    first = next(r for r in rows if r[0] == "10.20.5.1")
    assert first[2:4] == ("tcp", 22) and first[6] == 11                    # 10 + 1 aggregated
    assert summary["rows"] == 8 and summary["conversations"] == 7


@pytest.mark.parametrize("kind, data, reason", [
    ("cmdb", b"owner,app\nx,y\n", "missing required column"),
    ("flows", b"src,dst,last_seen\n", "no data rows"),
    ("flows", b"src,dst,last_seen\nnot-an-ip,10.0.0.1,2026-01-01\n", "unreadable"),
    ("cmdb", b"\xff\xfe", "not UTF-8"),
])
def test_bad_datasets_are_rejected_with_a_reason(kind, data, reason) -> None:
    with pytest.raises(cx.DatasetRejected, match=reason):
        cx.parse(kind, data)


# --------------------------------------------------------------------------
from tests.test_frr_intake import (  # noqa: E402,F401  (env is a fixture)
    ANALYST, VIEWER, _URL, _fresh, _settle, _upload, connect, env,
)

needs_db = pytest.mark.skipif(not _URL, reason="NPR_TEST_DATABASE_URL is not set")


@pytest.fixture()
def ctxenv(env):
    from src.jobs.worker import Worker
    w = Worker(kinds=["context.ingest"], concurrency=1, connect=connect, lease_s=30).start()
    yield env
    w.stop(timeout=10)
    c = connect()
    with c.cursor() as cur:
        cur.execute("DELETE FROM ztpa.context_datasets")
        cur.execute("DELETE FROM ztpa.jobs WHERE kind = 'context.ingest'")
    c.commit()
    c.close()


def _load(c, kind, data):
    r = c.post(f"/api/context/{kind}", params={"filename": f"{kind}.csv"}, content=data,
               headers={**ANALYST, "content-type": "text/csv"})
    assert r.status_code == 202, r.text
    did = r.json()["dataset"]["dataset_id"]
    for _ in range(100):
        ds = next(d for d in c.get("/api/context", headers=VIEWER).json()["items"] if d["dataset_id"] == did)
        if ds["status"] != "received":
            return ds
        time.sleep(0.1)
    raise AssertionError("dataset not processed")


@needs_db
def test_flows_turn_narrowing_into_an_evidence_backed_suggestion(ctxenv) -> None:
    c = ctxenv
    assert _load(c, "cmdb", CMDB)["status"] == "accepted"
    flows = _load(c, "flows", _flows(datetime.now(timezone.utc)))
    assert flows["status"] == "accepted" and flows["active"] is True
    assert c.get("/api/context/owners", params={"net": "10.30.0.7"}, headers=VIEWER).json()["items"][0]["owner"] \
        == "dc-team@example.com"

    eid = _settle(c, _upload(c, _fresh()).json()["export"]["export_id"])["export_id"]
    pkg = c.post(f"/api/exports/{eid}/change-package", headers=ANALYST).json()
    rule4 = next(i for i in pkg["items"] if i["rule_number"] == 4)          # corp-net -> dc-servers ssh/rdp
    obs = rule4["evidence"]["observed_sources"]
    cidrs = [g["cidr"] for g in obs["groups"]]
    assert cidrs[0] == "10.20.5.0/24" and "10.20.9.0/24" in cidrs and "10.99.0.0/24" not in cidrs
    assert rule4["evidence"]["suggested_input"]["allowed_sources"] == cidrs
    assert "Flows over the last 90 days" in rule4["rationale"]
    assert rule4["evidence"]["dest_owners"][0]["owner"] == "dc-team@example.com"


@needs_db
def test_without_flows_the_package_says_so(ctxenv) -> None:
    c = ctxenv
    eid = _settle(c, _upload(c, _fresh()).json()["export"]["export_id"])["export_id"]
    pkg = c.post(f"/api/exports/{eid}/change-package", headers=ANALYST).json()
    assert any("no flow data loaded" in l for l in pkg["limitations"])
    assert all("observed_sources" not in i["evidence"] for i in pkg["items"])


@needs_db
def test_a_bad_dataset_is_rejected_and_never_active(ctxenv) -> None:
    ds = _load(ctxenv, "cmdb", b"owner,app\nx,y\n")
    assert ds["status"] == "rejected" and "missing required column" in ds["rejection_reason"]
    assert ds["active"] is False
