"""FRR agents: the model may only narrate, its output is validated, invented
citations are refused, and every failure falls back to labelled engine text.
Offline: the model is a stub. A real-database orchestrated run is below."""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from src.frr import agents, knowledge
from src.frr import package as pk
from src.frr.review import review
from src.normalizers import checkpoint as cp
from tests import cp_fixture as fx


@dataclass
class R:
    text: str
    ok: bool = True
    provider: str = "stub"
    model: str = "m"
    error: str | None = None


def stub(payload, ok=True):
    calls = []

    def llm(**kw):
        calls.append(kw)
        return R(json.dumps(payload) if not isinstance(payload, str) else payload, ok=ok,
                 error=None if ok else "down")
    llm.calls = calls
    return llm


@pytest.fixture(scope="module")
def item():
    p = cp.parse(fx.export())
    d = pk.draft(json.loads(json.dumps(review(p).to_jsonable())), json.loads(json.dumps(p.to_jsonable())))
    return d["items"][0]


CTX = [{"cite": "abcd1234#0", "kind": "standard", "title": "Remote access standard",
        "heading": "SSH", "body": "SSH from the internet is prohibited; use the bastion."}]
P = agents.prompt("impact.v1")


def test_a_valid_narrative_is_kept_with_provenance(item) -> None:
    llm = stub({"summary": "Allows SSH from anywhere.", "availability_note": "Admins lose direct access.",
                "owner_questions": ["Who uses this?"], "cites": ["abcd1234#0"]})
    out = agents.assess_item(item, CTX, P, llm)
    assert out["by"] == "stub:m" and out["cites"] == ["abcd1234#0"]
    assert out["prompt"].startswith("impact.v1@")
    sent = json.loads(llm.calls[0]["user"])
    assert sent["context"][0]["cite"] == "abcd1234#0" and "severity_vector" not in sent["item"]["evidence"]


def test_the_model_cannot_change_band_proposal_or_commands(item) -> None:
    llm = stub({"summary": "ok", "band": "low", "proposal": "keep", "commands": ["rm -rf /"]})
    out = agents.assess_item(item, CTX, P, llm)
    assert not {"band", "proposal", "commands"} & set(out)


@pytest.mark.parametrize("payload, ok, reason", [
    ({"summary": "x", "cites": ["made-up#9"]}, True, "not given"),
    ({"availability_note": "no summary"}, True, "schema"),
    ({"summary": "x" * 2000}, True, "schema"),
    ("not json at all", True, "schema"),
    ({}, False, "down"),
])
def test_failures_fall_back_to_labelled_engine_text(item, payload, ok, reason) -> None:
    out = agents.assess_item(item, CTX, P, stub(payload, ok=ok))
    assert out["by"] == "engine_fallback" and reason in out["fallback_reason"]
    assert out["summary"] == item["rationale"]


def test_package_summary_falls_back_with_exact_numbers() -> None:
    p = cp.parse(fx.export())
    d = pk.draft(json.loads(json.dumps(review(p).to_jsonable())), json.loads(json.dumps(p.to_jsonable())))
    out = agents.summarise_package(d, agents.prompt("package.v1"), stub({}, ok=False))
    assert out["by"] == "engine_fallback" and f"{d['summary']['items']} proposed changes" in out["summary"]


def test_agents_and_prompt_versions_are_declared() -> None:
    keys = [a.key for a in agents.AGENTS]
    assert keys == ["orchestrator", "intake_parser", "policy_checker", "impact_assessor", "package_drafter"]
    assert all(agents.prompt(a.prompt).version for a in agents.AGENTS if a.prompt)


def test_chunking_follows_headings_and_size() -> None:
    doc = "# Remote access\nSSH only via bastion.\n## Exceptions\n" + ("word " * 600)
    chunks = knowledge.chunk(doc)
    assert chunks[0] == ("Remote access", "SSH only via bastion.")
    assert all(h == "Exceptions" for h, _ in chunks[1:]) and len(chunks) >= 3
    assert all(len(b) <= 1200 for _, b in chunks)


# --------------------------------------------------------------------------
# orchestrated run on a real database
# --------------------------------------------------------------------------
from tests.test_frr_intake import (  # noqa: E402,F401  (env is a fixture)
    _URL, _fresh, _settle, _upload, connect, env,
)

needs_db = pytest.mark.skipif(not _URL, reason="NPR_TEST_DATABASE_URL is not set")
ADMIN = {"x-npr-role": "admin", "x-npr-email": "root@example.com", "x-npr-sub": "sub-root"}
ANALYST = {"x-npr-role": "analyst", "x-npr-email": "ada@example.com", "x-npr-sub": "sub-ada"}


@pytest.fixture()
def runner(env, monkeypatch):
    """The intake env plus a worker for review runs, the model stubbed to cite
    whatever context it was given."""
    from src.jobs.worker import Worker
    from tests.test_frr_intake import connect as c

    def fake_complete(**kw):
        ctx = json.loads(kw["user"]).get("context") or []
        if kw.get("capability") == "frr_package":
            return R(json.dumps({"summary": "pkg summary", "key_risks": ["any-any"]}))
        return R(json.dumps({"summary": "narrated", "availability_note": "n",
                             "owner_questions": ["who?"], "cites": [x["cite"] for x in ctx[:1]]}))
    monkeypatch.setattr(agents, "complete", fake_complete)
    w = Worker(kinds=["frr.review_run"], concurrency=1, connect=c, lease_s=30).start()
    yield env
    w.stop(timeout=10)
    conn = c()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM ztpa.knowledge_docs WHERE title LIKE 'TEST %'")
        cur.execute("DELETE FROM ztpa.jobs WHERE kind = 'frr.review_run'")
        cur.execute("DELETE FROM ztpa.frr_approvers WHERE principal LIKE '%@example.com'")
    conn.commit()
    conn.close()


def _wait_run(client, run_id, timeout=30):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/frr/runs/{run_id}", headers=ANALYST).json()
        if run["status"] in ("succeeded", "failed"):
            return run
        time.sleep(0.1)
    raise AssertionError("run did not finish")


@needs_db
def test_an_orchestrated_run_hands_off_through_all_five_agents(runner) -> None:
    c = runner
    doc = "# Remote access\nSSH and RDP from the internet are prohibited; use the bastion.\n" \
          "# Rule cleanup\nUnused rules are disabled for 30 days before removal; rollback re-enables them."
    r = c.post("/api/knowledge", params={"kind": "standard", "title": "TEST network standard"},
               content=doc.encode(), headers=ADMIN)
    assert r.status_code == 201 and r.json()["chunks"] == 2
    hits = c.get("/api/knowledge/search", params={"q": "ssh internet bastion"}, headers=ANALYST).json()
    assert hits["items"][0]["heading"] == "Remote access"

    eid = _settle(c, _upload(c, _fresh()).json()["export"]["export_id"])["export_id"]
    run = c.post(f"/api/exports/{eid}/review-runs", headers=ANALYST)
    assert run.status_code == 202
    done = _wait_run(c, run.json()["run_id"])
    assert done["status"] == "succeeded", done
    agents_seen = [s["agent"] for s in done["steps"]]
    assert agents_seen == ["orchestrator", "intake_parser", "policy_checker", "impact_assessor",
                           "package_drafter", "orchestrator"]
    assessor = next(s for s in done["steps"] if s["agent"] == "impact_assessor")
    assert assessor["narrated"] == 7 and assessor["prompt"].startswith("impact.v1@")

    pkg = c.get(f"/api/change-packages/{done['package_id']}", headers=ANALYST).json()
    assert pkg["narrative"]["summary"] == "pkg summary"
    cited = [i["narrative"]["cites"] for i in pkg["items"] if i["narrative"]["cites"]]
    assert cited, "narratives should cite the retrieved standard"
    # Deterministic content untouched by the narrative.
    assert {i["proposal"] for i in pkg["items"]} <= {"remove", "disable_then_remove",
                                                     "time_bound_and_narrow", "revisit_after", "reorder"}


@needs_db
def test_a_rerun_never_replaces_a_package_under_review(runner) -> None:
    c = runner
    c.post("/api/admin/frr/approvers", json={"principal": "olivia@example.com", "duty": "network_owner"},
           headers=ADMIN)
    eid = _settle(c, _upload(c, _fresh()).json()["export"]["export_id"])["export_id"]
    first = _wait_run(c, c.post(f"/api/exports/{eid}/review-runs", headers=ANALYST).json()["run_id"])
    pkg = c.get(f"/api/change-packages/{first['package_id']}", headers=ANALYST).json()
    it = pkg["items"][0]
    owner = {"x-npr-role": "viewer", "x-npr-email": "olivia@example.com"}
    assert c.put(f"/api/change-packages/{pkg['package_id']}/items/{it['item_id']}",
                 json={"decision": "reject", "note": "known exception"}, headers=owner).status_code == 200
    second = _wait_run(c, c.post(f"/api/exports/{eid}/review-runs", headers=ANALYST).json()["run_id"])
    assert second["status"] == "failed"
    assert "already under review" in second["steps"][-1]["reason"]
    assert c.get(f"/api/change-packages/{pkg['package_id']}", headers=ANALYST).json()["status"] == "draft"
