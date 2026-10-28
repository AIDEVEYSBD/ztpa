"""Reviewer feedback: verdicts, agreement summary, and labels the eval reads."""

from __future__ import annotations

from tests.test_frr_intake import (  # noqa: F401  (env is a fixture)
    ANALYST, VIEWER, _fresh, _settle, _upload, env, pytestmark,
)

ADMIN = {"x-npr-role": "admin", "x-npr-email": "root@example.com", "x-npr-sub": "sub-root"}


def _export(c) -> str:
    return _settle(c, _upload(c, _fresh()).json()["export"]["export_id"])["export_id"]


def _fb(c, eid, uid, **body):
    return c.put(f"/api/exports/{eid}/review/{uid}/feedback", json=body, headers=ANALYST)


def test_feedback_becomes_eval_labels(env) -> None:
    c = env
    eid = _export(c)
    assert _fb(c, eid, "rule-1", check="any_any", verdict="agree").status_code == 200
    assert _fb(c, eid, "rule-4", check="admin_port_exposed", verdict="agree",
               suggested_band="medium").status_code == 200
    r = _fb(c, eid, "rule-9", check="over_permissive", verdict="disagree")
    assert r.status_code == 422                                        # needs a comment
    assert _fb(c, eid, "rule-9", check="over_permissive", verdict="disagree",
               comment="Admins role is a 4-person jump team").status_code == 200
    assert _fb(c, eid, "rule-2", check="unused", verdict="agree").status_code == 422   # not raised
    assert _fb(c, eid, "rule-2", check="broad_source", verdict="disagree",
               comment="internet to web farm should be flagged for WAF review").status_code == 422
    assert _fb(c, eid, "rule-2", check="broad_source", verdict="disagree", suggested_band="medium",
               comment="internet to web farm should be flagged for WAF review").status_code == 200

    summary = c.get(f"/api/exports/{eid}/feedback", headers=VIEWER).json()
    assert summary["summary"]["over_permissive"]["agreement"] == 0.0
    assert summary["suggested_bands"] == {"admin_port_exposed->medium": 1, "broad_source->medium": 1}

    assert c.get(f"/api/exports/{eid}/labels", headers=ANALYST).status_code == 403
    labels = c.get(f"/api/exports/{eid}/labels", headers=ADMIN).json()
    assert labels["rule-1"]["checks"] == ["any_any", "unused"] and labels["rule-1"]["band"] == "critical"
    assert labels["rule-4"]["band"] == "medium"
    assert labels["rule-9"]["checks"] == [] and labels["rule-9"]["band"] == "none"
    assert labels["rule-2"] == {"checks": ["broad_source"], "band": "medium", "reviewers": 1}
    assert "rule-7" not in labels                                        # unreviewed rules are not labels


def test_viewers_cannot_give_feedback_and_votes_update_in_place(env) -> None:
    c = env
    eid = _export(c)
    r = c.put(f"/api/exports/{eid}/review/rule-1/feedback", json={"check": "any_any", "verdict": "agree"},
              headers=VIEWER)
    assert r.status_code == 403
    _fb(c, eid, "rule-1", check="any_any", verdict="agree")
    _fb(c, eid, "rule-1", check="any_any", verdict="disagree", comment="changed my mind")
    items = c.get(f"/api/exports/{eid}/feedback", headers=VIEWER).json()["items"]
    assert len(items) == 1 and items[0]["verdict"] == "disagree"
    assert c.put(f"/api/exports/{eid}/review/no-such-rule/feedback",
                 json={"check": "any_any", "verdict": "agree"}, headers=ANALYST).status_code == 404
