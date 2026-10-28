"""FRR mode switches off auto-approval and device push in the older change gate."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.main as m

ADMIN = {"x-npr-role": "admin", "x-npr-email": "root@example.com"}


def _a_resolvable_change():
    f = next(f for f in m.engine().findings if f.type == "over_permissive")
    return f.id, {"op": "remove", "target_ref": f.raw_refs[0]}


def test_off_by_default_the_gate_can_auto_approve(monkeypatch) -> None:
    monkeypatch.delenv("NPR_FRR_MODE", raising=False)
    fid, change = _a_resolvable_change()
    assert m._rule_remediation(fid, change)["decision_row"]["decision"] == "auto_approve"


def test_frr_mode_escalates_everything(monkeypatch) -> None:
    monkeypatch.setenv("NPR_FRR_MODE", "true")
    fid, change = _a_resolvable_change()
    row = m._rule_remediation(fid, change)["decision_row"]
    assert row["decision"] == "escalate" and "FRR mode" in row["triggering_reason"]


def test_frr_mode_refuses_push_before_touching_anything(monkeypatch) -> None:
    monkeypatch.setenv("NPR_FRR_MODE", "true")
    r = TestClient(m.app).post("/api/staging/any-id/push", headers=ADMIN)
    assert r.status_code == 403 and "runbook" in r.text
