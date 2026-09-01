"""Truth-in-labelling tests for the staging area: the screen may not assert
something the engine did not do.

The production-readiness audit found three lies on the staging screen, all of the
same shape -- narrated action != executed action:

  1. every push step claimed a live connector ("Connected to the algosec policy
     data source", "Change written to the algosec data source"), for a push that
     contacts nothing;
  2. a duplicate resolved as "Skip: this flow is already permitted (no-op)" and
     was then appended to the record set anyway by the pushed-changes overlay;
  3. nothing on the wire told the UI the push was simulated, so the wording was
     hardcoded in the component.

`detect_conflicts` / `build_push_plan` / `apply_overlay` are pure functions over
a record set, so all of this is asserted directly -- no database, no model, no
`get_conn`. The one DB-shaped fact that matters (which rows the overlay is even
eligible to fold in) is asserted against the SQL `load_applied_changes` issues,
via a recording cursor: there is no live database in this suite and `.env` holds
placeholders, so the statement itself is the contract.
"""

from __future__ import annotations

import types

import pytest

from src.change.apply import apply_overlay
from src.change.staging import build_push_plan, detect_conflicts
from src.models import PolicyRecord
from src.persist import load_applied_changes

# Step text that would claim something this build cannot do. Matched
# case-insensitively against every label and detail of every generated plan.
FORBIDDEN_STEP_PHRASES = (
    "connected to",            # nothing is contacted
    "data source updated",     # no data source is written
    "change written",          # ditto
    "written to the algosec",  # ditto, tool-specific phrasing
)


def _rec(ref: str, source: str, destination: str, *, action: str = "allow",
         port: int | None = 443, protocol: str = "tcp", order: int = 10,
         source_kind: str = "cidr", tags: list[str] | None = None) -> PolicyRecord:
    """A canonical rule, spelled out field by field so each test's record set is
    readable on its own (the seeded demo dataset is deliberately not used: these
    assertions are about the push plan, not about the demo data)."""
    return PolicyRecord(
        id=f"r-{ref}", source_tool="algosec", raw_ref=ref, source=source, source_kind=source_kind,
        destination=destination, destination_kind="identity", dest_tags=tags or [],
        service=f"{protocol}/{port}" if port else protocol, port=port, protocol=protocol,
        action=action, order=order,
    )


def _ctx(*records: PolicyRecord, alias_map: dict[str, str] | None = None):
    """The engine surface `detect_conflicts` actually reads: records + alias_map."""
    return types.SimpleNamespace(records=list(records), alias_map=alias_map or {})


def _staged(rec: PolicyRecord, *, staged_id: str = "stage_1", kind: str = "add_allow",
            tool: str = "algosec") -> dict:
    """A staged_changes row as the push route hands it to build_push_plan: the
    payload is a PolicyRecord dump, which is what apply_overlay reconstructs."""
    return {"staged_id": staged_id, "kind": kind, "target_tool": tool, "payload": rec.model_dump()}


def _step(plan: dict, key: str) -> dict:
    return next(s for s in plan["push_steps"] if s["key"] == key)


def _overlay_rows(plan: dict, staged: dict) -> list[dict]:
    """The rows the engine would fold in on the next recompute, given this plan.

    Mirrors persist.load_applied_changes' eligibility rule -- only a row left in
    status 'pushed' is applied -- which test_overlay_eligibility_is_status_pushed
    pins to the real SQL so this helper cannot drift away from production."""
    return [{"kind": staged["kind"], "payload": staged["payload"]}] if plan["status"] == "pushed" else []


class _RecordingCursor:
    """Minimal psycopg-cursor stand-in. Records the statements it is handed and
    replays a canned row set; opening a real connection is forbidden here (the
    checked-in DATABASE_URL is a placeholder and CI has no Postgres)."""

    def __init__(self, rows: list[dict] | None = None) -> None:
        self.rows = rows or []
        self.statements: list[str] = []

    def execute(self, sql: str, params=None) -> None:
        self.statements.append(" ".join(sql.split()))

    def fetchall(self) -> list[dict]:
        return self.rows


# --------------------------------------------------------------------------
# 1. A step that reports "skip" must actually skip
# --------------------------------------------------------------------------

def test_duplicate_reports_skip_and_the_overlay_really_skips():
    """The headline lie. An identical allow already exists, the plan says
    "Skip: ... (no-op)", so the record set after the overlay must be IDENTICAL
    to the record set before it."""
    existing = _rec("algosec-7", "10.1.0.0/16", "app-segment")
    ctx = _ctx(existing)
    proposed = _rec("req-1", "10.1.0.0/16", "app-segment")
    staged = _staged(proposed)

    conflicts = detect_conflicts(ctx, staged)
    assert [c["kind"] for c in conflicts] == ["duplicate"]
    assert conflicts[0]["resolution"].startswith("Skip:")

    plan = build_push_plan(ctx, staged)
    assert plan["status"] == "no_op"

    before = list(ctx.records)
    after = apply_overlay(ctx.records, _overlay_rows(plan, staged))
    assert [r.raw_ref for r in after] == [r.raw_ref for r in before]
    assert len(after) == len(before) == 1


def test_duplicate_sibling_staged_change_also_really_skips():
    """Same rule for the sibling-staged duplicate: reported skip, executed skip."""
    ctx = _ctx(_rec("algosec-7", "10.9.0.0/16", "db-segment", action="deny"))
    proposed = _rec("req-2", "10.2.0.0/16", "app-segment")
    staged = _staged(proposed, staged_id="stage_a")
    sibling = _staged(_rec("req-3", "10.2.0.0/16", "app-segment"), staged_id="stage_b")

    plan = build_push_plan(ctx, staged, [sibling])
    assert [c["kind"] for c in plan["conflicts"]] == ["duplicate_staged"]
    assert plan["status"] == "no_op"
    assert apply_overlay(ctx.records, _overlay_rows(plan, staged)) == ctx.records


def test_skip_step_says_nothing_was_recorded():
    """The operator has to be able to read the outcome off the step, not infer it."""
    ctx = _ctx(_rec("algosec-7", "10.1.0.0/16", "app-segment"))
    plan = build_push_plan(ctx, _staged(_rec("req-1", "10.1.0.0/16", "app-segment")))
    apply_step = _step(plan, "apply")
    assert apply_step["status"] == "warn"
    assert "Skipped" in apply_step["label"]
    assert "no-op" in apply_step["detail"]
    # ... and the plan must NOT also carry the "staged for the tool" step, which
    # is the one that says something was recorded.
    assert not any(s["key"] == "verify" for s in plan["push_steps"])


def test_overlay_eligibility_is_status_pushed():
    """Pins the executed-action side of the contract: the engine folds in ONLY
    rows left in status 'pushed', which is why a 'no_op' plan is a real skip."""
    cur = _RecordingCursor([{"kind": "add_allow", "payload": {}}])
    rows = load_applied_changes(cur)  # type: ignore[arg-type]
    assert rows == [{"kind": "add_allow", "payload": {}}]
    assert "status='pushed'" in cur.statements[0]


# --------------------------------------------------------------------------
# 2. A clean push is still honest about what it did
# --------------------------------------------------------------------------

def test_clean_change_is_applied_and_says_only_that():
    """No conflicts -> the change IS folded into the engine's own record set on
    the next recompute (that part is real), and the steps claim nothing more."""
    ctx = _ctx(_rec("algosec-7", "10.1.0.0/16", "db-segment"))
    proposed = _rec("req-9", "10.4.0.0/16", "app-segment")
    staged = _staged(proposed)

    plan = build_push_plan(ctx, staged)
    assert plan["conflicts"] == []
    assert plan["status"] == "pushed"

    after = apply_overlay(ctx.records, _overlay_rows(plan, staged))
    assert [r.raw_ref for r in after] == ["algosec-7", "req-9"]

    verify = _step(plan, "verify")
    assert "recompute" in verify["detail"]
    assert "source system stays unchanged" in verify["detail"]


def test_contradiction_is_held_and_nothing_is_applied():
    """An explicit deny still blocks; the plan neither applies nor claims to."""
    ctx = _ctx(_rec("algosec-4", "10.5.0.0/16", "app-segment", action="deny"))
    staged = _staged(_rec("req-4", "10.5.0.0/16", "app-segment"))

    plan = build_push_plan(ctx, staged)
    assert [c["kind"] for c in plan["conflicts"]] == ["contradiction"]
    assert plan["status"] == "conflict"
    assert _step(plan, "apply")["status"] == "blocked"
    assert apply_overlay(ctx.records, _overlay_rows(plan, staged)) == ctx.records


def test_resolve_step_keys_are_unique_per_conflict():
    """The UI keys its animated list on step.key; two conflicts of the same kind
    used to collide on 'resolve:overlap' and drop a row."""
    ctx = _ctx(_rec("algosec-1", "10.0.0.0/8", "app-segment"),
               _rec("algosec-2", "10.6.0.0/16", "app-segment"))
    plan = build_push_plan(ctx, _staged(_rec("req-5", "10.6.1.0/24", "app-segment")))
    kinds = [c["kind"] for c in plan["conflicts"]]
    assert kinds == ["overlap", "overlap"]
    keys = [s["key"] for s in plan["push_steps"]]
    assert len(keys) == len(set(keys))


# --------------------------------------------------------------------------
# 3. The payload declares the simulation; no step claims a live connector
# --------------------------------------------------------------------------

def _all_plans() -> list[dict]:
    """One plan per outcome the builder can produce: pushed / no_op / conflict /
    stale remediation target."""
    clean_ctx = _ctx(_rec("algosec-7", "10.1.0.0/16", "db-segment"))
    dup_ctx = _ctx(_rec("algosec-7", "10.1.0.0/16", "app-segment"))
    deny_ctx = _ctx(_rec("algosec-4", "10.5.0.0/16", "app-segment", action="deny"))
    rem = {"staged_id": "stage_r", "kind": "remediation", "target_tool": "algosec",
           "payload": {"op": "remove", "target_ref": "algosec-gone"}}
    return [
        build_push_plan(clean_ctx, _staged(_rec("req-9", "10.4.0.0/16", "app-segment"))),
        build_push_plan(dup_ctx, _staged(_rec("req-1", "10.1.0.0/16", "app-segment"))),
        build_push_plan(deny_ctx, _staged(_rec("req-4", "10.5.0.0/16", "app-segment"))),
        build_push_plan(clean_ctx, rem),
    ]


@pytest.mark.parametrize("plan", _all_plans())
def test_push_plan_declares_itself_simulated(plan):
    """The UI renders its wording from this flag instead of hardcoding a claim,
    so it has to be on every plan, whatever the outcome."""
    assert plan["simulated"] is True
    assert plan["status"] in ("pushed", "no_op", "conflict")


@pytest.mark.parametrize("plan", _all_plans())
def test_no_step_claims_a_live_connector_was_contacted(plan):
    for step in plan["push_steps"]:
        text = f"{step['label']} {step['detail']}".lower()
        for phrase in FORBIDDEN_STEP_PHRASES:
            assert phrase not in text, f"step {step['key']!r} claims {phrase!r}: {text}"


@pytest.mark.parametrize("plan", _all_plans())
def test_fabricated_steps_are_labelled_simulated(plan):
    """connect / validate / stage / reflect do not happen. Each must say so; the
    conflict steps, which ARE genuine engine math, must NOT (a blanket
    'Simulated' on everything would understate the analysis)."""
    fabricated = [s for s in plan["push_steps"] if s["key"] in ("connect", "validate")]
    assert len(fabricated) == 2
    for step in fabricated:
        assert step["label"].startswith("Simulated:")
    assert "no live" in _step(plan, "connect")["detail"].lower()
    assert not _step(plan, "detect")["label"].startswith("Simulated")


def test_no_conflict_resolution_promises_an_unperformed_merge():
    """An overlap used to resolve as "Merge: fold into the broader rule" -- the
    overlay never merges anything, it appends. The copy has to match."""
    ctx = _ctx(_rec("algosec-1", "10.0.0.0/8", "app-segment"))
    staged = _staged(_rec("req-5", "10.6.1.0/24", "app-segment"))
    plan = build_push_plan(ctx, staged)
    assert [c["kind"] for c in plan["conflicts"]] == ["overlap"]
    assert not plan["conflicts"][0]["resolution"].lower().startswith("merge:")
    # and the executed action really is "append, unmerged"
    after = apply_overlay(ctx.records, _overlay_rows(plan, staged))
    assert [r.raw_ref for r in after] == ["algosec-1", "req-5"]
