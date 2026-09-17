"""A scenario is ONE estate, and the name in the picker is a claim.

THE RULE THIS FILE ENFORCES
---------------------------
    Every screen must be answering a question about the same network, and no
    screen may assert a state that another screen contradicts. `clean` may not
    report a critical anywhere, `partial` may not report full coverage anywhere,
    and `scale` must be large on every screen that has a size.

That was not true, and the failure was structural rather than cosmetic:
`scenarios._write` rewrote three of the estate's TEN exports, so the seven
infrastructure ones survived a scenario switch and belonged to whichever
scenario had written them last. Measured, before this file existed:

  * "Clean estate" reported ZERO policy findings beside an Explorer showing 13
    devices and a resilience analyzer reporting SIX single points of failure,
    four of them designed in. The screen contradicted the name.
  * "At scale" added 500 synthetic policy assets and left the topology at 13
    devices -- so the one screen the scale story exists for never changed, even
    though `estate.build(branches=N)` existed precisely to grow it.

Nothing caught either, because no test ever ran a scenario end to end. These do.
Each one writes the scenario into a SANDBOX, runs the real pipeline over it
(`normalize_all` -> `run` -> `reconstruct` -> `assess`), and asserts the row of
the matrix that scenario is supposed to produce.

WHY THE SANDBOX IS THE FIRST THING IN THIS FILE
-----------------------------------------------
`backend/data/mock` is not a fixture directory -- it is the engine's only input,
it is committed to git, and `test_demo_golden` measures a pinned snapshot id
against it. A test here that wrote to the real directory would leave the suite's
result dependent on test ORDER, which is the same class of defect as the one
above. `scenarios.MOCK_DIR` and `normalizers.MOCK_DIR` are two different module
globals -- the writer reads one and the reader reads the other -- so both are
redirected, and `test_the_writer_touches_nothing_outside_its_mock_dir` asserts
the redirection actually held rather than trusting it.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from src import normalizers, scenarios
from src.analyzers.resilience import assess
from src.analyzers.run_all import run

#: `scale` is run at a deliberately small n. The property under test is that the
#: topology grows WITH the rule table and that the policy answer does not move;
#: neither needs 500 branches, and the suite runs on every commit.
SCALE_N = 100


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(scenarios, "MOCK_DIR", tmp_path)
    monkeypatch.setattr(normalizers, "MOCK_DIR", tmp_path)
    return tmp_path


def _engine(scenario: str, n: int = 500):
    """Write a scenario and run the whole pipeline over it.

    Deliberately the real entrypoint rather than a hand-assembled ingest: the
    incoherence this file exists to catch lived in the seam between the writer
    and the reader, and a test that builds its own inputs cannot see a seam.
    """
    scenarios.write_scenario(scenario, n)
    result = run(label=scenario)
    return result, assess(result.topology)


def _table(result) -> set[tuple[str, tuple[str, ...], int]]:
    """A finding set keyed by CONTENT, not by id. `Finding.id` is derived from
    the snapshot id, and two scenarios never share one."""
    return {(f.type, tuple(sorted(f.raw_refs)), f.severity) for f in result.findings}


# ── The writer's own contract ──────────────────────────────────────────────

def test_the_writer_touches_nothing_outside_its_mock_dir(sandbox: Path) -> None:
    """The single most dangerous detail in the whole change.

    The infrastructure half of a dataset is projected by `seed_topology`, which
    has its own `MOCK_DIR` pointing at the real `backend/data/mock`. If
    `_write_dataset` resolved any path through THAT module instead of through
    `scenarios.MOCK_DIR`, this suite would write its fixtures over the engine's
    live input and every other test would be reading them.

    Asserted by watching the real directory's mtimes and contents across a write
    of every scenario, rather than by reading the source and believing it.
    """
    real = Path(normalizers.__file__).resolve().parents[2] / "data" / "mock"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in real.glob("*.json")}
    assert before, "the real data/mock should exist; this test is meaningless without it"

    for scenario in scenarios._BUILDERS:
        scenarios.write_scenario(scenario, SCALE_N)

    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in real.glob("*.json")}
    assert after == before, "a scenario write reached outside the sandbox"
    assert not list(real.glob(".*.tmp"))


@pytest.mark.parametrize("scenario", sorted(scenarios._BUILDERS))
def test_the_files_on_disk_are_a_function_of_the_scenario_and_nothing_else(
        sandbox: Path, scenario: str) -> None:
    """Write scenario X over every OTHER scenario in turn and assert the ten
    filenames land in exactly the same state each time.

    This is the defect, stated as a property. A file that survives a switch is a
    console the new scenario never onboarded -- `normalizers._load_optional`
    reads a present export as "this console answered" -- so the Sources screen
    and the Explorer would describe an estate the policy half has never seen.
    """
    states = []
    for previous in sorted(scenarios._BUILDERS):
        scenarios.write_scenario(previous, SCALE_N)
        scenarios.write_scenario(scenario, SCALE_N)
        states.append({p.name: p.read_text() for p in sandbox.glob("*.json")})

    assert all(s == states[0] for s in states), (
        f"'{scenario}' on disk depends on what was written before it")
    assert set(states[0]) >= set(scenarios.POLICY), "every scenario writes all three policy exports"
    assert not list(sandbox.glob(".*.tmp"))


@pytest.mark.parametrize("scenario", sorted(scenarios._BUILDERS))
def test_every_unobserved_lane_names_a_reason_and_an_api(
        sandbox: Path, scenario: str) -> None:
    """An empty lane and an unobserved lane are different claims, and only one of
    them is about the client's network. Every lane the product draws dark has to
    carry why it is dark and the exact read that would light it -- otherwise the
    Explorer is a picture with holes in it and no account of them."""
    result, _report = _engine(scenario, SCALE_N)
    for lane in result.topology.unobserved_layers:
        assert lane["reason"], f"{scenario}: {lane['layer']} is dark with no reason"
        assert lane["would_be_filled_by"], f"{scenario}: {lane['layer']} names no API"
    for gap in result.topology.unlinked_devices:
        assert gap["reason"] and gap["would_be_filled_by"], f"{scenario}: {gap['device_key']}"


# ── The four rows of the matrix ────────────────────────────────────────────

def test_demo_is_the_flagship_on_every_screen(sandbox: Path) -> None:
    """Nine consoles, two cross-tool paths, and three designed weak points that
    the resilience analyzer is supposed to find."""
    result, report = _engine("demo")

    assert len(result.findings) == 38
    paths = [f for f in result.findings if f.type == "cross_tool_path"]
    assert len(paths) == 2 and all(f.forced_critical for f in paths)
    assert {tuple(f.signals["path"])[-1] for f in paths} == {"db-prod-01", "db-prod-02"}

    topo = result.topology
    assert len(topo.devices) == 13
    assert len(topo.circuits) == 3
    assert len(topo.vlans) == 8
    # Every lane an onboarded console can see is drawn; the ONE that is not is
    # named. `endpoint` is honest -- no console in this estate enumerates a
    # workstation -- and it is the reason this assertion is `== ["endpoint"]`
    # rather than `== []`: a flagship with no absences in it would be the fiction.
    assert [l["layer"] for l in topo.unobserved_layers] == ["endpoint"]
    assert [d["device_key"] for d in topo.unlinked_devices] == ["ap-wifi-01"]

    assert report.analysable and not report.clean
    assert len(report.findings) == 6
    assert report.findings[0].severity_band == "critical"


def test_partial_loses_coverage_and_not_findings(sandbox: Path) -> None:
    """THE ARGUMENT THE PAIR EXISTS TO MAKE, as an assertion.

    `partial` and `demo` differ in exactly one variable: which infrastructure
    consoles are onboarded. If the policy answer is ever allowed to drift between
    them -- to make the switch look more dramatic on stage -- then a reviewer
    comparing the two screens is looking at two estates, and the comparison says
    nothing about coverage at all.
    """
    demo_result, _ = _engine("demo")
    partial_result, partial_report = _engine("partial")

    assert _table(partial_result) == _table(demo_result)
    assert Counter(f.severity_band for f in partial_result.findings) == \
        Counter(f.severity_band for f in demo_result.findings)

    # ...while the picture collapses to the enforcement points AlgoSec models.
    topo = partial_result.topology
    assert len(topo.devices) == 4
    assert not topo.circuits and not topo.vlans
    assert {d.layer for d in topo.devices} == {"edge", "perimeter"}
    assert len(topo.unobserved_layers) >= 5

    # The honesty beat: the analyzer found nothing AND says it analysed almost
    # nothing. An estate nobody observed must never render as an estate with no
    # single points of failure.
    assert partial_report.analysable
    assert not partial_report.findings
    assert "not about the estate" in partial_report.summary()

    assert normalizers.onboarded_sources() == ["algosec_topology_export.json"]


def test_clean_is_clean_on_both_graphs_and_still_names_one_absence(
        sandbox: Path) -> None:
    """The control case, and the row that used to contradict itself outright.

    Zero is only believable if it can be told apart from "we could not see the
    network", so all three of these are asserted together: no policy finding, no
    resilience finding, and `analysable` TRUE.
    """
    result, report = _engine("clean")

    assert result.findings == []
    assert [c for c in result.correlations if c.match_key == "manual_review"] == []

    topo = result.topology
    assert len(topo.devices) == 10
    assert len(topo.circuits) == 2
    assert topo.unlinked_devices == []
    assert report.analysable and report.clean and not report.findings
    # It still publishes the HA pair it CONSIDERED and declined to flag. A clean
    # report that shows its working is worth more than an empty one.
    assert any(s["kind"] == "ha_shared_failure_domain" for s in report.suppressed)

    # ...and it still names the one lane nothing reports, because a product that
    # prints an unqualified all-clear is the one you cannot trust when it prints
    # red.
    assert [l["layer"] for l in topo.unobserved_layers] == ["endpoint"]


def test_clean_onboards_meraki_and_meraki_reports_nothing(sandbox: Path) -> None:
    """"We read the org and it has no devices" and "we never asked" are two
    different cards on the Sources screen, and this estate has no Meraki
    hardware. So the export is written PRESENT AND EMPTY rather than removed --
    the one place in the set where that distinction can be demonstrated on screen
    instead of asserted in a docstring.
    """
    _engine("clean")

    assert normalizers.onboarded_sources() == sorted(scenarios.INFRA)
    meraki = json.loads((sandbox / "meraki_export.json").read_text())
    assert meraki and all(rows == [] for rows in meraki.values())


def test_scale_grows_the_picture_without_growing_the_ranked_list(
        sandbox: Path) -> None:
    """Both halves of "At scale", and the one that was missing.

    The topology has to grow -- that is the screen the scenario exists for, and
    it used to stay at 13 devices however large the rule table got. And the
    POLICY answer has to stay put: the synthetic assets live outside 10.0.0.0/8
    on purpose, because inside it every one of them was shadowed by ALGO-001 and
    n=500 produced 516 identical `shadowed_rule` findings. That is not throughput,
    it is 500 copies of a finding nobody reads, burying the flagship's 38.
    """
    demo_result, _ = _engine("demo")
    scale_result, scale_report = _engine("scale", SCALE_N)

    assert _table(scale_result) == _table(demo_result)
    assert len(scale_result.assets) > len(demo_result.assets) + SCALE_N - 1

    assert len(scale_result.topology.devices) > len(demo_result.topology.devices) * 4
    assert len(scale_result.topology.vlans) > len(demo_result.topology.vlans)

    # The estate got bigger, so its worst structural problem did not change: the
    # HQ's shared circuit handoff is still the top finding. Ranking is grouping by
    # root cause, not listing, and that is what survives volume.
    assert scale_report.findings[0].kind == "shared_circuit_handoff"


def test_no_branch_access_switch_is_drawn_among_the_workstations(
        sandbox: Path) -> None:
    """A fixture bug that only appears at scale, pinned where it appears.

    `_branch` put the site VLAN on `asw-01` only, so `asw-02` reached the
    reconstruction engine with a single addressed interface and no forwarding
    state -- and `_derive_role` correctly called it a SERVER and drew it in the
    endpoint lane. The engine was right and the fixture was starving it. At 250
    branches a buyer would have seen 250 Cisco C9200s sitting among the laptops.
    """
    result, _ = _engine("scale", SCALE_N)
    misplaced = [d.device_key for d in result.topology.devices
                 if d.device_key.endswith("-asw-02") and d.layer != "access"]
    assert not misplaced, f"branch access switches drawn outside the access lane: {misplaced}"
