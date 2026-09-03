"""The change gate must rule on what a rule GRANTS, never on how it is spelled.

The defect (PROD-READINESS-AUDIT-2, refutation of `internet-from-graph`):
`simulate.resolve_cidrs` derived a proposal's address space from `cidrs_for_token`
plus the engine's ASSET SET only. `normalizers/algosec.py` emits an entity solely
for a token some EXISTING rule references, so a perimeter object that is defined
in the export's catalog but not currently used by any rule resolved to
`source_cidrs == []`.

Everything then failed at once: E fell to E_IDENTITY (0.1, one host) instead of
1.0, `is_internet_source` answered False, the proposed boundary read
internal->internal, and `build.ensure` gave the node `ip_set=[]` so
`_internet_sensitive_paths` found no new path.

Consequence: "allow tcp/22 from ANY-EXTERNAL to db-prod-01 (pci)" came back
`forced_escalate=False` with no reasons, while the byte-identical request written
`0.0.0.0/0` was `forced_escalate=True`. `advisory.classify_change` short-circuits
on `forced_escalate` BEFORE any model call -- so the gap was an auto-approve of
internet-to-PCI SSH decided purely by spelling. That is the exact hole
`simulate.py`'s own module docstring claims to have closed.

The fix reads the export's object catalog (`EngineResult.resolved`) as well.
"""

from __future__ import annotations

import pytest

from src.analyzers.run_all import run
from src.change.simulate import resolve_cidrs, simulate_change
from src.models import PolicyRecord
from src.normalizers.common import ResolvedObject

# The perimeter objects a real AlgoSec catalog defines and that the seeded demo
# fixture does not use in any rule -- which is precisely what made them invisible.
PERIMETER = [
    ResolvedObject(source_tool="algosec", object_name="ANY-EXTERNAL", object_kind="address",
                   resolved={"value": "0.0.0.0/0", "type": "network", "tags": [],
                             "cidrs": ["0.0.0.0/0"], "abstract": True}),
    ResolvedObject(source_tool="algosec", object_name="INTERNET", object_kind="address",
                   resolved={"value": "0.0.0.0/0", "type": "network", "tags": [],
                             "cidrs": ["0.0.0.0/0"], "abstract": True}),
]

SPELLINGS = ["0.0.0.0/0", "any", "ANY-EXTERNAL", "INTERNET"]


@pytest.fixture(scope="module")
def engine():
    return run(label="seed-demo")


def _catalog(engine):
    return list(engine.resolved) + PERIMETER


def _proposal(source: str) -> PolicyRecord:
    """SSH from `source` to the PCI database. Identical grant every time."""
    return PolicyRecord(
        id="probe", source_tool="algosec", raw_ref="PROBE-GATE",
        source=source, source_kind="cidr" if source == "0.0.0.0/0" else "identity",
        destination="db-prod-01", destination_kind="identity",
        service="tcp/22", port=22, protocol="tcp", action="allow", order=999,
    )


@pytest.mark.parametrize("source", SPELLINGS)
def test_every_spelling_of_the_internet_force_escalates(engine, source):
    """THE SECURITY PROPERTY. Spelling must not buy an auto-approve.

    `forced_escalate` is checked before any model call, so a False here is not a
    softer ruling -- it is the gate handing the decision to the LLM under a delta
    that reads "no new internet paths".
    """
    delta = simulate_change(engine.records, engine.assets, engine.alias_map,
                            _proposal(source), _catalog(engine))
    assert delta["forced_escalate"] is True, (
        f"{source!r} did not force-escalate SSH from the internet to a PCI database"
    )
    assert delta["forced_reasons"], f"{source!r} force-escalated with no stated reason"


def test_all_four_spellings_resolve_to_the_same_address_space(engine):
    """The mechanism under the property: one address space, four labels."""
    spaces = {s: resolve_cidrs(s, engine.assets, engine.alias_map, (), _catalog(engine))
              for s in SPELLINGS}
    canonical = {s: sorted(set(v)) for s, v in spaces.items()}
    assert all("0.0.0.0/0" in v for v in canonical.values()), canonical


def test_a_catalogued_object_no_rule_uses_is_still_resolved(engine):
    """The specific gap: the asset set cannot see an unused catalog entry.

    Asserted directly, because it is the reason the bug survived a fix that was
    validated against objects the demo rules DO reference.
    """
    assert not any(a.asset_key == "ANY-EXTERNAL" for a in engine.assets), (
        "fixture drift: ANY-EXTERNAL is now an asset, so this test no longer "
        "exercises the catalog-only path it exists for"
    )
    from_assets = resolve_cidrs("ANY-EXTERNAL", engine.assets, engine.alias_map)
    from_catalog = resolve_cidrs("ANY-EXTERNAL", engine.assets, engine.alias_map,
                                 (), _catalog(engine))
    assert from_assets == [], "precondition: the asset set alone knows nothing about it"
    assert "0.0.0.0/0" in from_catalog


def test_object_names_match_case_insensitively(engine):
    """Object names are operator-typed and vendors disagree about case."""
    for spelling in ("any-external", "Any-External", "ANY-EXTERNAL"):
        got = resolve_cidrs(spelling, engine.assets, engine.alias_map, (), _catalog(engine))
        assert "0.0.0.0/0" in got, spelling


def test_the_catalog_cannot_narrow_what_the_caller_declared(engine):
    """Union, never intersection -- resolution may only ever widen exposure."""
    got = resolve_cidrs("ANY-EXTERNAL", engine.assets, engine.alias_map,
                        ("10.9.9.0/24",), _catalog(engine))
    assert "10.9.9.0/24" in got and "0.0.0.0/0" in got
