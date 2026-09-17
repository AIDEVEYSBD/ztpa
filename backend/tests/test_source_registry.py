"""The source registry, and the provenance lie it replaced.

The registry is the single place that knows what we can read and from where. It
replaced five copies of the same list that had no way to disagree loudly — the
`models.SourceTool` Literal, `profile._KNOWN_TOOLS`, the `sources.tool` CHECK in
schema.sql, `persist._DEVICE`, and the prose inside `identity.MAX_IP_FANOUT`.

The tests that matter most here are not the drift checks. They are the ones that
pin the two behaviours a stale copy of that list used to cause:

  * a record from an unlisted tool recorded under a DIFFERENT vendor's key, and
  * a legitimate merge withheld because a constant said only three tools exist.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src import sources
from src.identity import MAX_IP_FANOUT, fanout_cap, resolve_identities
from src.models import SourceTool
from src.normalizers.common import ObservedEntity
from src.normalizers.profile import (
    FieldMap, NormalizeError, SourceProfile, apply_profile, require_known_tool,
)

REPO = Path(__file__).resolve().parents[2]


# ── The registry is the one copy ───────────────────────────────────────────

def test_the_literal_and_the_registry_cannot_drift():
    """`models.SourceTool` is hand-written because a pydantic Literal must exist
    at class-definition time. This is what stops it going stale."""
    assert tuple(sorted(SourceTool.__args__)) == sources.TOOL_KEYS


def test_every_spec_declares_what_it_cannot_tell_us():
    """`blind_to` is the most useful field on a source card: it is what stops an
    operator reading an empty access lane as an empty access layer.

    Exempted for the fabric controllers, whose whole scope is links."""
    for spec in sources.REGISTRY:
        assert spec.yields, f"{spec.key} declares nothing it yields"
        if spec.key not in ("sd_wan", "sd_lan"):
            assert spec.blind_to, f"{spec.key} declares nothing it is blind to"


def test_algosec_is_not_described_as_an_inventory_product():
    """The most common wrong assumption in the room, encoded so a screen can set
    the expectation before an operator forms it.

    AlgoSec models enforcement points and policy. It does not enumerate access
    switches, workstations or VLANs on an access port, and a product that lets a
    reviewer believe otherwise has mis-sold its own coverage."""
    algosec = sources.BY_KEY["algosec"]
    blind = " ".join(algosec.blind_to).lower()
    assert "access switch" in blind
    assert "workstation" in blind


def test_fortitelemetry_is_disambiguated():
    """Two unrelated Fortinet products share this name. The one meant by
    "sources: Wiz, FortiTelemetry" is the Security Fabric control plane on
    TCP/8013, which has no API of its own — you read what it registered, via
    `monitor/system/csf`, and only from the fabric ROOT.

    Claiming the wrong one in front of a client is a capability claim we cannot
    back, so the disambiguation lives in the registry rather than in a slide."""
    fg = sources.BY_KEY["fortigate"]
    assert "fortitelemetry" in fg.aliases
    assert "csf" in fg.api
    assert "root" in fg.notes.lower()


def test_the_schema_check_is_open_not_a_fixed_list():
    """A closed CHECK here is what made `profile.py` relabel unlisted tools.

    Bring-your-own-source is a shipped feature; its records must persist under
    the operator's own name. The real constraint is non-empty."""
    schema = (REPO / "db" / "schema.sql").read_text()
    sources_table = schema[schema.index("CREATE TABLE IF NOT EXISTS sources"):]
    sources_table = sources_table[:sources_table.index(");")]
    assert "btrim(tool) <> ''" in sources_table
    assert "tool IN (" not in sources_table, (
        "a closed tool vocabulary is what the relabel existed to satisfy"
    )


def test_device_attribution_never_returns_none():
    """`resolved_objects` is UNIQUE on (snapshot_id, source_device, object_name,
    object_kind). The old three-entry `.get()` wrote NULL for every other tool,
    so two unlisted tools exporting a same-named object collided on insert."""
    for key in sources.TOOL_KEYS:
        assert sources.device_of(key)
    assert sources.device_of("acme-fw") == "acme-fw"


def test_an_unknown_tool_is_assumed_to_have_the_narrowest_scope():
    """Device tier is the conservative answer: it claims to see the least, so an
    unrecognised source cannot have its coverage overstated on a screen that
    tells an operator which lanes are accounted for."""
    assert sources.tier_of("acme-fw") == "device"
    assert sources.tier_of("algosec") == "aggregator"
    assert sources.tier_of("meraki") == "management_console"
    assert sources.tier_of("fortigate") == "device"


# ── The relabel, pinned dead ───────────────────────────────────────────────

def _profile(tool: str) -> SourceProfile:
    return SourceProfile(
        tool=tool, rules_path="rules",
        fields=FieldMap(src="src", dst="dst", service="svc", action="act", ref="id"),
    )


RAW = {"rules": [{"id": "R1", "src": "10.0.0.0/8", "dst": "10.1.0.0/16",
                  "svc": "tcp/443", "act": "allow"}]}


def test_a_byo_profile_keeps_its_own_tool_name():
    """THE REGRESSION THIS FILE EXISTS FOR.

    `profile.py` used to emit `source_tool="algosec"` for any tool outside the
    closed Literal, so that the record would validate. Bringing your own
    connector did not fail — it ingested cleanly under a different vendor's
    name, and every provenance claim it produced was false with nothing to
    notice it by.
    """
    res = apply_profile(RAW, _profile("acme-fw"))

    assert [r.source_tool for r in res.records] == ["acme-fw"]
    assert all(r.source_tool != "algosec" for r in res.records)


def test_a_profile_naming_no_tool_at_all_is_refused():
    """The one thing that IS an error. An empty tool attributes every record,
    object and finding to the empty string."""
    for empty in ("", "   "):
        with pytest.raises(NormalizeError, match="declares no `tool`"):
            require_known_tool(empty)


def test_no_source_file_still_rewrites_a_tool_name():
    """A grep, because the relabel was a single expression and would come back
    the same way: as a convenience for satisfying a type."""
    profile_src = (REPO / "backend" / "src" / "normalizers" / "profile.py").read_text()
    offending = [
        line for line in profile_src.splitlines()
        if re.search(r'source_tool\s*=.*\belse\s+"[a-z_]+"', line)
    ]
    assert not offending, f"a tool name is being rewritten again: {offending}"


# ── The fan-out cap, pinned to evidence rather than to a constant ──────────

def test_the_cap_counts_naming_tools_not_a_constant():
    """A host produces at most one name per tool that observes it, so the bound
    is the number of tools that actually named this address."""
    assert fanout_cap({"wiz"}) == 1
    assert fanout_cap({"algosec", "guardicore", "wiz"}) == 3
    assert fanout_cap(set()) == 1


def test_link_only_tools_do_not_widen_the_merge_guard():
    """An SD-WAN/SD-LAN fabric describes links, not hosts. It cannot contribute
    a name, so it must not raise the ceiling on how many names are explicable."""
    assert fanout_cap({"wiz", "sd_wan", "sd_lan"}) == 1
    assert "sd_wan" not in sources.HOST_DESCRIBING_TOOLS
    assert "sd_lan" not in sources.HOST_DESCRIBING_TOOLS


def test_registering_a_connector_nobody_onboarded_cannot_weaken_the_guard():
    """The trap in the obvious fix.

    Replacing the hardcoded 3 with `len(HOST_DESCRIBING_TOOLS)` fixes the
    four-tool bug and introduces a worse one: adding a connector to the
    catalogue would loosen the merge guard on every estate, including estates
    that never onboarded it. The cap must depend on the evidence, not on the
    size of the catalogue.
    """
    ents = [ObservedEntity(name=f"vip-{i}", kind="identity", tool="wiz",
                           ip="10.9.9.9", identifiers={"vpc": "vpc-a"})
            for i in range(4)]

    r = resolve_identities(ents)

    assert len(r.assets) == 4, "four names from ONE tool is a shared address"
    assert r.suppressed_by_reason == {"ip_fanout": 1}
    # ...and it stays withheld no matter how large the catalogue grows.
    assert MAX_IP_FANOUT >= 4


def test_four_tools_naming_one_host_merge_again():
    """The bug the hardcoded 3 caused: a host observed by four tools was
    withheld, the asset silently split in two, and any cross-tool path through
    it vanished from the findings with nothing reporting a problem."""
    ents = [
        ObservedEntity(name=n, kind="identity", tool=t, ip="10.30.7.7",
                       identifiers={"vpc": "vpc-1"})
        for n, t in [("app-server-07", "algosec"), ("appsrv-07", "wiz"),
                     ("app07", "guardicore"), ("APP-SERVER-07", "fortimanager")]
    ]

    r = resolve_identities(ents)

    assert len(r.assets) == 1
    assert r.suppressed_merges == 0
