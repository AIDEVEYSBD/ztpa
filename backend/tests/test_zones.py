"""Zone classification, the published boundary table, and graph construction.

These are the tests that would have caught the audit's zones.py:12 finding: with
``zone_of`` comparing ``node_key == "0.0.0.0/0"``, a rule sourced from
``0.0.0.0/1`` — half the routable IPv4 internet — was filed as internal→internal,
B collapsed from 1.5 to 1.0, and the guardrail that is advertised as
model-independent never fired. The same rule scored 90/critical or 56/medium
depending only on how the export spelled the source.

Three properties are pinned here, and they are the ones the product's claims rest
on:

1. **Zone is a function of the address space, not of its spelling.** A table over
   v4 and v6, public and special-use, wildcard words and named objects.
2. **The boundary multiplier is a published lookup.** Every ordered zone pair is
   asserted against `config.BOUNDARY_MULTIPLIERS` itself (so `boundary_multiplier`
   cannot start computing), plus the three documented crossings and the one
   documented omission asserted by value (so the table cannot be edited silently).
3. **A named subnet and the same subnet written as a raw CIDR are one node.**
   `_valid_traversal` decides which paths exist from the node's ``kind``, so if a
   ``network`` object arrives concrete while its CIDR arrives abstract,
   reachability becomes a function of export notation — which is exactly the
   defect behind the demo's flagship path pivoting through a /16.

No I/O, no database, no fixtures beyond plain model objects.
"""

from __future__ import annotations

import pytest

from src.config import (
    B_INTRA, BOUNDARY_MULTIPLIERS, ZONE_DEV, ZONE_DMZ, ZONE_INTERNAL, ZONE_INTERNET,
)
from src.graph.build import build_graph, node_db_kind, sensitive_assets
from src.graph.reachability import reachable
from src.graph.zones import boundary_label, boundary_multiplier, crosses_boundary, zone_of
from src.models import Asset, PolicyRecord

ALL_ZONES = [ZONE_INTERNET, ZONE_DMZ, ZONE_DEV, ZONE_INTERNAL]


def rec(rid: str, src: str, dst: str, *, service: str = "tcp/443", port: int | None = 443,
        protocol: str = "tcp", action: str = "allow", tool: str = "algosec",
        **kw) -> PolicyRecord:
    """A minimal canonical record. Only the graph-relevant fields matter here.

    `**kw` carries `source_cidrs` / `dest_cidrs` -- the RESOLVED address space a
    normalizer puts behind a named token, which `build_graph.ensure` now reads.
    """
    return PolicyRecord(
        id=rid, source_tool=tool, raw_ref=rid,
        source=src, source_kind="cidr" if "/" in src else "identity",
        destination=dst, destination_kind="cidr" if "/" in dst else "identity",
        service=service, port=port, protocol=protocol, action=action, **kw,
    )


# ---------------------------------------------------------------------------
# 1. zone_of: classification by address space
# ---------------------------------------------------------------------------

# The audit's exit criterion in table form. The first three rows are the
# regression: all of them are globally routable, all of them must be ZONE_INTERNET.
ZONE_TABLE = [
    ("0.0.0.0/0", ZONE_INTERNET),          # the whole space, by definition
    ("0.0.0.0/1", ZONE_INTERNET),          # half the internet; used to be "internal"
    ("1.0.0.0/8", ZONE_INTERNET),          # ordinary routable space
    ("10.0.0.0/8", ZONE_INTERNAL),         # RFC 1918
    ("192.168.1.0/24", ZONE_INTERNAL),     # RFC 1918
    ("::/0", ZONE_INTERNET),               # v6 default route
    ("2000::/3", ZONE_INTERNET),           # v6 global unicast
    ("169.254.0.0/16", ZONE_INTERNAL),     # RFC 3927 link-local
]


@pytest.mark.parametrize("token,expected", ZONE_TABLE)
def test_zone_of_classifies_address_space(token: str, expected: str) -> None:
    assert zone_of(token, []) == expected


@pytest.mark.parametrize("token", ["any", "Any", "ANY", "all", "*", "0.0.0.0/0.0.0.0"])
def test_wildcard_vocabulary_is_internet(token: str) -> None:
    """Every spelling of "everything" lands in the same zone as the literal /0.

    This is the zone half of the exit criterion that the same policy expressed
    four ways must score identically.
    """
    assert zone_of(token, []) == ZONE_INTERNET


@pytest.mark.parametrize("token,expected", ZONE_TABLE)
def test_zone_of_is_stable_under_repetition(token: str, expected: str) -> None:
    """Pure function: no memo, no clock, no set iteration leaking into the answer."""
    assert {zone_of(token, ["prod", "cloud"]) for _ in range(5)} == {
        zone_of(token, ["prod", "cloud"])}


def test_internet_classification_beats_tags() -> None:
    """A /0 mislabelled ``dev`` is still the internet — address space wins."""
    assert zone_of("0.0.0.0/1", ["dev", "sandbox"]) == ZONE_INTERNET


@pytest.mark.parametrize("tag,expected", [
    ("dmz", ZONE_DMZ), ("internet-facing", ZONE_DMZ), ("public", ZONE_DMZ),
    ("dev", ZONE_DEV), ("sandbox", ZONE_DEV), ("test", ZONE_DEV),
])
def test_tags_place_private_nodes(tag: str, expected: str) -> None:
    assert zone_of("app-server-07", [tag]) == expected


def test_most_exposed_tag_wins() -> None:
    """ZONE_PRIORITY is ordered, so a node tagged both dev and dmz is dmz —
    and the answer does not depend on tag order in the input list."""
    assert zone_of("box", ["dev", "dmz"]) == ZONE_DMZ
    assert zone_of("box", ["dmz", "dev"]) == ZONE_DMZ


@pytest.mark.parametrize("tags", [[], ["prod"], ["pci", "customer-data"], ["unknown-tag"]])
def test_untagged_and_unzoned_nodes_are_internal(tags: list[str]) -> None:
    assert zone_of("db-prod-01", tags) == ZONE_INTERNAL


def test_unresolvable_label_is_not_internet() -> None:
    """A token that names no address space is not evidence of internet exposure."""
    assert zone_of("ANY-EXTERNAL-GROUP", []) == ZONE_INTERNAL
    assert zone_of("", []) == ZONE_INTERNAL


@pytest.mark.parametrize("token", ["0.0.0.0", "::", "::1", "127.0.0.1", "100.64.0.0/10"])
def test_sentinel_and_non_routable_singletons_are_not_internet(token: str) -> None:
    """A bare unspecified address is an export placeholder, not the whole
    internet; CGNAT space is carrier space, not internet exposure."""
    assert zone_of(token, []) == ZONE_INTERNAL


# ---------------------------------------------------------------------------
# 1b. the concrete-asset carve-out
# ---------------------------------------------------------------------------

def test_concrete_host_holding_a_public_address_is_not_the_internet() -> None:
    """``lb-public-01`` (52.20.10.10) FACES the internet; it is not the internet.

    Zone is where a node lives. If a public-IP'd host classified as
    ZONE_INTERNET, every DMZ hop in the estate would relabel and dmz->internal
    (1.25) would silently inflate to internet->internal (1.5).
    """
    assert zone_of("lb-public-01", ["dmz", "internet-facing", "prod"],
                   ["52.20.10.10/32"], "concrete") == ZONE_DMZ
    assert zone_of("lb-public-01", ["prod"], ["52.20.10.10/32"], "concrete") == ZONE_INTERNAL


@pytest.mark.parametrize("resolved,expected", [
    (["0.0.0.0/0"], ZONE_INTERNET),
    (["1.0.0.0/8"], ZONE_INTERNET),
    (["::/0"], ZONE_INTERNET),
    (["10.0.0.0/8", "0.0.0.0/1"], ZONE_INTERNET),   # any public member is enough
    (["10.0.0.0/8"], ZONE_INTERNAL),
    (["10.0.0.0/8", "172.16.0.0/12"], ZONE_INTERNAL),
    ([], ZONE_INTERNAL),
])
def test_named_object_classifies_by_what_it_resolves_to(resolved: list[str], expected: str) -> None:
    """An address GROUP called "ANY-EXTERNAL" is the internet if that is what the
    object catalog says it dereferences to. Classifying the label would score the
    string instead of the address space."""
    assert zone_of("ANY-EXTERNAL", [], resolved, "abstract") == expected


def test_resolved_space_does_not_override_a_concrete_asset() -> None:
    """Same resolved CIDR, different node kind: only the address-space node is
    the internet. Guards the carve-out against being widened by accident."""
    assert zone_of("edge-node", [], ["1.0.0.0/8"], "abstract") == ZONE_INTERNET
    assert zone_of("edge-node", [], ["1.0.0.0/8"], "concrete") == ZONE_INTERNAL


def test_unknown_kind_still_classifies_from_the_key() -> None:
    """The 2-argument call sites (over_permissive, shadowing, transport_exposure,
    simulate, the DB-backed graph view in main.py) pass no kind. They must still
    get the address-space answer — that is where the guardrail reads it from."""
    assert zone_of("0.0.0.0/1", []) == ZONE_INTERNET
    assert zone_of("0.0.0.0/1", [], None, None) == ZONE_INTERNET


# ---------------------------------------------------------------------------
# 2. the published boundary table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("src", ALL_ZONES)
@pytest.mark.parametrize("dst", ALL_ZONES)
def test_boundary_multiplier_is_the_published_lookup(src: str, dst: str) -> None:
    """Every ordered pair resolves through config.BOUNDARY_MULTIPLIERS, with
    B_INTRA for unlisted pairs. `boundary_multiplier` must never compute a value:
    the severity vector is published in the UI and every factor in it has to be
    traceable to a named constant."""
    assert boundary_multiplier(src, dst) == BOUNDARY_MULTIPLIERS.get((src, dst), B_INTRA)


@pytest.mark.parametrize("src,dst,expected", [
    (ZONE_INTERNET, ZONE_INTERNAL, 1.5),    # the crossing the guardrail exists for
    (ZONE_DMZ, ZONE_INTERNAL, 1.25),
    (ZONE_DEV, ZONE_INTERNAL, 1.25),        # dev -> prod
    # Deliberately absent from the table: a DMZ asset is MEANT to be reachable
    # from outside, so this direction is expected, not a boundary crossing.
    (ZONE_INTERNET, ZONE_DMZ, 1.0),
    (ZONE_INTERNAL, ZONE_INTERNAL, 1.0),
    (ZONE_INTERNAL, ZONE_INTERNET, 1.0),    # egress is not scored as ingress
    (ZONE_DMZ, ZONE_DMZ, 1.0),
])
def test_published_boundary_values(src: str, dst: str, expected: float) -> None:
    """A second, independent statement of the documented crossings, so the table
    cannot be recalibrated without a test saying so out loud."""
    assert boundary_multiplier(src, dst) == expected


@pytest.mark.parametrize("src", ALL_ZONES)
@pytest.mark.parametrize("dst", ALL_ZONES)
def test_crosses_boundary_agrees_with_the_multiplier(src: str, dst: str) -> None:
    assert crosses_boundary(src, dst) is (boundary_multiplier(src, dst) > B_INTRA)


def test_boundary_label_names_the_crossing() -> None:
    assert boundary_label(ZONE_INTERNET, ZONE_INTERNAL) == "internet->internal"
    assert boundary_label(ZONE_DMZ, ZONE_DEV) == "dmz->dev"


@pytest.mark.parametrize("source", ["0.0.0.0/0", "0.0.0.0/1", "1.0.0.0/8", "any", "::/0"])
def test_every_public_source_crosses_the_same_boundary_into_internal(source: str) -> None:
    """The exit criterion's zone half: 0.0.0.0/1 and 1.0.0.0/8 get the SAME
    boundary multiplier as 0.0.0.0/0 for the same destination, so the only thing
    that can still separate their severities is exposure breadth (E)."""
    b = boundary_multiplier(zone_of(source, []), zone_of("db-prod-01", ["pci"]))
    assert b == BOUNDARY_MULTIPLIERS[(ZONE_INTERNET, ZONE_INTERNAL)] == 1.5


# ---------------------------------------------------------------------------
# 3. graph construction: one address space, one node shape
# ---------------------------------------------------------------------------

def _derived(node: dict) -> dict:
    """The attributes build_graph DERIVES (as opposed to copies verbatim)."""
    return {"kind": node["kind"], "zone": node["zone"], "ip_set": node["ip_set"]}


@pytest.mark.parametrize("cidr,expected_zone", [
    ("10.40.0.0/16", ZONE_INTERNAL),
    ("0.0.0.0/0", ZONE_INTERNET),
    ("1.0.0.0/8", ZONE_INTERNET),
])
def test_named_network_object_and_its_raw_cidr_are_the_same_node(
        cidr: str, expected_zone: str) -> None:
    """The audit's `algosec.py:31` finding, pinned at the graph layer.

    `_valid_traversal` reads ``kind``, so if the named object came through
    concrete while the raw CIDR came through abstract, whether a path exists
    would depend on whether the export happened to name the network.
    """
    named = Asset(asset_key="internal-app", kind="abstract", ip_set=[cidr],
                  tags=["prod"], source_tools=["algosec"])
    raw = Asset(asset_key=cidr, kind="abstract", ip_set=[cidr],
                tags=["prod"], source_tools=["algosec"])
    g = build_graph([], [named, raw], {})

    assert _derived(g.nodes["internal-app"]) == _derived(g.nodes[cidr])
    assert g.nodes["internal-app"]["kind"] == "abstract"
    assert g.nodes["internal-app"]["zone"] == expected_zone


def test_build_graph_copies_the_abstract_flag_without_re_deriving_it() -> None:
    """Whatever the identity layer decided is what the graph carries — the
    normalizers own abstractness, this module owns not losing it."""
    assets = [
        Asset(asset_key="app-segment", kind="abstract", ip_set=["10.30.0.0/16"]),
        Asset(asset_key="app-server-07", kind="concrete", ip_set=["10.30.7.7/32"]),
    ]
    g = build_graph([], assets, {})
    assert g.nodes["app-segment"]["kind"] == "abstract"
    assert g.nodes["app-server-07"]["kind"] == "concrete"


def test_alias_map_collapses_names_onto_one_node() -> None:
    """Wiz's "appsrv-07" and AlgoSec's "app-server-07" are ONE node, and the
    edge is attached to the canonical key, not the alias."""
    assets = [Asset(asset_key="app-server-07"), Asset(asset_key="10.0.0.0/8", kind="abstract",
                                                      ip_set=["10.0.0.0/8"])]
    g = build_graph([rec("R1", "10.0.0.0/8", "appsrv-07")], assets,
                    {"appsrv-07": "app-server-07"})
    assert "appsrv-07" not in g
    assert g.has_edge("10.0.0.0/8", "app-server-07")


# --- the ensure() fallback -------------------------------------------------

def test_ensure_gives_an_unknown_cidr_the_same_shape_as_an_asset_backed_one() -> None:
    """A record endpoint the identity layer never saw still has to classify by
    address space. Before, ``ensure`` built the node with no ip_set and called
    zone_of on the bare key, so an unknown ``0.0.0.0/1`` was internal."""
    g = build_graph([rec("R1", "0.0.0.0/1", "db-prod-01")], [Asset(asset_key="db-prod-01")], {})
    node = g.nodes["0.0.0.0/1"]
    assert node["kind"] == "abstract"
    assert node["zone"] == ZONE_INTERNET
    assert node["ip_set"] == ["0.0.0.0/1"]

    backed = build_graph([], [Asset(asset_key="0.0.0.0/1", kind="abstract",
                                    ip_set=["0.0.0.0/1"])], {})
    assert _derived(node) == _derived(backed.nodes["0.0.0.0/1"])


def test_ensure_canonicalizes_host_bits() -> None:
    """``10.0.0.1/24`` and ``10.0.0.0/24`` name one block, so the node's resolved
    space is the canonical string even though the key keeps the export's spelling."""
    g = build_graph([rec("R1", "10.0.0.1/24", "db")], [], {})
    assert g.nodes["10.0.0.1/24"]["ip_set"] == ["10.0.0.0/24"]


def test_ensure_classifies_a_named_endpoint_from_the_records_resolved_space() -> None:
    """A NAME the identity layer never saw is still address space if the record
    says so, and it has to land in the zone the literal string lands in.

    This is the change-gate path: a proposal names ``ANY-EXTERNAL``, no asset
    exists for it, and the only thing that knows what it dereferences to is the
    record's own `source_cidrs`. Without this the zone layer was the one place in
    the engine that never got to see the resolved space, so the boundary
    multiplier (1.0) contradicted the exposure score (E = 1.0) on one rule.
    """
    g = build_graph([rec("R1", "ANY-EXTERNAL", "db-prod-01", source_cidrs=["0.0.0.0/0"])],
                    [Asset(asset_key="db-prod-01")], {})
    node = g.nodes["ANY-EXTERNAL"]
    assert node["ip_set"] == ["0.0.0.0/0"]
    assert node["zone"] == ZONE_INTERNET
    # ...including a multi-block group, which is the encoding that has no single
    # `cidr` to fall back on anywhere in the pipeline.
    g2 = build_graph([rec("R2", "EXTERNAL-NETS", "db-prod-01",
                          source_cidrs=["10.0.0.0/8", "0.0.0.0/0"])],
                     [Asset(asset_key="db-prod-01")], {})
    assert g2.nodes["EXTERNAL-NETS"]["ip_set"] == ["0.0.0.0/0", "10.0.0.0/8"]
    assert g2.nodes["EXTERNAL-NETS"]["zone"] == ZONE_INTERNET


def test_ensure_leaves_an_unresolvable_label_abstract_with_no_address_space() -> None:
    """Fail closed: we have no evidence this token is a host, so it may be a path
    endpoint but never an intermediate hop. Inventing a pivot node from a token
    nothing in the input describes would be fabricated reachability."""
    g = build_graph([rec("R1", "UNKNOWN-GROUP", "db-prod-01")],
                    [Asset(asset_key="db-prod-01")], {})
    assert g.nodes["UNKNOWN-GROUP"] == {
        "kind": "abstract", "tags": [], "ip_set": [], "display": "UNKNOWN-GROUP",
        "zone": ZONE_INTERNAL, "tools": [],
    }


# --- the graph and the traversal filter agree ------------------------------

@pytest.mark.parametrize("pivot_kind,expected", [("abstract", False), ("concrete", True)])
def test_node_kind_decides_whether_a_path_can_pivot(pivot_kind: str, expected: bool) -> None:
    """The reason ``kind`` has to be propagated faithfully: it is what
    `_valid_traversal` reads. Reaching hosts inside a /16 does not let you
    originate as that /16, so an abstract middle hop kills the path."""
    assets = [
        Asset(asset_key="a"), Asset(asset_key="b"),
        Asset(asset_key="app-segment", kind=pivot_kind, ip_set=["10.30.0.0/16"]),
    ]
    g = build_graph([rec("R1", "a", "app-segment"), rec("R2", "app-segment", "b")], assets, {})
    assert reachable(g, "a", "b")["reachable"] is expected


# --- persistence vocabulary ------------------------------------------------

@pytest.mark.parametrize("node_key,asset_kind,expected", [
    ("0.0.0.0/0", "abstract", "internet"),
    ("0.0.0.0/1", "abstract", "internet"),      # was "subnet": half the internet
    ("1.0.0.0/8", "abstract", "internet"),
    ("::/0", "abstract", "internet"),
    ("any", "abstract", "internet"),
    ("10.0.0.0/8", "abstract", "subnet"),
    ("app-segment", "abstract", "subnet"),
    ("db-prod-01", "concrete", "asset"),
    ("lb-public-01", "concrete", "asset"),      # public IP, still an asset
])
def test_node_db_kind_matches_the_zone_classification(
        node_key: str, asset_kind: str, expected: str) -> None:
    """graph_nodes.kind must not contradict the zone the engine scored with."""
    assert node_db_kind(node_key, asset_kind) == expected


def test_sensitive_assets_is_sorted_and_tag_driven() -> None:
    assets = [
        Asset(asset_key="rds-prod-customers", tags=["pci", "prod"]),
        Asset(asset_key="db-prod-01", tags=["customer-data"]),
        Asset(asset_key="app-server-07", tags=["prod"]),
    ]
    g = build_graph([], assets, {})
    assert sensitive_assets(g, {"pci", "customer-data"}) == ["db-prod-01", "rds-prod-customers"]


# --- determinism + the disclosed Phase 3 gap -------------------------------

def test_node_attributes_do_not_depend_on_asset_order() -> None:
    """Determinism is a selling point: the same inputs in a different order must
    produce the same node facts."""
    assets = [
        Asset(asset_key="0.0.0.0/0", kind="abstract", ip_set=["0.0.0.0/0"]),
        Asset(asset_key="lb-public-01", tags=["dmz"], ip_set=["52.20.10.10/32"]),
        Asset(asset_key="db-prod-01", tags=["pci"], ip_set=["10.50.0.10/32"]),
    ]
    forward = build_graph([], assets, {})
    reverse = build_graph([], list(reversed(assets)), {})
    assert sorted(forward.nodes) == sorted(reverse.nodes)
    assert all(forward.nodes[n] == reverse.nodes[n] for n in forward.nodes)


def test_edge_aggregates_do_not_depend_on_record_order() -> None:
    """Parallel grants keep their input order (that is provenance), but the
    aggregated tools/services/apps are sorted sets and must not."""
    records = [
        rec("R1", "10.0.0.0/8", "app-server-08", service="tcp/443"),
        rec("R2", "10.0.0.0/8", "app-server-08", service="tcp/22", port=22, tool="guardicore"),
    ]
    assets = [Asset(asset_key="app-server-08"),
              Asset(asset_key="10.0.0.0/8", kind="abstract", ip_set=["10.0.0.0/8"])]
    forward = build_graph(records, assets, {})["10.0.0.0/8"]["app-server-08"]
    reverse = build_graph(list(reversed(records)), assets, {})["10.0.0.0/8"]["app-server-08"]
    for key in ("tools", "services", "apps"):
        assert forward[key] == reverse[key]
    assert forward["tools"] == ["algosec", "guardicore"]
    assert forward["services"] == ["tcp/22", "tcp/443"]


def test_deny_records_are_still_dropped() -> None:
    """DISCLOSED GAP, deliberately not fixed here (docs/ENGINE.md §10.1, Phase 3):
    the modelled effective policy is the union of allow edges, so a deny never
    subtracts an allow. Pinned as a test so the day it changes, it changes on
    purpose — the shadowing analyzer is what currently surfaces dead denies."""
    records = [rec("R1", "10.0.0.0/8", "app-server-07"),
               rec("R2", "10.20.5.7/32", "app-server-07", action="deny")]
    assets = [Asset(asset_key="app-server-07")]
    g = build_graph(records, assets, {})
    assert g.has_edge("10.0.0.0/8", "app-server-07")
    assert "10.20.5.7/32" not in g
