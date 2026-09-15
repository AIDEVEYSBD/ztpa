"""The console and the engine must agree about which side of a boundary a node is on.

`/api/graph` does not read a persisted zone — it re-derives one, because
`graph_nodes` has no zone column. That is fine as long as it re-derives it the
same way the engine did. It did not.

`zones.zone_of` grew two arguments (`cidrs`, `kind`) so that a NAMED object would
classify like the address space it dereferences to: an address group called
`ANY-EXTERNAL` whose catalog value is `0.0.0.0/0` is the internet, exactly as the
literal string is. `graph.build.build_graph` passes all four. The API route kept
the two-argument form.

The measured consequence: `ANY-EXTERNAL` came back `internal` from the API while
the engine had filed it `internet`. The engine had already scored the finding
with the internet→internal boundary multiplier of 1.5; the zone the screen
printed implied 1.0. A user looking at the map saw an internal-to-internal grant
attached to a finding scored as an internet ingress, with nothing on screen to
say which of the two was right.

This is the whole class of defect the four remediation phases were about: not a
missing answer, a confident wrong one, produced by two layers deriving the same
fact two different ways.
"""

from __future__ import annotations

import pytest

from app.main import _graph_payload
from src.graph.build import node_db_kind
from src.graph.zones import zone_of

# (node_id, tags, ip_set, asset_kind) — the four spellings of "the internet" the
# engine already treats identically, plus the concrete host that must NOT be
# swept up with them.
CASES = [
    ("ANY-EXTERNAL", [], ["0.0.0.0/0"], "abstract", "internet"),
    ("INTERNET", [], ["0.0.0.0/0"], "abstract", "internet"),
    ("0.0.0.0/0", [], ["0.0.0.0/0"], "abstract", "internet"),
    ("0.0.0.0/1", [], ["0.0.0.0/1"], "abstract", "internet"),
    ("DC-SUBNETS", [], ["10.0.0.0/8"], "abstract", "internal"),
    # A host that HOLDS a public address is a DMZ asset, not the internet. If a
    # fix to the above swept this up too, every DMZ hop in the estate would be
    # relabelled and dmz->internal (1.25) would silently inflate into
    # internet->internal (1.5).
    ("lb-public-01", ["dmz"], ["52.20.10.10/32"], "concrete", "dmz"),
]


def _payload_zone(node_id: str, tags: list[str], ip_set: list[str], asset_kind: str) -> str:
    """The zone `/api/graph` puts on the wire for this node."""
    row = {"node_id": node_id, "kind": node_db_kind(node_id, asset_kind),
           "label": node_id, "tags": tags, "ip_set": ip_set}
    return _graph_payload([row], [], [])["nodes"][0]["zone"]


@pytest.mark.parametrize("node_id,tags,ip_set,asset_kind,expected", CASES)
def test_the_api_reports_the_zone_the_engine_scored(node_id, tags, ip_set, asset_kind, expected):
    """One fact, one answer, whichever layer you ask."""
    engine = zone_of(node_id, tags, ip_set, asset_kind)

    assert engine == expected
    assert _payload_zone(node_id, tags, ip_set, asset_kind) == engine


def test_a_named_object_resolving_to_the_internet_is_not_reported_as_internal():
    """THE REGRESSION, stated on its own because it is the one that shipped.

    Named objects — not raw CIDRs — are how real AlgoSec, Palo Alto and Check
    Point policies overwhelmingly express `any`. So this was not an edge case in
    the estate; it was the common case.
    """
    assert _payload_zone("ANY-EXTERNAL", [], ["0.0.0.0/0"], "abstract") == "internet"


def test_the_two_argument_form_is_what_was_wrong():
    """Pin the actual defect, so a future refactor that drops the extra
    arguments again fails here rather than in a client demo."""
    assert zone_of("ANY-EXTERNAL", []) == "internal"          # what the route used to do
    assert zone_of("ANY-EXTERNAL", [], ["0.0.0.0/0"], "abstract") == "internet"


def test_a_node_with_no_address_space_still_classifies():
    """The route must not start requiring data the payload may not carry: a node
    with an empty `ip_set` has to degrade to the tag/key answer rather than
    raising or returning None."""
    assert _payload_zone("app-tier", ["prod"], [], "concrete") == "internal"
    assert _payload_zone("unknown-thing", [], [], "abstract") == "internal"
