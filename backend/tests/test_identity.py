"""The identity merge's safety rules — the exact problem the product is sold on.

README.md:12 sells "IP is an attribute, not a key", and the merge used to treat
the IP AS the key: `ip_to_names[e.ip]` unioned every name sharing a raw IP
string, with `if e.ip:` as the only filter. Union-find is transitive, so one
duplicated RFC 1918 address fused two unrelated hosts and one `0.0.0.0`
placeholder fused the estate. The consequence is not a mislabelled asset:
`build_graph` collapses both nodes' edges onto one, so the tool reports
reachability that does not exist, and `dest_score` takes the MAX over the
unioned tags, so a dev box inherits `pci`.

Every test here pins one guard against that, and all of them assert the same
direction of failure: **when in doubt, do not merge**. A withheld merge must
show up as a `manual_review` row with confidence 0.0 and a reason, never as
silence — an operator has to be able to see that the engine declined.

The last test pins the property the whole engine's reproducibility rests on:
the answer cannot depend on the order the entities arrived in.
"""

from __future__ import annotations

import ipaddress

import pytest

from src.identity import (
    MAX_IP_FANOUT, SENTINEL_BLOCKS, SUPPRESSION_REASONS,
    canonical_ip, context_of, is_sentinel_ip, resolve_identities,
)
from src.normalizers.common import ObservedEntity


def _ent(name: str, tool: str = "wiz", *, ip: str | None = None, cidr: str | None = None,
         context: str | None = None, tags: tuple[str, ...] = (),
         abstract: bool = False, **identifiers) -> ObservedEntity:
    """Build an ObservedEntity, setting `context` by attribute.

    `setattr` rather than a constructor kwarg on purpose: identity.py reads the
    field with `getattr(..., None)` so the merge fails SAFE against a normalizer
    that has not been taught to populate it yet, and these tests must exercise
    that same contract whether or not common.py declares the field.
    """
    e = ObservedEntity(name=name, kind="cidr" if cidr else "identity", tool=tool, ip=ip,
                       cidr=cidr, tags=list(tags), identifiers=dict(identifiers),
                       abstract=abstract)
    if context is not None:
        e.context = context
    return e


def _withheld(result, reason: str | None = None) -> list[dict]:
    """Every withheld-merge audit row (optionally of one reason), in output order."""
    return [c.evidence for c in result.correlations
            if c.match_key == "manual_review" and c.evidence.get("status") == "withheld"
            and (reason is None or c.evidence.get("reason") == reason)]


def _merged(result, a: str, b: str) -> bool:
    return result.alias_map[a] == result.alias_map[b]


# ---------------------------------------------------------------------------
# 1. Scope. The union key is (context, ip), and an unscoped collision is a
#    review candidate, not a merge. This is a Phase 1 exit criterion.
# ---------------------------------------------------------------------------

def test_same_ip_different_context_does_not_union_and_is_offered_for_review():
    """The audit's headline scenario: 10.0.1.5 in two accounts is two hosts.

    Nothing about these two entities differs except the account that assigns the
    address -- no env tags, no fan-out -- so this isolates the scope guard.
    """
    r = resolve_identities([
        _ent("prod-vpc-web-01", "wiz", ip="10.0.1.5", context="aws-prod"),
        _ent("dev-vpc-web-01", "wiz", ip="10.0.1.5", context="aws-dev"),
    ])

    assert not _merged(r, "prod-vpc-web-01", "dev-vpc-web-01")
    assert sorted(a.asset_key for a in r.assets) == ["dev-vpc-web-01", "prod-vpc-web-01"]
    # ...and the engine says so out loud rather than silently doing nothing.
    assert _withheld(r, "context_mismatch") == [{
        "status": "withheld", "reason": "context_mismatch", "ip": "10.0.1.5",
        "context": None, "names": ["dev-vpc-web-01", "prod-vpc-web-01"],
    }]
    assert r.suppressed_merges == 1
    assert r.suppressed_by_reason == {"context_mismatch": 1}
    # confidence 0.0 == "the engine does not know", which is what puts the row in
    # a review queue instead of an audit trail of things it did.
    assert [c.confidence for c in r.correlations if c.match_key == "manual_review"] == [0.0]


def test_same_ip_same_context_does_union():
    """The guard must not disable the feature: one scope, one address, one host."""
    r = resolve_identities([
        _ent("app-server-07", "algosec", ip="10.30.7.7", context="vpc-a"),
        _ent("appsrv-07", "wiz", ip="10.30.7.7", context="vpc-a"),
    ])

    assert _merged(r, "app-server-07", "appsrv-07")
    assert len(r.assets) == 1
    assert r.suppressed_merges == 0
    ip_corr = [c for c in r.correlations if c.match_key == "context_ip"]
    # `context_ip` finally names something real: the scope is in the evidence, so
    # the audit row can be checked back against the export it came from.
    assert [c.evidence for c in ip_corr] == [
        {"ip": "10.30.7.7", "context": "vpc-a", "names": ["app-server-07", "appsrv-07"]},
    ]
    assert [c.confidence for c in ip_corr] == [0.95]


@pytest.mark.parametrize("ctx_a,ctx_b", [
    (None, "vpc-a"),      # the export that knows its scope meets one that does not
    ("vpc-a", None),      # ...and the mirror image, so the rule is not order-dependent
    (None, None),         # two unknowns are NOT evidence of sameness
])
def test_unknown_context_on_either_side_does_not_union(ctx_a, ctx_b):
    r = resolve_identities([
        _ent("host-a", "algosec", ip="10.0.1.5", context=ctx_a),
        _ent("host-b", "wiz", ip="10.0.1.5", context=ctx_b),
    ])

    assert not _merged(r, "host-a", "host-b")
    assert _withheld(r, "unscoped_ip") == [{
        "status": "withheld", "reason": "unscoped_ip", "ip": "10.0.1.5",
        "context": None, "names": ["host-a", "host-b"],
    }]
    assert r.suppressed_merges == 1


def test_context_comes_from_the_field_or_from_a_namespace_identifier():
    """`context` is the declared field; the identifier fallback is a namespace
    key only. `env`/`cloud` are labels every account shares -- keying on them
    would reintroduce the collision -- so they must NOT read as a scope."""
    assert context_of(_ent("a", context="vpc-1")) == "vpc-1"
    assert context_of(_ent("a", vpc="vpc-1")) == "vpc-1"
    assert context_of(_ent("a", account="1234")) == "1234"
    assert context_of(_ent("a", env="prod", cloud="aws")) is None
    assert context_of(_ent("a", context="   ")) is None
    assert context_of(_ent("a")) is None


def test_env_and_cloud_labels_alone_are_not_a_scope():
    """The end-to-end consequence of the rule above, on the audit's own example."""
    r = resolve_identities([
        _ent("prod-vpc-web-01", "wiz", ip="10.0.1.5", tags=("pci",), cloud="aws", env="prod"),
        _ent("other-web-01", "wiz", ip="10.0.1.5", cloud="aws", env="prod"),
    ])
    assert not _merged(r, "prod-vpc-web-01", "other-web-01")
    # ...and specifically, the pci tag does not leak onto the other host.
    assert [a.tags for a in r.assets if a.asset_key == "other-web-01"] == [[]]


# ---------------------------------------------------------------------------
# 2. Sentinels. A placeholder address is a statement that the IP is UNKNOWN.
# ---------------------------------------------------------------------------

# (spelling, the ONE canonical address it denotes). The expected canonical form
# is written out rather than computed with `canonical_ip(ip)`: an expectation
# taken from the implementation agrees with the implementation by construction,
# which is exactly how the mapped-v6 hole below survived a green test run.
_SENTINEL_SPELLINGS = [
    ("0.0.0.0", "0.0.0.0"),            # the unspecified address: an empty IP column, filled in
    ("127.0.0.1", "127.0.0.1"),        # loopback: every host is this
    ("127.5.5.5", "127.5.5.5"),        # ...anywhere in 127/8, not just the .1
    ("169.254.10.1", "169.254.10.1"),  # RFC 3927 link-local: a DHCP failure
    ("::", "::"),                      # v6 unspecified
    ("::1", "::1"),                    # v6 loopback
    ("fe80::1", "fe80::1"),            # v6 link-local
    # The SAME addresses in the IPv4-mapped v6 spelling (RFC 4291 s2.5.5.2).
    # These are not exotic: `normalizers.profile.object_cidrs` accepts them as
    # single host addresses, so they reach `ObservedEntity.ip` from a real
    # export -- and they used to UNION, because the membership test required
    # `addr.version == net.version` and a mapped loopback is version 6, so the
    # v4 sentinel blocks were never consulted for it.
    ("::ffff:0.0.0.0", "0.0.0.0"),
    ("::ffff:127.0.0.1", "127.0.0.1"),
    ("::ffff:7f00:1", "127.0.0.1"),                 # the same value in hextets
    ("0:0:0:0:0:ffff:127.0.0.1", "127.0.0.1"),      # ...and fully expanded
    ("::ffff:169.254.10.1", "169.254.10.1"),
    ("::ffff:127.0.0.1/128", "127.0.0.1"),          # written as its own host network
]


@pytest.mark.parametrize("ip,canon", _SENTINEL_SPELLINGS)
def test_sentinel_addresses_never_union_even_inside_one_scope(ip, canon):
    """Matching context is not enough: these addresses identify nothing at all."""
    r = resolve_identities([
        _ent("host-a", "algosec", ip=ip, context="vpc-a"),
        _ent("host-b", "wiz", ip=ip, context="vpc-a"),
    ])

    assert canonical_ip(ip) == canon
    assert is_sentinel_ip(ip)
    assert not _merged(r, "host-a", "host-b")
    assert _withheld(r, "sentinel_ip") == [{
        "status": "withheld", "reason": "sentinel_ip", "ip": canon,
        "context": None, "names": ["host-a", "host-b"],
    }]


def test_a_sentinel_placeholder_does_not_collapse_the_estate():
    """The degenerate input from the audit: six Wiz hosts plus the PCI database
    all carrying `0.0.0.0`. The old rule returned ONE asset -- key `db-prod-01`,
    tagged pci -- and alias_map re-pointed all seven names at it, so every rule
    in the estate terminated on the regulated database."""
    entities = [_ent(f"wiz-host-{i}", "wiz", ip="0.0.0.0", context="vpc-a") for i in range(6)]
    entities.append(_ent("db-prod-01", "algosec", ip="0.0.0.0", tags=("pci",), context="vpc-a"))

    r = resolve_identities(entities)

    assert len(r.assets) == 7
    assert all(r.alias_map[e.name] == e.name for e in entities)
    assert [a.tags for a in r.assets if a.asset_key == "wiz-host-0"] == [[]]
    assert r.suppressed_by_reason == {"sentinel_ip": 1}


def test_a_mapped_sentinel_does_not_collapse_the_estate_either():
    """The collapse scenario above, written the other way round.

    ``::ffff:127.0.0.1`` IS 127.0.0.1 (RFC 4291 s2.5.5.2), and
    `normalizers.profile.object_cidrs` accepts that spelling as a host address,
    so an agent reporting its loopback over a v6 socket used to walk straight
    past the sentinel guard: the family test in `is_sentinel_ip` meant the v4
    blocks were never consulted for a version-6 address, so all three names
    fused into ONE asset keyed `db-prod-01` -- alias_map re-pointing the two
    unknown hosts at the PCI database -- with a `context_ip` correlation at
    confidence 0.95 and `suppressed_merges == 0`, i.e. no trace that anything
    had been decided. The two spellings must now be indistinguishable."""
    def estate(ip: str) -> list[ObservedEntity]:
        return [_ent(f"wiz-host-{i}", "wiz", ip=ip, context="vpc-a") for i in range(2)] + [
            _ent("db-prod-01", "algosec", ip=ip, tags=("pci", "prod"), context="vpc-a"),
        ]

    r = resolve_identities(estate("::ffff:127.0.0.1"))

    assert sorted(a.asset_key for a in r.assets) == ["db-prod-01", "wiz-host-0", "wiz-host-1"]
    assert r.alias_map == {"db-prod-01": "db-prod-01",
                           "wiz-host-0": "wiz-host-0", "wiz-host-1": "wiz-host-1"}
    # ...and specifically, the regulated tags did not leak onto the two unknowns.
    assert [a.tags for a in r.assets if a.asset_key == "wiz-host-0"] == [[]]
    assert r.suppressed_by_reason == {"sentinel_ip": 1}
    assert [c.match_key for c in r.correlations] == ["manual_review"]
    assert _withheld(r, "sentinel_ip") == [{
        "status": "withheld", "reason": "sentinel_ip", "ip": "127.0.0.1", "context": None,
        "names": ["db-prod-01", "wiz-host-0", "wiz-host-1"],
    }]
    # The spelling is not allowed to change ANY of the above -- including the
    # canonical address in the review row and the /32 in the asset's ip_set.
    assert _dump(r) == _dump(resolve_identities(estate("127.0.0.1")))
    assert [a.ip_set for a in r.assets if a.asset_key == "db-prod-01"] == [["127.0.0.1/32"]]


def test_an_ipv4_mapped_address_is_the_v4_address_it_denotes():
    """The fold that closes the hole above, stated on its own.

    A mapped address is v4 wearing a v6 hat, so it must classify, canonicalise
    and MERGE as its embedded v4 form -- the same rule `netaddr._unwrap_mapped`
    applies to networks. A mapped address whose embedded v4 is ordinary is
    ordinary: the fix must not turn the whole ``::ffff:0:0/96`` block into a
    sentinel, or every cloud host reported over a v6 socket would stop merging.
    """
    assert canonical_ip("::ffff:10.0.0.5") == "10.0.0.5"
    assert canonical_ip("::ffff:10.0.0.5/128") == "10.0.0.5"
    assert not is_sentinel_ip("::ffff:10.0.0.5")
    assert not is_sentinel_ip("::ffff:52.20.10.10")
    # The deprecated IPv4-COMPATIBLE form (`::a.b.c.d`) is NOT folded: `::1`
    # sits inside that block and is the v6 loopback, not 0.0.0.1.
    assert canonical_ip("::1") == "::1" and is_sentinel_ip("::1")

    # Two tools spelling one address in two families are one host in one scope...
    scoped = resolve_identities([
        _ent("host-a", "algosec", ip="10.0.0.5", context="vpc-a"),
        _ent("host-b", "wiz", ip="::ffff:10.0.0.5", context="vpc-a"),
    ])
    assert _merged(scoped, "host-a", "host-b")
    assert [a.ip_set for a in scoped.assets] == [["10.0.0.5/32"]]

    # ...and the same pair with no declared scope is still a review candidate,
    # reported against the one canonical address rather than two spellings.
    unscoped = resolve_identities([
        _ent("host-a", "algosec", ip="10.0.0.5"),
        _ent("host-b", "wiz", ip="::ffff:10.0.0.5"),
    ])
    assert not _merged(unscoped, "host-a", "host-b")
    assert _withheld(unscoped, "unscoped_ip") == [{
        "status": "withheld", "reason": "unscoped_ip", "ip": "10.0.0.5",
        "context": None, "names": ["host-a", "host-b"],
    }]


def test_every_sentinel_block_holds_in_both_spellings():
    """The property behind the case list, over the published blocks themselves.

    A v4 sentinel block must answer the same in either family's spelling of one
    of its addresses; a v6-only block has no mapped spelling and is asserted
    directly. This is what makes adding a block to `SENTINEL_BLOCKS` safe: the
    new block cannot be v4-only-in-practice without this test failing."""
    samples = {"0.0.0.0/32": "0.0.0.0", "127.0.0.0/8": "127.9.9.9",
               "169.254.0.0/16": "169.254.99.9", "::/128": "::", "::1/128": "::1",
               "fe80::/10": "fe80::abcd"}
    assert sorted(samples) == sorted(SENTINEL_BLOCKS)
    for block, sample in sorted(samples.items()):
        assert is_sentinel_ip(sample), block
        if ipaddress.ip_network(block).version == 4:
            assert is_sentinel_ip(f"::ffff:{sample}"), block
            assert canonical_ip(f"::ffff:{sample}") == sample, block


def test_sentinel_blocks_are_published_and_parseable():
    """The ignore set is policy, not an implementation detail: it is named, it is
    importable, and a reviewer can read it without reading the algorithm."""
    assert SENTINEL_BLOCKS == (
        "0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "::/128", "::1/128", "fe80::/10",
    )
    # An ordinary address is not swept up by the ignore set...
    assert not is_sentinel_ip("10.0.1.5")
    assert not is_sentinel_ip("52.20.10.10")
    # ...and a value that is not an address at all can never be an identity either.
    assert is_sentinel_ip("not-an-ip")
    assert is_sentinel_ip("10.0.0.0/8")
    assert is_sentinel_ip(None)


# ---------------------------------------------------------------------------
# 3. Fan-out. An address carrying many names is shared infrastructure.
# ---------------------------------------------------------------------------

def test_six_names_on_one_address_do_not_collapse_the_estate():
    """A cluster VIP / NAT pool address, correctly scoped and free of any tag
    conflict -- so only the cardinality guard can stop it."""
    entities = [_ent(f"host-{i}", "wiz", ip="10.9.9.9", context="vpc-a") for i in range(6)]

    r = resolve_identities(entities)

    assert len(r.assets) == 6
    assert all(r.alias_map[e.name] == e.name for e in entities)
    assert _withheld(r, "ip_fanout") == [{
        "status": "withheld", "reason": "ip_fanout", "ip": "10.9.9.9", "context": "vpc-a",
        "names": sorted(e.name for e in entities),
    }]
    assert r.suppressed_merges == 1


@pytest.mark.parametrize("count,expect_union", [
    (MAX_IP_FANOUT, True),        # the widest fan-out one genuine host can produce
    (MAX_IP_FANOUT + 1, False),   # one more name than any single host can explain
])
def test_fanout_cap_boundary(count, expect_union):
    entities = [_ent(f"host-{i}", "wiz", ip="10.9.9.9", context="vpc-a") for i in range(count)]

    r = resolve_identities(entities)

    assert (len(r.assets) == 1) is expect_union
    assert (r.suppressed_merges == 0) is expect_union


def test_one_name_seen_by_many_tools_is_not_fanout():
    """Fan-out counts NAMES, not entities: the same host observed by every tool
    is one node, and must not be withheld for being well covered."""
    entities = [_ent("db-prod-01", tool, ip="10.50.0.10", context="vpc-a")
                for tool in ("algosec", "guardicore", "wiz", "sd_wan", "sd_lan")]

    r = resolve_identities(entities)

    assert len(r.assets) == 1
    assert r.suppressed_merges == 0


def test_the_cap_cannot_be_evaded_by_spelling_the_address_two_ways():
    """Fan-out counts names on an ADDRESS, so the address has to be one thing.

    Four names on 10.0.0.5 inside one scope is over the cap and must be withheld
    whole. Written half as `10.0.0.5` and half as `::ffff:10.0.0.5` the group
    used to split into two groups of two -- each under the cap -- and BOTH fused
    silently, with `suppressed_by_reason == {}`: a shared VIP became two assets
    that each claimed to be a host, and nothing said a decision had been made.
    Canonicalising the family makes the four names one group again."""
    entities = [_ent("h-1", "wiz", ip="10.0.0.5", context="vpc-a"),
                _ent("h-2", "algosec", ip="10.0.0.5", context="vpc-a"),
                _ent("h-3", "guardicore", ip="::ffff:10.0.0.5", context="vpc-a"),
                _ent("h-4", "sd_wan", ip="::ffff:10.0.0.5", context="vpc-a")]

    r = resolve_identities(entities)

    assert sorted(a.asset_key for a in r.assets) == ["h-1", "h-2", "h-3", "h-4"]
    assert r.suppressed_by_reason == {"ip_fanout": 1}
    assert _withheld(r, "ip_fanout") == [{
        "status": "withheld", "reason": "ip_fanout", "ip": "10.0.0.5",
        "context": "vpc-a", "names": ["h-1", "h-2", "h-3", "h-4"],
    }]


# ---------------------------------------------------------------------------
# 4. Environment exclusivity. prod and dev are not the same machine.
# ---------------------------------------------------------------------------

def test_prod_and_dev_never_union():
    """The audit's second scenario: `db-dev-01` (dev VRF) and `payments-db`
    (prod, pci) on 10.0.0.10. The old rule merged them, rooted the asset at
    `db-dev-01`, and handed the dev box the pci tag at confidence 0.95."""
    r = resolve_identities([
        _ent("db-dev-01", "algosec", ip="10.0.0.10", tags=("dev",), context="dc-1"),
        _ent("payments-db", "wiz", ip="10.0.0.10", tags=("pci", "prod"), context="dc-1"),
    ])

    assert not _merged(r, "db-dev-01", "payments-db")
    assert [a.tags for a in r.assets if a.asset_key == "db-dev-01"] == [["dev"]]
    assert _withheld(r, "env_conflict") == [{
        "status": "withheld", "reason": "env_conflict", "ip": "10.0.0.10",
        "context": "dc-1", "names": ["db-dev-01", "payments-db"],
    }]


def test_env_conflict_is_checked_against_the_whole_component():
    """Union-find is transitive, so the guard has to look at the COMPONENT, not
    at the two names in front of it: prod -- untagged -- dev would otherwise
    fuse a prod and a dev host through an untagged middle name."""
    r = resolve_identities([
        _ent("a-prod", "algosec", ip="10.0.0.10", tags=("prod",), context="dc-1"),
        _ent("b-untagged", "wiz", ip="10.0.0.10", context="dc-1"),
        _ent("c-dev", "guardicore", ip="10.0.0.10", tags=("dev",), context="dc-1"),
    ])

    assert not _merged(r, "a-prod", "c-dev")


def test_environment_synonyms_are_not_a_conflict():
    """"production" and "prod" are one environment. Folding them onto a class
    keeps the guard from refusing a merge over a spelling."""
    r = resolve_identities([
        _ent("host-a", "algosec", ip="10.0.0.10", tags=("production",), context="dc-1"),
        _ent("host-b", "wiz", ip="10.0.0.10", tags=("prod",), context="dc-1"),
    ])

    assert _merged(r, "host-a", "host-b")


# ---------------------------------------------------------------------------
# 5. The escape hatch and the rest of the merge.
# ---------------------------------------------------------------------------

def test_a_human_confirmed_merge_overrides_every_guard():
    """The guards exist to hand an ambiguous collision to a person. When the
    person answers, that answer is authoritative -- otherwise the review queue
    would be a queue with no exit."""
    entities = [
        _ent("app-server-07", "algosec", ip="10.30.7.7", tags=("prod",)),
        _ent("appsrv-07", "wiz", ip="10.30.7.7", context="aws-prod", tags=("dev",)),
    ]

    r = resolve_identities(entities, manual_merges=[("app-server-07", "appsrv-07")])

    assert _merged(r, "app-server-07", "appsrv-07")
    assert [c.evidence for c in r.correlations
            if c.match_key == "manual_review" and c.confidence == 1.0] == [
        {"names": ["app-server-07", "appsrv-07"], "by": "human-confirmed"}]
    # ...and the review queue empties: telling the operator a merge is "withheld
    # pending review" after they reviewed it sends them back to their own decision.
    assert _withheld(r) == []
    assert r.suppressed_merges == 0


def test_exact_name_match_across_tools_still_merges():
    """The other merge arm is untouched: one name seen by two tools is one asset,
    with no IP involved at all."""
    r = resolve_identities([
        _ent("internal-app", "algosec", cidr="10.40.0.0/16", tags=("prod",)),
        _ent("internal-app", "guardicore", tags=("internal-app",)),
    ])

    assert len(r.assets) == 1
    assert r.assets[0].tags == ["internal-app", "prod"]
    assert [c.match_key for c in r.correlations] == ["hostname"]


def test_host_cidr_uses_the_address_family_prefix_length():
    """`f"{ip}/32"` produced `2001:db8::1/32` for every IPv6 asset -- 2**96
    addresses, i.e. an asset's own address reported as a colossal network."""
    r = resolve_identities([
        _ent("v6-host", "wiz", ip="2001:db8::1", context="vpc-a"),
        _ent("v4-host", "wiz", ip="10.0.0.5", context="vpc-a"),
    ])

    by_key = {a.asset_key: a.ip_set for a in r.assets}
    assert by_key["v6-host"] == ["2001:db8::1/128"]
    assert by_key["v4-host"] == ["10.0.0.5/32"]


def test_addresses_are_canonicalised_before_they_are_compared():
    """Two spellings of one address are one merge group, not two -- otherwise the
    guard's answer would depend on how a vendor wrote the column."""
    assert canonical_ip("10.0.0.5") == canonical_ip("10.0.0.5/32") == "10.0.0.5"
    assert canonical_ip("2001:0db8::0001") == "2001:db8::1"
    assert canonical_ip("10.0.0.0/8") is None      # a network is not a host
    assert canonical_ip("") is None
    assert canonical_ip(None) is None

    r = resolve_identities([
        _ent("host-a", "algosec", ip="10.0.0.5", context="vpc-a"),
        _ent("host-b", "wiz", ip="10.0.0.5/32", context="vpc-a"),
    ])
    assert _merged(r, "host-a", "host-b")


def test_a_malformed_cidr_does_not_take_the_run_down():
    """An address-group object whose `value` is a list used to reach
    `ips.add(e.cidr)` and raise `TypeError: unhashable type: 'list'` out of the
    whole engine. Unusable address space is dropped, not crashed on."""
    ent = _ent("group-obj", "algosec")
    ent.cidr = ["10.0.0.0/8", "10.1.0.0/16"]      # what a mis-mapped export yields
    bad_ip = _ent("typo-host", "algosec", ip="10.0.0.999", context="vpc-a")

    r = resolve_identities([ent, bad_ip])

    assert {a.asset_key: a.ip_set for a in r.assets} == {"group-obj": [], "typo-host": []}


def test_a_multi_block_group_keeps_every_block_in_its_ip_set():
    """The companion to the test above, and the reason `ObservedEntity.cidrs`
    exists at all.

    Dropping an UNUSABLE address space is right; dropping a usable one is the
    defect. `cidr` can hold only one string, so a group resolving to several
    blocks left it None and the asset came out with `ip_set == []` -- and that
    empty list is exactly what `graph.build` hands `zones.zone_of`, so a group
    containing 0.0.0.0/0 was classified ZONE_INTERNAL, the boundary multiplier
    collapsed 1.5 -> 1.0, and the identical grant scored 86/critical written
    `0.0.0.0/0` and 57/medium written as the group that resolves to it.

    `ip_set` is sorted and de-duplicated, so two tools' views of one group
    cannot make the asset depend on which export was read first.
    """
    group = _ent("external-nets", "algosec", abstract=True)
    group.cidrs = ["0.0.0.0/0", "10.0.0.0/8"]
    also = _ent("external-nets", "wiz", abstract=True)
    also.cidrs = ["10.0.0.0/8", "192.168.0.0/16"]     # overlapping second view

    r = resolve_identities([group, also])

    asset = next(a for a in r.assets if a.asset_key == "external-nets")
    assert asset.ip_set == ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16"]
    assert asset.kind == "abstract"
    # Order of arrival must not change the answer -- the property the whole
    # module ends on, asserted here too because ip_set now comes from a list.
    assert resolve_identities([also, group]).assets[0].ip_set == asset.ip_set


def test_a_group_member_that_is_not_address_space_is_dropped_not_crashed_on():
    """`cidrs` goes through the same `parse_net` guard `cidr` does: a mis-mapped
    export can put anything in a list, and an unusable member must not be able to
    reach `ip_set` (where it would be scored as if it were a network) or take the
    run down."""
    ent = _ent("mixed-group", "algosec", abstract=True)
    ent.cidrs = ["10.0.0.0/8", "10.0.0.0/33", "", None, ["nested"]]

    r = resolve_identities([ent])

    assert r.assets[0].ip_set == ["10.0.0.0/8"]


def test_the_asset_reports_the_scope_its_merge_was_keyed_on():
    """`Asset.context` used to be derived AFTER the merge from env/cloud, so it
    described something other than the key the merge actually used."""
    r = resolve_identities([_ent("host-a", "wiz", ip="10.0.0.5", context="vpc-a", env="prod")])
    assert r.assets[0].context == "vpc-a"
    # ...with the old derivation kept as a fallback so an export that declares no
    # namespace still shows the operator something.
    r2 = resolve_identities([_ent("host-b", "wiz", ip="10.0.0.5", env="prod")])
    assert r2.assets[0].context == "prod"


def test_suppression_reasons_are_published_and_exhaustive():
    """Every reason the engine can emit is in the published tuple, so a UI can
    label the review queue without inventing strings."""
    entities = [
        _ent("mismatch-a", "wiz", ip="10.1.0.1", context="vpc-a"),
        _ent("mismatch-b", "wiz", ip="10.1.0.1", context="vpc-b"),
        _ent("unscoped-a", "wiz", ip="10.2.0.1"),
        _ent("unscoped-b", "wiz", ip="10.2.0.1", context="vpc-a"),
        _ent("env-a", "wiz", ip="10.3.0.1", context="vpc-a", tags=("prod",)),
        _ent("env-b", "wiz", ip="10.3.0.1", context="vpc-a", tags=("dev",)),
        _ent("sentinel-a", "wiz", ip="127.0.0.1", context="vpc-a"),
        _ent("sentinel-b", "wiz", ip="127.0.0.1", context="vpc-a"),
    ] + [_ent(f"vip-{i}", "wiz", ip="10.4.0.1", context="vpc-a") for i in range(4)]

    r = resolve_identities(entities)

    assert r.suppressed_by_reason == {
        "context_mismatch": 1, "env_conflict": 1, "ip_fanout": 1,
        "sentinel_ip": 1, "unscoped_ip": 1,
    }
    assert r.suppressed_merges == 5
    assert sorted(r.suppressed_by_reason) == sorted(SUPPRESSION_REASONS)
    assert list(r.suppressed_by_reason) == sorted(r.suppressed_by_reason)   # keys sorted


# ---------------------------------------------------------------------------
# 6. Order-independence. The engine's reproducibility claim rests on this.
# ---------------------------------------------------------------------------

def _mixed_estate() -> list[ObservedEntity]:
    """One entity list exercising every arm: a name match, a scoped IP merge, a
    cross-scope collision, an env conflict, a sentinel and a fan-out group.

    Two of the addresses are written in the IPv4-mapped v6 spelling of the value
    their counterpart uses, so the canonicalisation that folds the two families
    together is inside the order-independence property rather than beside it: if
    the fold ever became order- or family-sensitive, the scoped merge and the
    sentinel row below would move and this estate would stop matching itself.
    """
    return [
        _ent("internal-app", "algosec", cidr="10.40.0.0/16", tags=("prod",)),
        _ent("internal-app", "guardicore", tags=("internal-app",)),
        _ent("app-server-07", "algosec", ip="10.30.7.7", context="vpc-a", tags=("prod",)),
        _ent("appsrv-07", "wiz", ip="::ffff:10.30.7.7", context="vpc-a", tags=("prod",)),
        _ent("prod-web-01", "wiz", ip="10.0.1.5", context="vpc-prod"),
        _ent("dev-web-01", "wiz", ip="10.0.1.5", context="vpc-dev"),
        _ent("db-dev-01", "algosec", ip="10.0.0.10", context="dc-1", tags=("dev",)),
        _ent("payments-db", "wiz", ip="10.0.0.10", context="dc-1", tags=("pci", "prod")),
        _ent("agent-a", "wiz", ip="127.0.0.1", context="dc-1"),
        _ent("agent-b", "wiz", ip="::ffff:127.0.0.1", context="dc-1"),
        _ent("0.0.0.0/0", "algosec", cidr="0.0.0.0/0", abstract=True),
    ] + [_ent(f"vip-{i}", "wiz", ip="10.7.7.7", context="dc-1") for i in range(4)]


# Fixed permutations, written out rather than generated: a shuffle seeded by the
# clock would make a failure here unreproducible, which is the opposite of the
# property under test.
_PERMUTATIONS = (
    tuple(range(15)),
    tuple(reversed(range(15))),
    (7, 0, 14, 3, 11, 1, 9, 5, 13, 2, 8, 6, 12, 4, 10),
    (14, 13, 0, 1, 12, 11, 2, 3, 10, 9, 4, 5, 8, 7, 6),
    (2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 0),
)


def _dump(r) -> tuple:
    """Everything the merge asserts about the estate, in output order."""
    return (
        tuple(sorted(r.alias_map.items())),
        tuple((a.asset_key, a.kind, a.context, tuple(a.ip_set), tuple(a.tags),
               tuple(a.source_tools), a.display_name) for a in r.assets),
        tuple((c.asset_key, c.match_key, c.confidence, repr(sorted(c.evidence.items(), key=str)))
              for c in r.correlations),
        r.suppressed_merges,
        tuple(sorted(r.suppressed_by_reason.items())),
    )


@pytest.mark.parametrize("order", _PERMUTATIONS)
def test_the_answer_does_not_depend_on_the_order_entities_arrived_in(order):
    base = _mixed_estate()
    assert len(order) == len(base)

    expected = _dump(resolve_identities(base))
    permuted = _dump(resolve_identities([base[i] for i in order]))

    assert permuted == expected


def test_the_mixed_estate_actually_exercises_every_arm():
    """Guards the test above from silently degrading into a no-op if a future
    edit stops one of the arms from firing."""
    r = resolve_identities(_mixed_estate())

    assert _merged(r, "app-server-07", "appsrv-07")           # scoped IP merge happened
    assert not _merged(r, "prod-web-01", "dev-web-01")        # context mismatch withheld
    assert not _merged(r, "db-dev-01", "payments-db")         # env conflict withheld
    assert not _merged(r, "agent-a", "agent-b")               # sentinel withheld
    assert not _merged(r, "vip-0", "vip-1")                   # fan-out withheld
    assert sorted({c.match_key for c in r.correlations}) == ["context_ip", "hostname", "manual_review"]
    assert r.suppressed_by_reason == {
        "context_mismatch": 1, "env_conflict": 1, "ip_fanout": 1, "sentinel_ip": 1,
    }
