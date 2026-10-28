"""The indexed shadowing scan must report exactly what the O(n^2) scan did:
same shadowed rule, same (earliest) shadowing rule, for every rule. Checked
against a reference implementation of the scan on randomised rulebases that mix
any-protocol, ranges, single ports, ICMP, identities, groups and IPv6."""

from __future__ import annotations

import random

import pytest

from src.analyzers import shadowing as sh
from src.analyzers.cidr_overlap import dest_nets, source_nets
from src.normalizers.common import parse_service, record_from_service

NETS = ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.3/32", "10.2.0.0/16",
        "192.168.0.0/16", "192.168.5.0/24", "2001:db8::/32", "2001:db8:1::/48"]
SERVICES = ["any", "tcp/22", "tcp/443", "tcp/1-1024", "tcp/80,443", "udp/53", "udp/1-65535",
            "icmp", "tcp/8000-8100", "tcp/8080"]


def _rulebase(rnd: random.Random, n: int):
    recs = []
    for i in range(n):
        src = rnd.choice(NETS + ["Admins", "Contractors"])
        dst_pick = rnd.sample(NETS, rnd.choice([1, 1, 2]))
        dst_name = rnd.choice(["web", "db", "dmz"]) if len(dst_pick) > 1 or rnd.random() < .3 else dst_pick[0]
        is_ident = src in ("Admins", "Contractors")
        recs.append(record_from_service(
            record_id=f"r{i}", source_tool="t", raw_ref=f"r{i}", source=src,
            destination=dst_name, svc=parse_service(rnd.choice(SERVICES)),
            action=rnd.choice(["allow", "allow", "deny"]), order=i,
            source_cidrs=[] if is_ident else [src], dest_cidrs=dst_pick))
    return recs


def _reference(records, alias_map):
    """The pre-index scan, verbatim in its predicates."""
    recs = sorted([r for r in records if r.order is not None], key=lambda r: (r.order, r.raw_ref))
    sn, dn = [source_nets(r) for r in recs], [dest_nets(r) for r in recs]
    out = {}
    for i, later in enumerate(recs):
        for j in range(i):
            e = recs[j]
            if (sh._dest_covers(dn[j], dn[i], e, later, alias_map)
                    and sh._service_covers(e, later)
                    and sh._source_covers(sn[j], sn[i], e, later)):
                out[later.raw_ref] = e.raw_ref
                break
    return out


@pytest.mark.parametrize("seed", range(12))
def test_indexed_scan_matches_the_reference(seed) -> None:
    import networkx as nx
    rnd = random.Random(seed)
    recs = _rulebase(rnd, 220)
    findings = sh.analyze(recs, nx.DiGraph(), {})
    got = {f.signals["shadowed_ref"]: f.signals["shadowing_ref"] for f in findings}
    assert got == _reference(recs, {})
    assert got, "the randomised rulebase should contain shadowing to compare"
