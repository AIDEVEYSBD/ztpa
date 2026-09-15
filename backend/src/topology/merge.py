"""Fold several consoles' views of one network into one picture.

The problem
-----------
Every console sees a slice, and the slices OVERLAP. On the demo estate three
different sources describe `fw-perim-01`:

    fortimanager  (aggregator)  model=FortiGate-200F  ha_role=primary
    fortigate     (device)      model=None            ha_role=None
    algosec       (aggregator)  model=FortiGate-200F  ha_role=None

Ingesting all three yields 19 devices for a 13-device estate. That is not a
cosmetic duplicate: the topology screen would draw three boxes where there is one
firewall, the resilience analyzer would compute articulation points over a graph
whose nodes are split, and the inventory count -- a number a reviewer reads out
loud -- would be wrong by 46%.

The naive fix is worse than the bug
-----------------------------------
A last-write-wins merge keyed on `device_key` would let the device-tier read,
which reports no model and no HA role because neither is in the four tables it
reads, overwrite `model="FortiGate-200F"` and `ha_role="primary"` with None.
Onboarding MORE sources would then produce a THINNER inventory, and nothing
would report a problem. So the rule is:

    A STATED FACT IS NEVER OVERWRITTEN BY AN ABSENT ONE.

`None` means "this console does not carry this field", never "this field is
empty". That is the same three-valued discipline `NetInterface.admin_up` uses,
applied to the merge.

When two consoles state DIFFERENT values
----------------------------------------
That is not a tie to be broken quietly. Two sources disagreeing about what a
device is, or what model it is, is a finding about the estate's own record-
keeping -- a stale entry in one console, a device replaced without the aggregator
being told. So a conflict is RECORDED on the merged row (`conflicts`), with both
values and both tools named, and then resolved by tier:

    device  >  management_console  >  aggregator

because a first-hand read beats a second-hand one. Ties inside a tier break on
the tool key, so the result cannot depend on ingest order.

`role` is resolved on its own axis first (`declared` > `derived` > `unknown`),
because a console that states a device type outright outranks one that had its
type inferred, regardless of tier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, TypeVar

from ..models import (
    Circuit, NetDevice, NetInterface, NetLink, Provenance, Subnet, Vlan,
)

# First-hand beats second-hand. Higher wins.
_TIER_RANK = {"device": 3, "management_console": 2, "aggregator": 1}

# A console that SAYS what something is outranks one whose type we worked out,
# whatever tier either sits at.
_ROLE_SOURCE_RANK = {"declared": 3, "derived": 2, "unknown": 1}

# How much a link's evidence is worth. A neighbour protocol is a device saying
# "I see this peer on this port"; containment is arithmetic over two addresses.
# Both are real observations and they are not equally strong, so a merged link
# keeps the strongest one that was offered rather than whichever arrived last.
_EVIDENCE_RANK = {
    "lldp": 6, "cdp": 6, "api_topology": 5, "config": 4,
    "routing": 3, "declared": 2, "containment": 1,
}

T = TypeVar("T")


def _rank(p: Provenance) -> tuple[int, str]:
    """Sort key making the winner independent of ingest order."""
    return (_TIER_RANK.get(p.source_tier, 0), p.source_tool)


@dataclass
class _Field:
    """One source's claim about one field."""

    value: object
    tool: str
    tier: str


def _resolve(claims: list[_Field], field: str, key: str) -> tuple[object, list[dict]]:
    """The winning value for one field, plus any conflict it papers over.

    Absent claims are dropped BEFORE anything is compared, so a console that does
    not carry the field takes no part in deciding it. That is the whole rule: a
    source can only contribute what it actually observed.
    """
    stated = [c for c in claims if c.value not in (None, "", [])]
    if not stated:
        return None, []
    distinct = {_hashable(c.value) for c in stated}
    conflicts: list[dict] = []
    if len(distinct) > 1:
        # Recorded, not resolved away. Two consoles disagreeing about a device is
        # a fact about the estate's record-keeping, and the operator is the one
        # who can act on it.
        conflicts.append({
            "entity": key,
            "field": field,
            "claims": sorted(
                ({"tool": c.tool, "tier": c.tier, "value": c.value} for c in stated),
                key=lambda d: (d["tool"], str(d["value"])),
            ),
        })
    best = max(stated, key=lambda c: (_TIER_RANK.get(c.tier, 0), c.tool))
    return best.value, conflicts


def _hashable(v: object) -> object:
    return tuple(v) if isinstance(v, list) else v


def _observed(views) -> list[dict]:
    """Every console that saw this row, deduped and sorted.

    Deduped on a tuple before being rendered as dicts: a set of dicts is not a
    thing, and a merge whose output order depended on insertion order would make
    the snapshot fingerprint depend on ingest order.
    """
    seen = {(v.provenance.source_tool, v.provenance.source_tier, v.provenance.raw_ref)
            for v in views}
    return [{"tool": t, "tier": ti, "raw_ref": r} for t, ti, r in sorted(seen)]


def _union(values: Iterable[Iterable[str]]) -> list[str]:
    """Sorted union — used for fields where every source's view is additive
    (addresses, tags, the networks behind an interface). A second console seeing
    another address on a port adds to what we know; it does not contradict it."""
    out: set[str] = set()
    for v in values:
        out.update(v or ())
    return sorted(out)


def merge_devices(devices: Iterable[NetDevice]) -> tuple[list[NetDevice], list[dict]]:
    """One row per device, with every console's contribution folded in."""
    by_key: dict[str, list[NetDevice]] = {}
    for d in devices:
        by_key.setdefault(d.device_key, []).append(d)

    merged: list[NetDevice] = []
    conflicts: list[dict] = []
    for key in sorted(by_key):
        views = sorted(by_key[key], key=lambda d: _rank(d.provenance), reverse=True)
        primary = views[0]
        if len(views) == 1:
            merged.append(primary)
            continue

        def claims(attr: str) -> list[_Field]:
            return [_Field(getattr(v, attr), v.provenance.source_tool,
                           v.provenance.source_tier) for v in views]

        out = primary.model_copy(deep=True)
        for attr in ("name", "vendor", "model", "os_version", "serial", "mgmt_ip",
                     "site", "ha_group", "ha_role"):
            value, c = _resolve(claims(attr), attr, key)
            conflicts.extend(c)
            if value is not None:
                setattr(out, attr, value)

        # Role resolves on its own axis: a console that STATES the type outranks
        # one whose type we derived, whichever tier each sits at.
        roled = sorted(views, key=lambda v: (_ROLE_SOURCE_RANK.get(v.role_source, 0),
                                             _TIER_RANK.get(v.provenance.source_tier, 0),
                                             v.provenance.source_tool), reverse=True)
        declared = [v for v in roled if v.role_source == "declared" and v.role != "unknown"]
        stated_roles = {v.role for v in declared}
        if len(stated_roles) > 1:
            conflicts.append({
                "entity": key, "field": "role",
                "claims": sorted(({"tool": v.provenance.source_tool,
                                   "tier": v.provenance.source_tier, "value": v.role}
                                  for v in declared),
                                 key=lambda d: (d["tool"], d["value"])),
            })
        best_role = roled[0]
        out.role, out.role_source, out.role_reason = (
            best_role.role, best_role.role_source, best_role.role_reason)

        out.tags = _union(v.tags for v in views)
        # The row now says every console that saw this device, which is what
        # "where did we find it" means for something three consoles describe.
        out.observed_by = _observed(views)
        out.conflicts = [c for c in conflicts if c["entity"] == key]
        merged.append(out)
    return merged, conflicts


def merge_interfaces(interfaces: Iterable[NetInterface]) -> tuple[list[NetInterface], list[dict]]:
    """One row per interface. Addresses are unioned; scalars follow the device rule."""
    by_key: dict[str, list[NetInterface]] = {}
    for i in interfaces:
        by_key.setdefault(i.interface_key, []).append(i)

    merged: list[NetInterface] = []
    conflicts: list[dict] = []
    for key in sorted(by_key):
        views = sorted(by_key[key], key=lambda i: _rank(i.provenance), reverse=True)
        primary = views[0]
        if len(views) == 1:
            merged.append(primary)
            continue

        out = primary.model_copy(deep=True)
        for attr in ("description", "vlan_id", "zone", "speed_mbps", "lag_group",
                     "mac", "neighbor_device", "neighbor_interface"):
            value, c = _resolve(
                [_Field(getattr(v, attr), v.provenance.source_tool, v.provenance.source_tier)
                 for v in views], attr, key)
            conflicts.extend(c)
            if value is not None:
                setattr(out, attr, value)

        # admin_up / oper_up are three-valued and must not go through `_resolve`,
        # which drops falsey claims: a source reporting a port DOWN states False,
        # and treating that as "said nothing" would hide an outage. Only None is
        # absence here.
        for attr in ("admin_up", "oper_up"):
            stated = [v for v in views if getattr(v, attr) is not None]
            if not stated:
                continue
            if len({getattr(v, attr) for v in stated}) > 1:
                conflicts.append({
                    "entity": key, "field": attr,
                    "claims": sorted(({"tool": v.provenance.source_tool,
                                       "tier": v.provenance.source_tier,
                                       "value": getattr(v, attr)} for v in stated),
                                     key=lambda d: (d["tool"], str(d["value"]))),
                })
            setattr(out, attr, getattr(max(stated, key=lambda v: _rank(v.provenance)), attr))

        out.addresses = _union(v.addresses for v in views)
        out.networks_behind = _union(v.networks_behind for v in views)
        out.observed_by = _observed(views)
        out.conflicts = [c for c in conflicts if c["entity"] == key]
        merged.append(out)
    return merged, conflicts


def _link_identity(ln: NetLink) -> tuple:
    """What makes two link rows the same cable.

    Keyed on the device pair AND the interface pair, both unordered, because a
    pair of devices can genuinely be joined by more than one cable -- collapsing
    on the device pair alone would erase exactly the redundancy this product
    exists to report on. Interfaces fall back to empty when a console did not
    name them, which correctly collapses two unported views of one adjacency.
    """
    devs = tuple(sorted((ln.a_device, ln.b_device)))
    ifs = tuple(sorted((ln.a_interface or "", ln.b_interface or "")))
    return devs, ifs


def merge_links(links: Iterable[NetLink]) -> list[NetLink]:
    """One row per cable, keeping the strongest evidence anyone offered.

    A link seen by CDP and also derivable from address containment is a CDP link:
    downgrading it because a weaker observation arrived later would understate
    what we know, and the evidence class is rendered on screen.
    """
    by_id: dict[tuple, list[NetLink]] = {}
    for ln in links:
        by_id.setdefault(_link_identity(ln), []).append(ln)

    merged: list[NetLink] = []
    for ident in sorted(by_id, key=lambda t: (t[0], t[1])):
        views = by_id[ident]
        best = max(views, key=lambda l: (_EVIDENCE_RANK.get(l.evidence, 0),
                                         _TIER_RANK.get(l.provenance.source_tier, 0),
                                         l.provenance.source_tool))
        out = best.model_copy(deep=True)
        if len(views) > 1:
            # Keep the richer structural facts whichever view carried them: a
            # console that knows this is a 2-member LAG knows something the one
            # that merely saw the adjacency does not.
            out.aggregated = any(v.aggregated for v in views)
            out.member_count = max(v.member_count for v in views)
            out.redundant_group = next(
                (v.redundant_group for v in sorted(views, key=lambda v: _rank(v.provenance),
                                                   reverse=True) if v.redundant_group), None)
            out.observed_by = sorted(
                ({"tool": v.provenance.source_tool, "tier": v.provenance.source_tier,
                  "evidence": v.evidence} for v in views),
                key=lambda d: (d["tool"], d["evidence"]),
            )
        merged.append(out)
    return merged


def _merge_keyed(items: Iterable[T], key) -> list[T]:
    """Collapse rows sharing a key, preferring the higher-tier view.

    Used for VLANs, subnets and circuits, whose fields are either list-valued
    (unioned by the caller's model defaults being additive) or stable across
    sources. Kept simple deliberately: none of the three has the scalar-vs-None
    hazard that made devices and interfaces need their own path.
    """
    by_key: dict[object, list[T]] = {}
    for item in items:
        by_key.setdefault(key(item), []).append(item)
    out: list[T] = []
    for k in sorted(by_key, key=str):
        views = sorted(by_key[k], key=lambda v: _rank(v.provenance), reverse=True)
        out.append(views[0])
    return out


def merge_vlans(vlans: Iterable[Vlan]) -> list[Vlan]:
    by_id: dict[int, list[Vlan]] = {}
    for v in vlans:
        by_id.setdefault(v.vlan_id, []).append(v)
    out: list[Vlan] = []
    for vid in sorted(by_id):
        views = sorted(by_id[vid], key=lambda v: _rank(v.provenance), reverse=True)
        best = views[0].model_copy(deep=True)
        # Additive: two consoles each knowing part of where a VLAN is carried is
        # more coverage, not a disagreement.
        best.subnets = _union(v.subnets for v in views)
        best.gateways = _union(v.gateways for v in views)
        best.device_keys = _union(v.device_keys for v in views)
        best.tags = _union(v.tags for v in views)
        if best.name is None:
            best.name = next((v.name for v in views if v.name), None)
        out.append(best)
    return out


def merge_subnets(subnets: Iterable[Subnet]) -> list[Subnet]:
    by_cidr: dict[str, list[Subnet]] = {}
    for s in subnets:
        by_cidr.setdefault(s.cidr, []).append(s)
    out: list[Subnet] = []
    for cidr in sorted(by_cidr):
        views = sorted(by_cidr[cidr], key=lambda s: _rank(s.provenance), reverse=True)
        best = views[0].model_copy(deep=True)
        best.gateways = _union(v.gateways for v in views)
        best.device_keys = _union(v.device_keys for v in views)
        best.tags = _union(v.tags for v in views)
        out.append(best)
    return out


def merge_circuits(circuits: Iterable[Circuit]) -> list[Circuit]:
    by_id: dict[str, list[Circuit]] = {}
    for c in circuits:
        by_id.setdefault(c.circuit_id, []).append(c)
    out: list[Circuit] = []
    for cid in sorted(by_id):
        views = sorted(by_id[cid], key=lambda c: _rank(c.provenance), reverse=True)
        best = views[0].model_copy(deep=True)
        best.public_ips = _union(v.public_ips for v in views)
        for attr in ("provider", "bandwidth_mbps", "device_key", "interface"):
            if getattr(best, attr) is None:
                setattr(best, attr, next((getattr(v, attr) for v in views
                                          if getattr(v, attr) is not None), None))
        if best.technology == "unknown":
            best.technology = next((v.technology for v in views
                                    if v.technology != "unknown"), "unknown")
        out.append(best)
    return out
