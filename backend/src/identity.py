"""Asset / identity layer — the duplicate-IP solution.

IP is an attribute, not the key. We merge each tool's view of a node into one
canonical asset using *deterministic* signals only:
  - exact name match across tools        (match_key = hostname)
  - shared host IP **within one declared
    scope**, capped and guarded          (match_key = context_ip)

A wrong merge would corrupt a fact (reachability), so this is deterministic and
auditable. Fuzzy, embedding-based *suggestions* for review live separately
(advisory.entity_suggest) and never auto-merge.

The alias_map (every observed name -> canonical asset_key) is what lets the
graph connect "appsrv-07" (Wiz) to "app-server-07" (AlgoSec/Guardicore).

Why the shared-IP arm is scoped, capped and guarded
---------------------------------------------------
The previous implementation keyed the union on the RAW IP STRING and unioned
every name that carried it. The correlation was even labelled `context_ip`, but
no context existed anywhere in the code — `ObservedEntity` had no such field and
`Asset.context` was assigned only AFTER the merge. Union-find is transitive by
construction and the only filter was `if e.ip:`, so:

  - RFC 1918 reuse across VPCs/accounts/VRFs — universal in any estate large
    enough to buy this product — fused two unrelated hosts. `build_graph` then
    collapsed both nodes' edges onto one, so the tool REPORTED REACHABILITY THAT
    DOES NOT EXIST, and `dest_score` took the MAX over the unioned tags, so a
    dev box inherited `pci` and every allow into it became a critical finding
    against regulated data.
  - Six hosts sharing a `0.0.0.0` placeholder (or `127.0.0.1`, or a cluster VIP,
    or a NAT address) collapsed the entire estate into ONE asset, with every
    edge attached to it.

Fabricated reachability in a security tool is worse than no tool, so every rule
below fails in the same direction: **when in doubt, do not merge.** A missed
merge is a UI annoyance that surfaces as a review candidate; a wrong merge is a
false statement about the customer's network that nobody can see. Four
independent guards implement that:

  1. SCOPE.    An IP only identifies a host inside the namespace that assigns it.
               The union key is `(context, canonical_ip)`; when either side has
               no declared context, or the two contexts differ, THERE IS NO
               UNION — the collision becomes a `manual_review` candidate.
               The scope is not invented here: it is whatever the EXPORT
               declares, lifted into the entity by
               `normalizers.common.scope_identifiers` and read back by
               `context_of`. A tool that names no VRF / VPC / account therefore
               cannot take this arm at all — which is the correct failure
               direction, and is why the three bundled demo exports (none of
               which declares a namespace) produce no shared-IP merge and one
               `unscoped_ip` review row for the 10.30.7.7 collision between
               `app-server-07` and `appsrv-07`.
  2. SENTINEL. Addresses from `SENTINEL_BLOCKS` never union at all, in any
               scope and in EITHER family's spelling of them (`::ffff:127.0.0.1`
               is 127.0.0.1): they are placeholders, not identities.
  3. FAN-OUT.  `MAX_IP_FANOUT` distinct names on one address inside one scope is
               the most a genuine host can produce; beyond it the address is
               shared infrastructure and the whole group is withheld.
  4. ENVIRONMENT. Two components carrying mutually exclusive environment tags
               (prod vs dev) are never unioned automatically.

`manual_merges` — an operator saying "these two names are the same host" —
bypasses all four. That is the point of the review path: the guards withhold a
merge and hand it to a human, and the human's answer is authoritative.

Determinism (independently verified: `sorted()` at every iteration site, a
union-find rooted at `min(name)`, byte-identical output across processes and
PYTHONHASHSEED values) is a property of this file and every addition preserves
it: sets are used only as internal scratch, never in an output path, and every
group is `sorted()` before it is read.

WITHHOLDING IS A DECISION, SO IT IS ANNOUNCED
---------------------------------------------
The guards are the good half of this module, and they were also its quietest.
`IdentityResult.suppressed_merges` and `.suppressed_by_reason` are computed
correctly and then dropped: `analyzers.run_all.run()` copies assets,
correlations and alias_map out of the result and never reads the counts, so the
only surviving trace of "we withheld six merges on this estate" is a set of
confidence-0.0 correlation rows nobody queries. To an operator looking at two
asset cards for what they believe is one host, the engine appears to have simply
not noticed.

Two events are logged here, at levels that match what they mean:

  * merges WITHHELD (INFO). Not a failure -- it is the module working -- but it
    is a queue of human decisions the estate is waiting on, and the by-reason
    breakdown says which. `unscoped_ip` in particular is an export-quality
    finding ("your export declares no VPC/VRF"), not a network finding.
  * a manual merge naming a name NOBODY OBSERVED (WARNING). That one is a
    failure: a human went to the review queue, confirmed two assets are the same
    host, and the engine dropped the answer because the name is not in this
    snapshot's entity set (a renamed host, a tool no longer ingested, a merge
    confirmed against an older export). Nothing told them. `run_all` folds
    merges into the snapshot fingerprint, so the id even changes -- a new
    snapshot that is identical to the old one.

Logging cannot reach the fact path: no branch below reads a logger, and the
`sorted()` in each call site is there so the MESSAGE is deterministic too.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from dataclasses import dataclass, field

from .models import Asset, AssetCorrelation
from .netaddr import parse_net
from .normalizers.common import INTERNET_CIDR, ObservedEntity
from .sources import HOST_DESCRIBING_TOOLS, TOOL_KEYS as _ALL_TOOL_KEYS

# A child of the API's logger, so an identity decision comes out as one JSON line
# with the request id already attached (app/main.py configures "npr.api"). In the
# engine-only contexts -- verify_engine.py, the test suite -- it propagates to
# the root logger, which is where pytest's caplog can see it.
log = logging.getLogger("npr.api.identity")

# "An address object of either family". Named here rather than reused from
# `netaddr`, whose same-spelled private name is the isinstance TUPLE of these two
# classes and would be wrong in an annotation.
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# ---------------------------------------------------------------------------
# Published policy constants. These are the merge's *policy*, not its mechanics,
# so they live at module scope where a reviewer (or a test) can read the rule
# without reading the algorithm.
# ---------------------------------------------------------------------------

# Addresses that never identify a host, and therefore never union — whatever the
# scope, and however many names carry them. Real exports are full of these: an
# agent that reports its loopback, a DHCP failure, a row whose IP column was
# empty and got filled with the unspecified address. Each one is a statement
# that the IP is UNKNOWN, which is the opposite of an identity signal.
SENTINEL_BLOCKS: tuple[str, ...] = (
    "0.0.0.0/32",       # RFC 1122 unspecified — the "we don't know" placeholder
    "127.0.0.0/8",      # RFC 1122 loopback — every host is 127.0.0.1
    "169.254.0.0/16",   # RFC 3927 link-local / APIPA — a DHCP failure, not an address
    "::/128",           # RFC 4291 v6 unspecified
    "::1/128",          # RFC 4291 v6 loopback
    "fe80::/10",        # RFC 4291 v6 link-local — the exact analogue of 169.254/16;
                        # omitting it would be an accident of the v4-shaped list
)
_SENTINEL_NETS = tuple(ipaddress.ip_network(b) for b in SENTINEL_BLOCKS)

# Largest number of DISTINCT NAMES on one address, inside one declared scope,
# that we will still fuse automatically.
#
# The union links *names*, and one host produces at most one name per tool that
# observes it. So the bound is "how many tools could each contribute one name",
# which is the count of HOST-DESCRIBING sources: a fabric controller that only
# describes links (sd_wan, sd_lan) cannot name a host and must not widen it.
# More names than that on one address means the address is being SHARED — a
# cluster VIP, a NAT/SNAT pool, an unresolved-DNS default — rather than
# identifying anything. Counting names, not entities, is deliberate: the same
# name seen by every tool is one node and must not count as fan-out.
#
# DERIVED PER ADDRESS, not a global constant — see `fanout_cap`.
#
# The literal 3 this replaces was correct for exactly the three host-describing
# tools that existed when it was written, and it was the easiest thing in this
# codebase to leave behind when a fourth was added: no error, and the worst
# available symptom. A legitimate four-tool merge is withheld as `ip_fanout`,
# the asset silently splits in two, and a cross-tool path through it vanishes
# from the findings with nothing anywhere reporting a problem.
#
# Replacing it with `len(HOST_DESCRIBING_TOOLS)` would fix that and introduce a
# worse one in the other direction: registering a connector nobody has onboarded
# would WEAKEN the guard on every estate, because the ceiling would count tools
# that never observed anything. A guard whose strength depends on the catalogue
# rather than on the evidence is not a guard.
#
# So the bound is computed from what actually named this address. It is stricter
# than the old constant in the case that matters (six names from ONE tool now
# caps at 1, not 3) and looser in exactly the case that was a bug (four names
# from four tools). This constant remains only as the registry-wide CEILING, for
# documentation and for tests that need a value no real address can exceed.
MAX_IP_FANOUT = len(HOST_DESCRIBING_TOOLS)


def fanout_cap(tools: set[str]) -> int:
    """How many distinct names one genuine host could produce at this address.

    The union links NAMES, and a single host yields at most one name per tool
    that observes it. So the ceiling is the number of distinct host-describing
    tools that actually named this address in this scope — never the size of the
    catalogue, and never a constant fixed when the catalogue was smaller.

    Tools that describe only links (an SD-WAN or SD-LAN fabric) cannot name a
    host and so do not raise the cap. A tool outside the registry is counted:
    it named something, and refusing to count it would make an unrecognised
    source silently tighten the guard.

    Floors at 1 — an address named by no host-describing tool at all can still
    legitimately carry one name.
    """
    naming = {t for t in tools if t not in _LINK_ONLY_TOOLS}
    return max(len(naming), 1)


# Tools that describe LINKS rather than hosts. Read off the registry so a new
# fabric controller cannot quietly widen the merge guard.
_LINK_ONLY_TOOLS: frozenset[str] = frozenset(
    set(_ALL_TOOL_KEYS) - set(HOST_DESCRIBING_TOOLS)
)

# Identifier keys that name a NAMESPACE — something inside which an IP is unique.
# Ordered: the first non-empty one wins, so the answer cannot depend on dict
# ordering. `env` and `cloud` are deliberately absent: "prod" and "aws" are
# labels shared by every account in the estate, so keying a merge on them would
# reintroduce exactly the collision this module exists to prevent.
CONTEXT_IDENTIFIER_KEYS: tuple[str, ...] = (
    "vrf", "vpc", "account", "subscription", "project", "tenant",
)

# Environment tags, folded onto a canonical class so that "production"/"prod"
# are one environment and not a conflict. Two components whose environment
# classes are both known and different are never unioned automatically: an
# address that appears in prod and in dev is the textbook RFC 1918 reuse case.
ENV_TAG_CLASSES: dict[str, str] = {
    "prod": "prod", "production": "prod", "prd": "prod",
    "dev": "dev", "development": "dev",
    "staging": "staging", "stage": "staging", "stg": "staging",
    "test": "test", "qa": "test", "uat": "test",
    "sandbox": "sandbox", "sbx": "sandbox",
}

# Reasons a candidate merge was withheld. Published so the UI can label the
# review queue with something better than "suppressed".
SUPPRESSION_REASONS: tuple[str, ...] = (
    "context_mismatch",   # the address exists in two different declared scopes
    "env_conflict",       # mutually exclusive environment tags (prod vs dev)
    "ip_fanout",          # more than MAX_IP_FANOUT names on one address in one scope
    "sentinel_ip",        # a placeholder address (SENTINEL_BLOCKS) shared by many names
    "unscoped_ip",        # at least one side declared no scope at all
)


@dataclass
class IdentityResult:
    assets: list[Asset] = field(default_factory=list)
    correlations: list[AssetCorrelation] = field(default_factory=list)
    alias_map: dict[str, str] = field(default_factory=dict)   # observed name -> canonical key
    # How many candidate merges the guards WITHHELD, so the UI can say
    # "N merges withheld pending review" instead of silently doing nothing.
    # One per withheld candidate group (an address plus the names it links),
    # which is exactly one row in the review queue — not a pair count.
    suppressed_merges: int = 0
    # The same number broken down by SUPPRESSION_REASONS, keys sorted.
    suppressed_by_reason: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Address helpers — never raise. A malformed value in a customer export is a
# fact to classify, not an exception to handle at nine call sites.
# ---------------------------------------------------------------------------

def _unmap(addr: _IPAddress) -> _IPAddress:
    """An IPv4-mapped v6 address -> the IPv4 address it IS; everything else as-is.

    ``::ffff:127.0.0.1`` and ``127.0.0.1`` are ONE host (RFC 4291 §2.5.5.2).
    Which spelling an export uses is an accident of whether the agent that wrote
    it held a v6 socket, so the two must not be two identities — and, far more
    sharply, must not be two *classifications*.

    This fold is what makes the address rules below family-agnostic. Without it
    `is_sentinel_ip` gated block membership on ``addr.version == net.version``,
    and a mapped loopback is version 6, so the v4 sentinel blocks were never
    consulted for it: ``is_sentinel_ip("::ffff:127.0.0.1")`` was False and the
    address UNIONED. That is not a synthetic value —
    `normalizers.profile.object_cidrs` accepts the mapped spelling as a single
    host address, so it reaches `ObservedEntity.ip` from a real export, and with
    it the whole estate-collapse the sentinel guard exists to stop came back:
    six hosts plus the PCI database on ``::ffff:127.0.0.1`` fused into one asset
    keyed `db-prod-01`, with `suppressed_merges == 0` because nothing had been
    withheld. Written ``127.0.0.1``, the identical input produced seven assets.

    `netaddr._unwrap_mapped` applies the same rule to networks, so the two
    layers agree on what a mapped address means.

    Only the MAPPED block (``::ffff:0:0/96``) is folded. The deprecated
    IPv4-compatible form (``::a.b.c.d``, RFC 4291 §2.5.5.1) is deliberately left
    alone: ``::`` and ``::1`` sit inside that block and are the v6 unspecified
    and loopback addresses, NOT 0.0.0.0 and 0.0.0.1, so folding it would rewrite
    two sentinels into unrelated routable-looking addresses — the same class of
    bug in the opposite direction.
    """
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def canonical_ip(ip) -> str | None:
    """One spelling per address, or None when the value is not a host address.

    `10.0.0.5`, `10.0.0.5/32` and `::1` all reduce to a single canonical string,
    so two tools spelling one address differently land in the same merge group
    instead of two. Address FAMILY is part of "spelling": an IPv4-mapped v6
    value (`::ffff:10.0.0.5`) canonicalises to its embedded v4 form
    (`10.0.0.5`), because it is that address — see `_unmap`. Anything that is
    not a single host — a network, a label, a list that a mis-mapped ingest
    profile put in the column — returns None and therefore never merges.
    """
    if not isinstance(ip, str) or not ip.strip():
        return None
    token = ip.strip()
    try:
        return str(_unmap(ipaddress.ip_address(token)))
    except ValueError:
        pass
    net = parse_net(token)                       # tolerate "10.0.0.5/32"
    if net is not None and net.prefixlen == net.max_prefixlen:
        return str(_unmap(net.network_address))
    return None


def is_sentinel_ip(ip) -> bool:
    """True when this value cannot identify a host, so it must never union.

    Covers both halves of "not an identity": an address inside
    `SENTINEL_BLOCKS`, and a value that is not a host address at all. The second
    case is folded in on purpose — a token we cannot parse is not evidence of
    shared identity either, and the caller would otherwise have to remember to
    check both.
    """
    canon = canonical_ip(ip)
    if canon is None:
        return True
    # `canonical_ip` has already folded a mapped address to its v4 form; folding
    # again keeps this predicate correct on its OWN terms rather than by
    # convention, so it cannot silently regress if canonicalisation moves.
    addr = _unmap(ipaddress.ip_address(canon))
    # No `addr.version == net.version` test here, deliberately: that comparison
    # was the bug (see `_unmap`) — it read as a safety check while it was the
    # thing suppressing the v4 blocks for a v6-spelled loopback. `ipaddress`
    # already answers False for an address of the other family
    # (`_BaseNetwork.__contains__` short-circuits on `_version`), so the
    # cross-family pairs are free and no family reasoning is needed at all.
    return any(addr in net for net in _SENTINEL_NETS)


def context_of(entity: ObservedEntity) -> str | None:
    """The namespace an entity's IP is unique inside, or None when undeclared.

    Two sources, in that order.

    `ObservedEntity.context` is an optional forward hook: no shipped model
    DECLARES that field, so `getattr` (rather than attribute access) is what
    keeps this layer working either way. It is also what let this docstring
    claim the field was "populated by each normalizer from its export" while it
    was in fact None for 100% of entities in production — the scoped arm, and
    with it `MAX_IP_FANOUT` and the environment guard, was unreachable outside
    the tests, which reached it by `setattr`.

    The LIVE source is the second one: the namespace identifiers listed in
    `CONTEXT_IDENTIFIER_KEYS`, which `normalizers.common.scope_identifiers`
    lifts off an export row that declares a VRF / VPC / account / subscription /
    project / tenant, under those canonical keys.

    An export that declares no namespace — which includes all three bundled demo
    exports — yields None, and None is a first-class answer meaning "this export
    declared no scope". It is never treated as a scope that could match another
    None: two unknowns are not evidence of sameness, so a shared address with no
    declared namespace is a review candidate and never a merge.
    """
    raw = getattr(entity, "context", None)
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    identifiers = getattr(entity, "identifiers", None) or {}
    for key in CONTEXT_IDENTIFIER_KEYS:
        value = identifiers.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _env_classes(tags) -> frozenset[str]:
    """The environment classes a tag list asserts (empty when it asserts none)."""
    return frozenset(
        ENV_TAG_CLASSES[t.strip().lower()]
        for t in (tags or [])
        if isinstance(t, str) and t.strip().lower() in ENV_TAG_CLASSES
    )


def _host_cidr(ip: str) -> str | None:
    """A bare address rendered as its own single-host network, v4 OR v6.

    The old implementation was `f"{ip}/32"`, which silently produced the
    nonsense `2001:db8::1/32` for every IPv6 asset — a /32 of v6 is 2**96
    addresses, so an asset's own address read as a colossal network. The prefix
    length now comes from the address family itself.
    """
    canon = canonical_ip(ip)
    if canon is None:
        return None
    addr = ipaddress.ip_address(canon)
    return f"{addr}/{addr.max_prefixlen}"


def resolve_identities(entities: list[ObservedEntity],
                       manual_merges: list[tuple[str, str]] = ()) -> IdentityResult:
    names = sorted({e.name for e in entities})
    parent = {n: n for n in names}

    by_name: dict[str, list[ObservedEntity]] = defaultdict(list)
    for e in entities:
        by_name[e.name].append(e)

    # Environment class per COMPONENT (keyed by its root), kept current as
    # components merge so the exclusivity guard sees the whole component and not
    # just the two names in front of it. Union-find is transitive: without this,
    # prod--(untagged)--dev would still fuse a prod and a dev host through an
    # untagged middle name.
    comp_env: dict[str, frozenset[str]] = {
        n: _env_classes([t for e in by_name[n] for t in e.tags]) for n in names
    }

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            root, merged = min(ra, rb), max(ra, rb)
            parent[merged] = root               # smaller name becomes root (deterministic)
            comp_env[root] = comp_env[root] | comp_env[merged]

    def union_scoped(a: str, b: str) -> str | None:
        """Union unless a guard refuses. Returns the refusal reason, or None."""
        ra, rb = find(a), find(b)
        if ra == rb:
            return None
        env_a, env_b = comp_env[ra], comp_env[rb]
        if env_a and env_b and env_a != env_b:
            return "env_conflict"
        union(ra, rb)
        return None

    # --- shared-IP candidates, grouped by the scope the address is unique in ---
    # Sets here are internal scratch only; every one of them is `sorted()` before
    # it is read, so no iteration order can reach the output.
    scoped: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    # Which tools named each (ip, scope). The fan-out cap is computed from this
    # rather than from a constant: six names on one address from ONE tool is not
    # a host no matter how many tools exist in the catalogue.
    scoped_tools: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    unscoped: dict[str, set[str]] = defaultdict(set)
    ip_names: dict[str, set[str]] = defaultdict(set)
    sentinel_names: dict[str, set[str]] = defaultdict(set)
    for e in entities:
        ip = canonical_ip(e.ip)
        if ip is None:
            continue
        if is_sentinel_ip(ip):
            sentinel_names[ip].add(e.name)
            continue
        ip_names[ip].add(e.name)
        ctx = context_of(e)
        if ctx is None:
            unscoped[ip].add(e.name)
        else:
            scoped[ip][ctx].add(e.name)
            scoped_tools[ip][ctx].add(e.tool)

    merged_groups: list[tuple[str, str, list[str]]] = []       # (ip, context, names)
    withheld: list[tuple[str, str, str | None, list[str]]] = []  # (ip, reason, context, names)

    for ip in sorted(ip_names):
        by_ctx = scoped.get(ip, {})
        for ctx in sorted(by_ctx):
            group = sorted(by_ctx[ctx])
            if len(group) < 2:
                continue                                  # nothing to link in this scope
            if len(group) > fanout_cap(scoped_tools[ip][ctx]):
                # More names than the tools that named them could each have
                # contributed one of: a shared address (a cluster VIP, a NAT
                # pool, an unresolved-DNS default), not an identity. Withhold
                # the WHOLE group rather than fusing an arbitrary prefix of it.
                withheld.append((ip, "ip_fanout", ctx, group))
                continue
            linked, refused = [], []
            for other in group[1:]:
                if union_scoped(group[0], other) is None:
                    linked.append(other)
                else:
                    refused.append(other)
            if linked:
                merged_groups.append((ip, ctx, sorted([group[0]] + linked)))
            if refused:
                withheld.append((ip, "env_conflict", ctx, sorted([group[0]] + refused)))
        # Cross-scope collisions on this address. The old rule would have fused
        # every one of these; each is now one row in the review queue instead.
        if len(ip_names[ip]) > 1:
            if unscoped.get(ip):
                # At least one side declared no scope, so nothing about this
                # address is comparable. Reported ahead of context_mismatch
                # because "your export declares no VPC/VRF" is the actionable half.
                withheld.append((ip, "unscoped_ip", None, sorted(ip_names[ip])))
            elif len(by_ctx) > 1:
                withheld.append((ip, "context_mismatch", None, sorted(ip_names[ip])))

    # A placeholder address shared by several names is not a merge candidate at
    # all -- it is a data-quality signal ("these rows have no IP") -- but it is
    # exactly the input that used to collapse the estate, so it is counted and
    # surfaced rather than dropped in silence.
    for ip in sorted(sentinel_names):
        if len(sentinel_names[ip]) > 1:
            withheld.append((ip, "sentinel_ip", None, sorted(sentinel_names[ip])))

    # human-confirmed merges (advisory.entity_suggest -> reviewed -> confirmed).
    # Deterministic like the others; only union names we actually observed.
    # These bypass every guard above BY DESIGN: the guards exist to hand an
    # ambiguous collision to a human, and this is the human's answer coming back.
    unmatched: list[tuple[str, str, list[str]]] = []
    for a, b in manual_merges:
        if a in parent and b in parent:
            union(a, b)
        else:
            # The operator's decision is being DROPPED. Collected rather than
            # logged inline so one line covers the whole run, and sorted so the
            # line is as deterministic as the assets it describes.
            unmatched.append((a, b, sorted(n for n in (a, b) if n not in parent)))
    if unmatched:
        log.warning("confirmed asset merges name entities that are not in this snapshot; "
                    "the operator's decision was NOT applied",
                    extra={"event": "identity_manual_merge_unmatched",
                           "count": len(unmatched),
                           "pairs": [{"a": a, "b": b, "missing": miss}
                                     for a, b, miss in sorted(unmatched)]})

    components: dict[str, list[str]] = defaultdict(list)
    for n in names:
        components[find(n)].append(n)

    result = IdentityResult()
    abstract_keys: set[str] = set()
    for _root, members in components.items():
        members = sorted(members)
        ents = [e for nm in members for e in by_name[nm]]

        def tool_count(nm: str) -> int:
            return len({e.tool for e in by_name[nm]})

        # canonical key = name used by the most tools; tie -> lexicographically smallest
        canonical = sorted(members, key=lambda nm: (-tool_count(nm), nm))[0]
        tools = sorted({e.tool for e in ents})
        tags = sorted({t for e in ents for t in e.tags})
        ips: set[str] = set()
        identifiers: dict = {}
        for e in ents:
            host = _host_cidr(e.ip) if e.ip is not None else None
            if host is not None:
                ips.add(host)
            # Through parse_net rather than straight into the set: a `cidr` that
            # a mis-mapped export made a list is unhashable and used to raise
            # TypeError out of the whole engine run.
            net = parse_net(e.cidr) if e.cidr is not None else None
            if net is not None:
                ips.add(str(net))
            # ...and every OTHER block the node denotes. `ObservedEntity.cidr`
            # holds one string, so an address group ({0.0.0.0/0, 10.0.0.0/8})
            # left it None and the asset came out with ip_set == []. That empty
            # list is what `graph.build` hands `zones.zone_of`, so the group was
            # classified ZONE_INTERNAL and the boundary multiplier collapsed
            # 1.5 -> 1.0: the same grant scored 86/critical written 0.0.0.0/0 and
            # 57/medium written as the group that resolves to it. The record's
            # `source_cidrs` carried the space correctly all along, but a record
            # field cannot classify a node -- only the asset can. Same parse_net
            # guard, so a non-string member is dropped, never crashed on.
            for raw in e.cidrs:
                net = parse_net(raw)
                if net is not None:
                    ips.add(str(net))
            identifiers.update({k: v for k, v in e.identifiers.items() if v is not None})
        abstract = all(e.abstract for e in ents)
        # The asset now REPORTS the scope its merge was keyed on, instead of a
        # label derived after the fact. The env/cloud fallback is kept so an
        # export that declares no namespace still shows the operator something.
        declared = sorted({c for c in (context_of(e) for e in ents) if c})
        context = ("|".join(declared) if declared
                   else (identifiers.get("env") or identifiers.get("cloud")))

        result.assets.append(Asset(
            asset_key=canonical,
            kind="abstract" if abstract else "concrete",
            context=context,
            identifiers=identifiers,
            ip_set=sorted(ips),
            tags=tags,
            source_tools=tools,
            display_name="Internet" if canonical == INTERNET_CIDR else canonical,
        ))
        for nm in members:
            result.alias_map[nm] = canonical

        if abstract:
            abstract_keys.add(canonical)
            continue  # don't emit identity-merge audits for internet/subnet nodes

        # audit: exact-name merges (a single name seen by >1 tool)
        for nm in members:
            ts = sorted({e.tool for e in by_name[nm]})
            if len(ts) > 1:
                result.correlations.append(AssetCorrelation(
                    asset_key=canonical, match_key="hostname", confidence=1.0,
                    evidence={"name": nm, "tools": ts},
                ))

    # audit: shared-IP merges that actually happened. `context_ip` finally names
    # something real -- the scope is in the evidence, so the audit row can be
    # checked against the export it came from.
    for ip, ctx, group in merged_groups:
        key = result.alias_map.get(group[0])
        if key is None or key in abstract_keys:
            continue
        result.correlations.append(AssetCorrelation(
            asset_key=key, match_key="context_ip", confidence=0.95,
            evidence={"ip": ip, "context": ctx, "names": group},
        ))

    # audit: candidate merges the guards WITHHELD. confidence 0.0 -- this is the
    # engine stating it does not know, which is the whole point: the row is a
    # review queue entry, not a claim about the estate.
    reason_counts: dict[str, int] = {}
    for ip, reason, ctx, group in withheld:
        key = result.alias_map.get(group[0])
        if key is None:
            continue
        # ...unless the names ended up in one asset anyway -- a human confirmed
        # the merge through `manual_merges`, or an exact-name match already tied
        # them together. Reporting "1 merge withheld pending review" for a merge
        # that HAPPENED would send the operator back to a decision they made.
        if len({result.alias_map[n] for n in group if n in result.alias_map}) < 2:
            continue
        result.correlations.append(AssetCorrelation(
            asset_key=key, match_key="manual_review", confidence=0.0,
            evidence={"status": "withheld", "reason": reason, "ip": ip,
                      "context": ctx, "names": group},
        ))
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
    result.suppressed_merges = sum(reason_counts.values())
    result.suppressed_by_reason = {r: reason_counts[r] for r in sorted(reason_counts)}
    if result.suppressed_merges:
        # INFO, not WARNING: withholding is the correct answer to an ambiguous
        # collision, and a demo estate legitimately has one every run. It is
        # still a queue of decisions waiting on a human, which is why it is said
        # out loud at all -- `run_all.run()` drops these counts on the floor, so
        # this line is currently the ONLY place outside the correlation rows
        # where the number appears.
        log.info("candidate asset merges withheld pending human review",
                 extra={"event": "identity_merges_withheld",
                        "withheld": result.suppressed_merges,
                        "by_reason": result.suppressed_by_reason})

    # audit: human-confirmed merges (so the unified asset shows as cross-tool correlated)
    for a, b in manual_merges:
        if a in result.alias_map and b in result.alias_map and result.alias_map[a] == result.alias_map[b]:
            result.correlations.append(AssetCorrelation(
                asset_key=result.alias_map[a], match_key="manual_review", confidence=1.0,
                evidence={"names": sorted({a, b}), "by": "human-confirmed"},
            ))

    result.assets.sort(key=lambda a: a.asset_key)
    result.correlations.sort(key=lambda c: (c.asset_key, c.match_key, str(c.evidence)))
    return result
