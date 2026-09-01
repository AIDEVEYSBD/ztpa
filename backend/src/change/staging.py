"""Deterministic conflict detection + simulated push for the staging area.

We are not wired to AlgoSec / Guardicore / Wiz, so the push is *simulated* -- but
the conflict math is genuine engine math: a staged change is compared against the
current canonical rules (and other staged changes for the same tool) to surface
duplicates, CIDR overlaps, shadowing denies, and contradictions, each with a
deterministic resolution. build_push_plan() returns an ordered list of steps the
UI animates so the operator watches conflicts resolve in real time.

Every step this module emits must describe something that actually happened. The
fabricated ones (connect / validate / stage / reflect) say "Simulated:" out loud
and the payload carries `simulated: True` so the UI renders the wording from the
flag instead of hardcoding a claim; the resolutions that say "Skip" now really
skip -- the plan comes back as status 'no_op' so the pushed-changes overlay
(persist.load_applied_changes, WHERE status='pushed') never folds the record in.
Previously the overlay appended the duplicate anyway, i.e. the screen narrated a
conflict resolution the engine did not perform.

WHAT THE MATH COMPARES (PROD-READINESS-AUDIT, "Conflict math ignores port ranges
and rule order, and doesn't canonicalize source identities")
------------------------------------------------------------------------------
Two rules touch the same traffic when the same PACKET could match both. A packet
has a protocol, a port and a source address, so all three comparisons have to be
about those values rather than about the strings an export happened to use:

  services   INTERVAL INTERSECTION over every (lo, hi) the service grants, not
             `port_a == port_b`. Equality made `tcp/1-65535` not conflict with
             `tcp/3389`, and a staged `tcp/8050` land silently inside an existing
             `tcp/8000-8100` -- "No conflicts with existing rules", then a
             redundant grant pushed. Comma lists ("tcp/80,443") are covered too:
             they live only in the service LABEL, because the canonical record
             carries a single (port, port_end) pair.

  sources    the RESOLVED address space (`PolicyRecord.source_cidrs`), plus the
             alias-canonical label. Comparing labels meant the same host under
             two tools' names ("appsrv-07" / "app-server-07") read as two
             different sources, so a cross-tool duplicate was invisible -- in the
             product whose headline claim is that it unifies exactly those names.

  intersect vs COVER   these are different questions and both are needed.
             Intersection decides "is there a conflict at all"; coverage decides
             whether the honest resolution is "Skip: already permitted" (the
             existing rule grants everything the staged one would) or "Redundant:
             kept as its own entry" (it grants only part). Reporting a skip for a
             staged rule that is WIDER than the existing one would be the same
             class of lie this module was cleaned up to remove.

Rule ORDER is still not consulted -- see the note above `_BLOCKING_KINDS`.
"""

from __future__ import annotations

from ..netaddr import parse_net, same_family
from ..normalizers.common import cidrs_for_token, parse_service

# A port interval, inclusive at both ends. `[]` (no interval at all) means the
# service named no port, i.e. THE WHOLE PROTOCOL -- which is why every predicate
# below treats an empty list as "matches everything", never as "matches nothing".
Interval = tuple[int, int]


# --- what a rule grants ----------------------------------------------------

def _service_of(service: str | None, port=None, port_end=None,
                protocol: str | None = None) -> tuple[str, list[Interval]]:
    """(protocol, port intervals) for one rule's service. Never raises.

    Two views of the same fact have to be reconciled. The scalar `port` /
    `port_end` pair is what a canonical `PolicyRecord` carries and is
    authoritative. The service LABEL is the only place a comma list survives --
    `DecodedService.ports` exists precisely because the scalar pair structurally
    cannot hold `tcp/80,443` -- so the label is decoded as well and preferred
    whenever its first interval agrees with the scalar pair. Where the two
    disagree the numbers win: a record is scored on its fields, never on its
    prose.
    """
    svc = parse_service(service) if service else None
    proto = protocol or (svc.protocol if svc is not None else "any")
    scalar: list[Interval] = []
    if isinstance(port, int):
        scalar = [(port, port_end if isinstance(port_end, int) else port)]
    parsed = svc.intervals() if svc is not None else []
    if parsed and (not scalar or parsed[0] == scalar[0]):
        return proto, parsed
    return proto, scalar


def _intervals_intersect(a: list[Interval], b: list[Interval]) -> bool:
    """True when some port is granted by both. Empty == the whole protocol."""
    if not a or not b:
        return True
    return any(a_lo <= b_hi and b_lo <= a_hi for a_lo, a_hi in a for b_lo, b_hi in b)


def _intervals_cover(outer: list[Interval], inner: list[Interval]) -> bool:
    """True when every port in `inner` is also granted by `outer`.

    Both lists come out of `_merge_intervals`, so they are sorted and disjoint
    and each `inner` interval must sit inside a SINGLE `outer` one. An empty
    `outer` is the whole protocol and covers everything; an empty `inner` is an
    unstated port, which only the whole protocol can be proven to cover.
    """
    if not outer:
        return True
    if not inner:
        return False
    return all(any(o_lo <= lo and hi <= o_hi for o_lo, o_hi in outer) for lo, hi in inner)


def _svc_match(proto_a: str, ports_a: list[Interval],
               proto_b: str, ports_b: list[Interval]) -> bool:
    """Could one packet match both services? Protocol compatible AND ports overlap."""
    if proto_a != "any" and proto_b != "any" and proto_a != proto_b:
        return False
    return _intervals_intersect(ports_a, ports_b)


def _svc_covers(proto_outer: str, ports_outer: list[Interval],
                proto_inner: str, ports_inner: list[Interval]) -> bool:
    """Does `outer` already grant everything `inner` would? (Not symmetric.)"""
    if proto_outer != "any" and proto_outer != proto_inner:
        return False
    return _intervals_cover(ports_outer, ports_inner)


# --- who a rule applies to -------------------------------------------------

def _canon(ctx, name: str) -> str:
    return ctx.alias_map.get(name, name)


def _source_space(ctx, token: str, declared=None) -> tuple[str, list[str]]:
    """(alias-canonical label, resolved address space) for a rule's source.

    `declared` is the record's / payload's own `source_cidrs`: the address space
    a normalizer dereferenced the object catalog to. When it is empty we derive
    what the token itself denotes (an address, or the wildcard vocabulary) --
    which is what `record_from_service` would have stored anyway, so a record
    hand-built without the field still compares on address space rather than on
    string luck. A token that names no address space at all resolves to `[]`,
    and the label is then the only handle we have.
    """
    key = _canon(ctx, token or "")
    cidrs = list(declared or []) or cidrs_for_token(key) or cidrs_for_token(token or "")
    return key, cidrs


def _same_source(a_label: str, a_cidrs: list[str], b_label: str, b_cidrs: list[str]) -> bool:
    """The SAME source, however the two exports spelled it.

    Label equality AFTER alias canonicalization catches "appsrv-07" vs
    "app-server-07" -- the cross-tool duplicate the identity layer exists to
    find. Address-space equality catches "10.1.0.0/16" vs "10.1.0.1/16", two
    spellings of one network: both lists are canonical and sorted (the
    `PolicyRecord` validator and `cidrs_for_token` produce the same normal form),
    so `==` is exact set identity.
    """
    if a_label and a_label == b_label:
        return True
    return bool(a_cidrs) and a_cidrs == b_cidrs


def _sources_overlap(a_cidrs: list[str], b_cidrs: list[str]) -> bool:
    """True when the two address spaces share at least one address.

    `same_family` first: comparing a v4 network against a v6 one is meaningless,
    and the guard keeps one v6 rule in a v4 rulebase from deciding anything by
    accident.
    """
    for a in a_cidrs:
        na = parse_net(a)
        if na is None:
            continue
        for b in b_cidrs:
            nb = parse_net(b)
            if nb is not None and same_family(na, nb) and na.overlaps(nb):
                return True
    return False


def detect_conflicts(ctx, staged: dict, other_staged: list[dict] | None = None) -> list[dict]:
    """Compare an add_allow staged change against current rules + sibling staged
    changes. Returns a list of {kind, detail, against, resolution} conflicts."""
    payload = staged.get("payload") or {}
    if staged.get("kind") != "add_allow":
        # Remediation changes are restrictive; the only "conflict" worth flagging is
        # a stale target (the rule it edits no longer exists in this snapshot).
        ref = payload.get("target_ref")
        if ref and not any(r.raw_ref == ref for r in ctx.records):
            return [{"kind": "stale_target", "detail": f"rule {ref} no longer exists in this snapshot",
                     "against": ref, "resolution": "Re-derive the fix against the current snapshot before applying."}]
        return []

    dst = _canon(ctx, payload.get("destination", ""))
    src_key, src_cidrs = _source_space(ctx, payload.get("source", ""), payload.get("source_cidrs"))
    proto, ports = _service_of(payload.get("service", "any"), payload.get("port"),
                               payload.get("port_end"), payload.get("protocol"))

    conflicts: list[dict] = []
    for r in ctx.records:
        if _canon(ctx, r.destination) != dst:
            continue
        r_proto, r_ports = _service_of(r.service, r.port, r.port_end, r.protocol)
        if not _svc_match(proto, ports, r_proto, r_ports):
            continue
        r_key, r_cidrs = _source_space(ctx, r.source, r.source_cidrs)
        identical_src = _same_source(src_key, src_cidrs, r_key, r_cidrs)
        if not (identical_src or _sources_overlap(src_cidrs, r_cidrs)):
            continue
        if r.action == "allow" and identical_src and _svc_covers(r_proto, r_ports, proto, ports):
            # Same source, and the existing grant already carries every port the
            # staged one would: pushing it changes nothing, so "skip" is true.
            same_service = (r_proto, r_ports) == (proto, ports)
            detail = (f"an identical allow already exists ({r.raw_ref})" if same_service
                      else f"{r.raw_ref} ({r.service}) already permits every port this asks for")
            conflicts.append({"kind": "duplicate", "detail": detail, "against": r.raw_ref,
                              "resolution": "Skip: this flow is already permitted (no-op)."})
        elif r.action == "allow" and identical_src:
            # Same source, overlapping but NOT covering service: part of the
            # staged range is genuinely new, so this may not be reported as a skip.
            conflicts.append({"kind": "overlap",
                              "detail": f"existing allow {r.raw_ref} ({r.service}) already permits part of {payload.get('service', 'any')}",
                              "against": r.raw_ref,
                              "resolution": f"Redundant in part: {r.raw_ref} already permits some of these ports. The rule is kept as its own entry — fold the two by hand at the source system."})
        elif r.action == "allow":
            conflicts.append({"kind": "overlap", "detail": f"source overlaps existing allow {r.raw_ref} ({r.source})",
                              "against": r.raw_ref, "resolution": f"Redundant: {r.raw_ref} already covers this source range. The rule is kept as its own entry — fold the two by hand at the source system."})
        elif r.action == "deny":
            conflicts.append({"kind": "contradiction", "detail": f"an existing deny {r.raw_ref} blocks this flow",
                              "against": r.raw_ref, "resolution": "Needs human review: an explicit deny contradicts this allow."})

    # sibling staged changes targeting the same flow
    for o in (other_staged or []):
        if o.get("staged_id") == staged.get("staged_id") or o.get("kind") != "add_allow":
            continue
        op = o.get("payload") or {}
        if _canon(ctx, op.get("destination", "")) != dst:
            continue
        o_key, o_cidrs = _source_space(ctx, op.get("source", ""), op.get("source_cidrs"))
        if not _same_source(src_key, src_cidrs, o_key, o_cidrs):
            continue
        o_proto, o_ports = _service_of(op.get("service", "any"), op.get("port"),
                                       op.get("port_end"), op.get("protocol"))
        # Same "Skip must be true" rule as above: a sibling only covers this flow
        # when it grants every port of it. Two staged changes to one destination
        # on DIFFERENT ports are two changes, not a duplicate.
        if not _svc_covers(o_proto, o_ports, proto, ports):
            continue
        conflicts.append({"kind": "duplicate_staged", "detail": f"another staged change targets the same flow ({o.get('staged_id')})",
                          "against": o.get("staged_id"), "resolution": "Skip: a sibling staged change already covers this flow."})
    return conflicts


# --- what a push actually does ---------------------------------------------
# Conflict kinds that BLOCK the push: a human has to look at them.
#
# NOTE (deliberately not fixed here): `contradiction` ignores rule ORDER. In a
# first-match rulebase a deny that sits BELOW an allow for the same flow never
# matches, so flagging it is a false positive -- a spurious block, never a
# spurious approval, which is why it is safe to leave. Fixing it means comparing
# `r.order` against the staged rule's insertion order, and the honest version of
# that needs the push to re-prove against the live engine (Phase 3).
_BLOCKING_KINDS = ("contradiction", "stale_target")
# Conflict kinds whose deterministic resolution is "do nothing". These are the
# kinds whose step text says "Skip", so the push must genuinely skip: the row is
# left in a `no_op` status, which persist.load_applied_changes() (WHERE
# status='pushed') never folds into the overlay. Before this, the UI narrated a
# skip the overlay did not perform -- it appended the duplicate record anyway.
_SKIP_KINDS = ("duplicate", "duplicate_staged")


def build_push_plan(ctx, staged: dict, other_staged: list[dict] | None = None) -> dict:
    """Ordered, animatable steps for a SIMULATED push, with conflicts resolved
    deterministically.

    Nothing here contacts a source system: there is no connector to AlgoSec /
    Guardicore / Wiz in this build, so the plan is flagged `simulated: True` and
    every fabricated step is labelled "Simulated:" on screen. What IS real is the
    conflict math (genuine engine math against the current snapshot) and the
    consequence of the final status:

      - 'pushed'   -- the change is recorded locally and apply_overlay() folds it
                      into the record set on the next recompute (nothing is
                      written to the source system).
      - 'no_op'    -- every conflict resolves to "skip", so NOTHING is recorded;
                      the overlay leaves the record set untouched.
      - 'conflict' -- a contradiction / stale target needs human review; nothing
                      is recorded.
    """
    tool = staged.get("target_tool") or "source system"
    conflicts = detect_conflicts(ctx, staged, other_staged)
    unresolved = [c for c in conflicts if c["kind"] in _BLOCKING_KINDS]
    skips = [c for c in conflicts if c["kind"] in _SKIP_KINDS]

    steps: list[dict] = [
        {"key": "connect", "label": f"Simulated: connect to {tool}", "status": "ok",
         "detail": f"No live {tool} connector is configured — nothing was contacted."},
        {"key": "validate", "label": "Simulated: validate change payload", "status": "ok",
         "detail": "Checked against the current snapshot only; no source-system validation was performed."},
    ]
    if conflicts:
        steps.append({"key": "detect", "label": f"Detect conflicts ({len(conflicts)})", "status": "warn",
                      "detail": "; ".join(f"{c['kind']}: {c['detail']}" for c in conflicts)})
        # The index keeps the step key unique when two conflicts share a kind
        # (two duplicates against two rules) -- it is the React list key.
        for i, c in enumerate(conflicts):
            resolved = c["kind"] not in _BLOCKING_KINDS
            steps.append({"key": f"resolve:{i}:{c['kind']}", "label": f"Resolve {c['kind']}",
                          "status": "ok" if resolved else "blocked", "detail": c["resolution"]})
    else:
        steps.append({"key": "detect", "label": "Detect conflicts", "status": "ok",
                      "detail": "No conflicts with existing rules."})

    if unresolved:
        steps.append({"key": "apply", "label": "Hold for human review", "status": "blocked",
                      "detail": "An unresolved conflict prevents auto-apply. Nothing was recorded."})
        final = "conflict"
    elif skips:
        # The reported resolution and the executed action are now the same thing.
        steps.append({"key": "apply", "label": "Skipped — nothing recorded", "status": "warn",
                      "detail": f"{skips[0]['resolution']} The staged change is a no-op: it is not "
                                f"recorded and the next recompute is unchanged."})
        final = "no_op"
    else:
        steps.append({"key": "apply", "label": f"Simulated: stage for {tool}", "status": "ok",
                      "detail": f"Recorded locally as staged for {tool}. There is no connector, so the "
                                f"{tool} data source is untouched."})
        steps.append({"key": "verify", "label": "Simulated: reflect on next recompute", "status": "ok",
                      "detail": "The engine folds this change into its own record set as an overlay on "
                                "the next recompute; the source system stays unchanged."})
        final = "pushed"

    resolution = {"resolved": [c for c in conflicts if c not in unresolved], "unresolved": unresolved,
                  "skipped": skips}
    return {"status": final, "simulated": True, "conflicts": conflicts,
            "resolution": resolution, "push_steps": steps}
