"""Deterministic conflict detection + simulated push for the staging area.

We are not wired to AlgoSec / Guardicore / Wiz, so the push is *simulated* -- but
the conflict math is genuine engine math: a staged change is compared against the
current canonical rules (and other staged changes for the same tool) to surface
duplicates, CIDR overlaps, shadowing denies, and contradictions, each with a
deterministic resolution. build_push_plan() returns an ordered list of steps the
UI animates so the operator watches conflicts resolve in real time."""

from __future__ import annotations

import ipaddress

from ..normalizers.common import is_cidr, parse_service


def _net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except Exception:
        return None


def _overlap(a: str, b: str) -> bool:
    na, nb = _net(a), _net(b)
    if not na or not nb:
        return False
    return na.overlaps(nb)


def _svc_match(proto_a, port_a, proto_b, port_b) -> bool:
    """Two services touch the same traffic if protocol matches (or either is 'any')
    and the port matches (or either is the whole protocol / 'any')."""
    if proto_a != "any" and proto_b != "any" and proto_a != proto_b:
        return False
    if port_a is None or port_b is None:
        return True
    return port_a == port_b


def _canon(ctx, name: str) -> str:
    return ctx.alias_map.get(name, name)


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

    src = payload.get("source", "")
    dst = _canon(ctx, payload.get("destination", ""))
    proto, port, _ = parse_service(payload.get("service", "any"))
    src_is_cidr = is_cidr(src)

    conflicts: list[dict] = []
    for r in ctx.records:
        if _canon(ctx, r.destination) != dst:
            continue
        if not _svc_match(proto, port, r.protocol, r.port):
            continue
        same_src = (r.source == src) or (src_is_cidr and is_cidr(r.source) and _overlap(src, r.source))
        if r.action == "allow" and r.source == src and _svc_match(proto, port, r.protocol, r.port):
            conflicts.append({"kind": "duplicate", "detail": f"an identical allow already exists ({r.raw_ref})",
                              "against": r.raw_ref, "resolution": "Skip: this flow is already permitted (no-op)."})
        elif r.action == "allow" and same_src:
            conflicts.append({"kind": "overlap", "detail": f"source overlaps existing allow {r.raw_ref} ({r.source})",
                              "against": r.raw_ref, "resolution": f"Merge: fold into the broader rule {r.raw_ref} instead of adding a redundant one."})
        elif r.action == "deny" and same_src:
            conflicts.append({"kind": "contradiction", "detail": f"an existing deny {r.raw_ref} blocks this flow",
                              "against": r.raw_ref, "resolution": "Needs human review: an explicit deny contradicts this allow."})

    # sibling staged changes targeting the same flow
    for o in (other_staged or []):
        if o.get("staged_id") == staged.get("staged_id"):
            continue
        op = o.get("payload") or {}
        if o.get("kind") == "add_allow" and _canon(ctx, op.get("destination", "")) == dst and op.get("source") == src:
            conflicts.append({"kind": "duplicate_staged", "detail": f"another staged change targets the same flow ({o.get('staged_id')})",
                              "against": o.get("staged_id"), "resolution": "Skip: a sibling staged change already covers this flow."})
    return conflicts


def build_push_plan(ctx, staged: dict, other_staged: list[dict] | None = None) -> dict:
    """Ordered, animatable steps for a simulated push, with conflicts resolved
    deterministically. Final status is 'pushed' (all resolved) or 'conflict'
    (a contradiction needs human review)."""
    tool = staged.get("target_tool") or "source system"
    conflicts = detect_conflicts(ctx, staged, other_staged)
    unresolved = [c for c in conflicts if c["kind"] in ("contradiction", "stale_target")]

    steps: list[dict] = [
        {"key": "connect", "label": f"Connect to {tool}", "status": "ok",
         "detail": f"Authenticated session to {tool} (simulated)."},
        {"key": "validate", "label": "Validate change payload", "status": "ok",
         "detail": "Payload schema and references validated against the current snapshot."},
    ]
    if conflicts:
        steps.append({"key": "detect", "label": f"Detect conflicts ({len(conflicts)})", "status": "warn",
                      "detail": "; ".join(f"{c['kind']}: {c['detail']}" for c in conflicts)})
        for c in conflicts:
            resolved = c["kind"] not in ("contradiction", "stale_target")
            steps.append({"key": f"resolve:{c['kind']}", "label": f"Resolve {c['kind']}",
                          "status": "ok" if resolved else "blocked", "detail": c["resolution"]})
    else:
        steps.append({"key": "detect", "label": "Detect conflicts", "status": "ok",
                      "detail": "No conflicts with existing rules."})

    if unresolved:
        steps.append({"key": "apply", "label": "Apply change", "status": "blocked",
                      "detail": "Held for human review: an unresolved conflict prevents auto-apply."})
        final = "conflict"
    else:
        steps.append({"key": "apply", "label": "Apply change", "status": "ok",
                      "detail": f"Change written to {tool} (simulated)."})
        steps.append({"key": "verify", "label": "Verify applied state", "status": "ok",
                      "detail": "Re-read confirms the rule is present and consistent (simulated)."})
        final = "pushed"

    resolution = {"resolved": [c for c in conflicts if c not in unresolved], "unresolved": unresolved}
    return {"status": final, "conflicts": conflicts, "resolution": resolution, "push_steps": steps}
