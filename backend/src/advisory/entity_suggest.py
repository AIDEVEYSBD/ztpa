"""Capability #8 -- embedding-based entity-resolution SUGGESTIONS (assist only).

The deterministic identity layer merges only on hard signals (exact name, shared
IP). This proposes *possible* same-asset pairs across tools for HUMAN REVIEW --
it never auto-merges, because a wrong merge would corrupt a reachability fact.
Conservative by design: only pairs sharing a sensitive tag are considered.
"""

from __future__ import annotations

import math

from ..config import SENSITIVE_TAGS
from ..models import Asset
from .client import embed


def _cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _text(a: Asset) -> str:
    return (f"{a.display_name or a.asset_key}; type {a.identifiers.get('type', '')}; "
            f"tags {' '.join(sorted(a.tags))}")


def suggest_merges(assets: list[Asset]) -> list[dict]:
    concrete = [a for a in assets if a.kind == "concrete"]
    candidates: list[tuple[Asset, Asset]] = []
    for i in range(len(concrete)):
        for j in range(i + 1, len(concrete)):
            a, b = concrete[i], concrete[j]
            if not (set(a.tags) & set(b.tags) & SENSITIVE_TAGS):
                continue                                  # only flag possible duplicate *sensitive* assets
            if set(a.ip_set) & set(b.ip_set):
                continue                                  # a shared IP would already merge deterministically
            candidates.append((a, b))
    if not candidates:
        return []

    flat = [t for pair in candidates for t in (_text(pair[0]), _text(pair[1]))]
    vecs = embed(flat)

    out: list[dict] = []
    for k, (a, b) in enumerate(candidates):
        sim = _cos(vecs[2 * k], vecs[2 * k + 1]) if len(vecs) > 2 * k + 1 else 0.0
        shared = sorted(set(a.tags) & set(b.tags) & SENSITIVE_TAGS)
        confidence = round(0.5 * sim + 0.5 * min(1.0, 0.6 + 0.2 * len(shared)), 3)
        out.append({
            "a": a.asset_key, "b": b.asset_key,
            "a_tools": a.source_tools, "b_tools": b.source_tools,
            "a_ips": a.ip_set, "b_ips": b.ip_set,
            "shared_sensitive_tags": shared, "name_similarity": round(sim, 3),
            "confidence": confidence, "recommended_action": "review",
            "reason": (f"Both carry {', '.join(shared)} and resemble the same logical asset seen across "
                       f"{sorted(set(a.source_tools) | set(b.source_tools))}. Review before merging -- "
                       f"the engine will not merge automatically (different addresses, no shared identifier)."),
        })
    out.sort(key=lambda x: -x["confidence"])
    return out
