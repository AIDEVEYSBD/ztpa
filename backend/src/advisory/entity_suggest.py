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
from .client import embed_texts


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
    emb = embed_texts(flat)
    vecs = emb.vectors

    # A dead embedding server used to render as the POSITIVE claim "these two PCI
    # assets do not resemble each other": embed() returned [] for both "nothing
    # asked" and "every provider down", so every pair scored name_similarity 0.0
    # and the suggestion shipped anyway. Zero similarity computed from zero data
    # is not a measurement. When the vectors are absent we now say so, and drop
    # the similarity term from confidence rather than scoring it as a hard zero.
    out: list[dict] = []
    for k, (a, b) in enumerate(candidates):
        have_vecs = emb.ok and len(vecs) > 2 * k + 1
        sim = _cos(vecs[2 * k], vecs[2 * k + 1]) if have_vecs else None
        shared = sorted(set(a.tags) & set(b.tags) & SENSITIVE_TAGS)
        tag_term = min(1.0, 0.6 + 0.2 * len(shared))
        # With no similarity, confidence rests on the tag evidence alone instead
        # of being halved by a fabricated 0.0.
        confidence = round(0.5 * sim + 0.5 * tag_term, 3) if have_vecs else round(tag_term, 3)
        out.append({
            "a": a.asset_key, "b": b.asset_key,
            "a_tools": a.source_tools, "b_tools": b.source_tools,
            "a_ips": a.ip_set, "b_ips": b.ip_set,
            "shared_sensitive_tags": shared,
            "name_similarity": round(sim, 3) if have_vecs else None,
            "similarity_available": have_vecs,
            "similarity_unavailable_reason": None if have_vecs else (
                emb.error or "no embedding provider answered"),
            "confidence": confidence,
            "confidence_basis": "similarity+tags" if have_vecs else "tags_only",
            "recommended_action": "review",
            # The "resemble" clause is a similarity claim, so it may only be made
            # when a similarity was actually computed. Degraded, we state the tag
            # evidence we do have and name what is missing -- rather than implying
            # a resemblance the engine never measured.
            "reason": (
                (f"Both carry {', '.join(shared)} and resemble the same logical asset seen across "
                 f"{sorted(set(a.source_tools) | set(b.source_tools))}. Review before merging -- "
                 f"the engine will not merge automatically (different addresses, no shared identifier).")
                if have_vecs else
                (f"Both carry {', '.join(shared)} and appear across "
                 f"{sorted(set(a.source_tools) | set(b.source_tools))}. Name similarity could NOT be "
                 f"computed (no embedding provider answered), so this pair is proposed on shared "
                 f"sensitive tags alone -- treat the absence of a similarity score as unknown, not as "
                 f"evidence the assets differ. Review before merging.")
            ),
        })
    out.sort(key=lambda x: -x["confidence"])
    return out
