"""Zone classification + trust-boundary multiplier (deterministic lookups)."""

from __future__ import annotations

from ..config import (
    BOUNDARY_MULTIPLIERS, B_INTRA, ZONE_INTERNAL, ZONE_INTERNET, ZONE_PRIORITY, ZONE_TAGS,
)
from ..normalizers.common import INTERNET_CIDR


def zone_of(node_key: str, tags: list[str]) -> str:
    """Only the literal internet node is ZONE_INTERNET; exposed assets are DMZ."""
    if node_key == INTERNET_CIDR:
        return ZONE_INTERNET
    present = {ZONE_TAGS[t] for t in tags if t in ZONE_TAGS}
    for zone in ZONE_PRIORITY:        # most-exposed wins
        if zone in present:
            return zone
    return ZONE_INTERNAL


def boundary_multiplier(src_zone: str, dst_zone: str) -> float:
    return BOUNDARY_MULTIPLIERS.get((src_zone, dst_zone), B_INTRA)


def crosses_boundary(src_zone: str, dst_zone: str) -> bool:
    return boundary_multiplier(src_zone, dst_zone) > B_INTRA


def boundary_label(src_zone: str, dst_zone: str) -> str:
    return f"{src_zone}->{dst_zone}"
