"""Deterministic id generation.

Every id the engine produces is a stable function of its content, so re-running
the same snapshot UPSERTs to byte-identical rows (CLAUDE.md principle #7). Never
use randomness or timestamps here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_SEP = "\x1f"  # unit separator — unlikely to appear in inputs


def _digest(*parts: Any, length: int = 16) -> str:
    payload = _SEP.join(
        json.dumps(p, sort_keys=True, separators=(",", ":")) if not isinstance(p, str) else p
        for p in parts
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:length]


def det_id(prefix: str, *parts: Any) -> str:
    """Generic deterministic id, e.g. det_id('F', snapshot, 'over_permissive', ref)."""
    return f"{prefix}_{_digest(*parts)}"


def snapshot_id(label: str, content_fingerprint: str) -> str:
    """Stable across runs for the same inputs."""
    return f"snap_{_digest(label, content_fingerprint, length=12)}"


def content_fingerprint(*blobs: Any) -> str:
    """A single hash over arbitrary input blobs (e.g. the three raw exports)."""
    return _digest(*blobs, length=40)
