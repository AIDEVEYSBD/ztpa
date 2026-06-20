"""Normalizer orchestration: load the simulated exports and merge into one
canonical NormalizeResult."""

from __future__ import annotations

import json
from pathlib import Path

from . import algosec, guardicore, wiz
from .common import NormalizeResult

MOCK_DIR = Path(__file__).resolve().parents[2] / "data" / "mock"


def _load(name: str) -> dict:
    return json.loads((MOCK_DIR / name).read_text())


def normalize_all() -> NormalizeResult:
    out = NormalizeResult()
    out.extend(algosec.normalize(_load("algosec_export.json")))
    out.extend(guardicore.normalize(_load("guardicore_export.json")))
    out.extend(wiz.normalize(_load("wiz_export.json")))
    return out


__all__ = ["normalize_all", "NormalizeResult", "algosec", "guardicore", "wiz"]
