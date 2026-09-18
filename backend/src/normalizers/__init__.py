"""Normalizer orchestration: load whatever consoles are onboarded and merge.

Two kinds of source, and the difference is structural
-----------------------------------------------------
The three POLICY exports (AlgoSec, Guardicore, Wiz) are REQUIRED. They are what
the product was built to analyse, the engine has nothing to say without them, and
a missing one is a broken deployment rather than a configuration choice — so a
missing file raises.

The INFRASTRUCTURE exports are OPTIONAL, one per console, and that is not
laziness about error handling. Partial onboarding is the normal state of every
real estate: a client with AlgoSec and no Catalyst Center genuinely has no view
of their access layer, and the product's job is to say which lanes that leaves
dark rather than to refuse to start. An absent file means "this console is not
onboarded", which is a fact about the engagement, not a failure.

WHAT ABSENT MUST NEVER MEAN IS UNREADABLE.
`_load_optional` distinguishes the two by hand, because the one-line version of
this function — a bare `try: ... except: return None` — collapses "not onboarded"
into "the file is corrupt" and the console then reports a lane as unobserved when
in fact we failed to read it. A file that EXISTS and will not parse raises, every
time. Only `FileNotFoundError` is a valid absence.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional

from . import algosec, algosec_topology, carrier, cisco, fortinet, guardicore, juniper, wiz
from . import vendor_policy  # noqa: E402
from .common import NormalizeResult

log = logging.getLogger(__name__)

MOCK_DIR = Path(__file__).resolve().parents[2] / "data" / "mock"

#: The policy exports. Missing one is a broken deployment.
REQUIRED = (
    ("algosec_export.json", algosec.normalize),
    ("guardicore_export.json", guardicore.normalize),
    ("wiz_export.json", wiz.normalize),
    # The vendor consoles' own rulebases. REQUIRED, not optional, and that is a
    # deliberate difference from the topology exports beside them: which
    # TOPOLOGY files exist is the estate's onboarding state, but policy is what
    # this engine was built to analyse, so a missing policy export is a broken
    # deployment rather than a configuration choice. Read by `vendor_policy`,
    # not by `fortinet`/`juniper` -- see that module's docstring for why.
    ("fortimanager_policy_export.json", vendor_policy.normalize_fortimanager),
    ("fortigate_policy_export.json", vendor_policy.normalize_fortigate),
    ("junos_space_policy_export.json", vendor_policy.normalize_junos_space),
)

#: The infrastructure exports, one per onboarded console. Each is optional; the
#: set that is present IS the estate's onboarding state, and the topology layer
#: reports which lanes that leaves unobserved.
OPTIONAL: tuple[tuple[str, Callable[[dict], NormalizeResult]], ...] = (
    ("algosec_topology_export.json", algosec_topology.normalize),
    ("fortimanager_export.json", fortinet.normalize),
    ("fortigate_export.json", fortinet.normalize),
    ("carrier_portal_export.json", carrier.normalize),
    ("catalyst_center_export.json", cisco.normalize_catalyst),
    ("meraki_export.json", cisco.normalize_meraki),
    ("junos_space_export.json", juniper.normalize),
)


def _load(name: str) -> dict:
    return json.loads((MOCK_DIR / name).read_text())


def _load_optional(name: str) -> Optional[dict]:
    """The export, or None when this console is not onboarded.

    ONLY `FileNotFoundError` is an absence. A file that exists and does not parse
    is a failure and is raised, because the alternative — swallowing it — makes
    the topology screen report a lane as "no source reported a device here" when
    the truth is "a source reported one and we could not read it". Those are the
    two statements this product exists to keep apart.
    """
    path = MOCK_DIR / name
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def onboarded_sources() -> list[str]:
    """Which optional consoles have an export present, for the Sources screen."""
    return sorted(name for name, _fn in OPTIONAL if (MOCK_DIR / name).exists())


def normalize_all() -> NormalizeResult:
    out = NormalizeResult()
    for name, fn in REQUIRED:
        out.extend(fn(_load(name)))
    for name, fn in OPTIONAL:
        raw = _load_optional(name)
        if raw is None:
            continue
        result = fn(raw)
        # Logged rather than silent: "we read this console and it had nothing"
        # and "we did not read this console" produce the same empty lists
        # downstream, and only this loop knows which happened.
        log.info("infrastructure export ingested", extra={
            "event": "infra_ingest", "export": name,
            "devices": len(result.devices), "interfaces": len(result.interfaces),
            "links": len(result.links), "circuits": len(result.circuits),
        })
        out.extend(result)
    return out


__all__ = [
    "normalize_all", "onboarded_sources", "NormalizeResult",
    "algosec", "guardicore", "wiz",
    "algosec_topology", "carrier", "cisco", "fortinet", "juniper",
]
