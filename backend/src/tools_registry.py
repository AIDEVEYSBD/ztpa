"""Single source of truth for every tool / AI capability the app exposes, plus
the per-role enable/disable layer the admin Tools screen drives.

Two kinds of entry:
  - agent_tool   : a deterministic engine tool the assistant may call.
  - ai_capability: an LLM/embedding job (explain, rank, classify, ...).

Enablement is per-role, stored in ztpa.tool_settings (a row's enabled_roles
array). An absent row means enabled for all roles (default-on). The current
request's role comes from request_ctx (set by the proxy-injected header)."""

from __future__ import annotations

import time

from . import request_ctx
from .db import fetch_all, get_conn

# key, label, kind, description, example_output (a short illustrative result)
TOOLS: list[dict] = [
    # --- deterministic agent tools (the assistant calls these) ---------------
    {"key": "resolve", "label": "Resolve identity", "kind": "agent_tool",
     "description": "Resolve a name or CIDR to its canonical asset (tags, IPs, source tools, zone).",
     "example_output": '{"found": true, "asset_key": "app-server-07", "kind": "concrete", "tags": ["pci"]}'},
    {"key": "reachable", "label": "Reachability check", "kind": "agent_tool",
     "description": "Can source reach destination (optionally on a port)? Returns yes/no plus the path(s).",
     "example_output": '{"reachable": true, "paths": ["0.0.0.0/0 -> lb-public-01 -> app-server-07"]}'},
    {"key": "find_paths", "label": "Find paths", "kind": "agent_tool",
     "description": "All paths from source to destination, with the tools each hop crosses.",
     "example_output": '{"count": 1, "paths": [{"path": "internet -> lb -> app", "tools": ["wiz", "algosec"]}]}'},
    {"key": "effective_policy", "label": "Effective policy", "kind": "agent_tool",
     "description": "What can actually reach an asset, and whether it is internet-exposed.",
     "example_output": '{"asset": "db-prod-01", "internet_exposed": false, "reachable_from": [...]}'},
    {"key": "risk_findings", "label": "Risk findings", "kind": "agent_tool",
     "description": "The deterministic risk findings, optionally filtered by type / minimum severity.",
     "example_output": '{"count": 12, "findings": [{"type": "cross_tool_path", "severity": 95}]}'},
    {"key": "simulate_change", "label": "Simulate change", "kind": "agent_tool",
     "description": "Compute the delta a proposed allow rule would create (new paths / exposure).",
     "example_output": '{"new_paths": [...], "new_exposed_assets": ["db-prod-01"], "would_escalate": true}'},
    # --- AI capabilities (LLM / embeddings) ----------------------------------
    {"key": "explain", "label": "Explain finding", "kind": "ai_capability",
     "description": "Plain-English explanation of why a finding matters (language).",
     "example_output": "This rule lets the entire internet reach a PCI database on tcp/1433..."},
    {"key": "rank", "label": "Rank actions", "kind": "ai_capability",
     "description": "Group findings by root cause and rank worst-first (judgment).",
     "example_output": '[{"priority": 1, "title": "Close internet path to db-prod-01"}]'},
    {"key": "classify", "label": "Classify change", "kind": "ai_capability",
     "description": "Auto-approve vs escalate a change, reasoning over the computed delta (guardrailed).",
     "example_output": '{"decision": "escalate", "confidence": 0.95, "forced_escalate": true}'},
    {"key": "remediate", "label": "Draft remediation", "kind": "ai_capability",
     "description": "Draft a fix-as-code, re-simulated by the engine to prove it resolves the finding.",
     "example_output": '{"fix_text": "Scope rule R-12 source to 10.20.5.0/24", "validation": {"resolves": true}}'},
    {"key": "report", "label": "Posture report", "kind": "ai_capability",
     "description": "Executive / PCI-DSS / Zero-Trust posture narrative (language).",
     "example_output": "## Executive summary\\nThe estate has 3 critical cross-tool exposures..."},
    {"key": "intake", "label": "Change intake", "kind": "ai_capability",
     "description": "Extract a structured rule from free-text change requests (language to structure).",
     "example_output": '{"source": "10.0.0.0/8", "destination": "app-07", "service": "tcp/443"}'},
    {"key": "authoring", "label": "Connector authoring", "kind": "ai_capability",
     "description": "Propose a declarative SourceProfile from a sample export (bring-your-own source).",
     "example_output": '{"tool": "panos", "field_map": {...}}'},
    {"key": "entity_suggest", "label": "Entity-merge suggestions", "kind": "ai_capability",
     "description": "Embedding-based suggestions of duplicate assets for human review (never auto-merge).",
     "example_output": '[{"a": "appsrv-07", "b": "app-server-07", "confidence": 0.92}]'},
    {"key": "assistant", "label": "Ask the network", "kind": "ai_capability",
     "description": "Tool-calling assistant that answers questions grounded in engine facts.",
     "example_output": "Yes — the internet can reach db-prod-01 via lb-public-01 -> app-server-07."},
    {"key": "embed", "label": "Embeddings", "kind": "ai_capability",
     "description": "Vector embeddings used by entity-resolution suggestions (local nomic-embed).",
     "example_output": "[0.012, -0.044, ...] (768-dim vector)"},
]

TOOLS_BY_KEY = {t["key"]: t for t in TOOLS}
ALL_ROLES = ["admin", "analyst", "viewer"]

# tiny TTL cache so per-tool enforcement doesn't hit the DB on every agent call
_CACHE: dict = {"at": 0.0, "map": {}}
_TTL = 5.0


def _settings_map() -> dict[str, list[str]]:
    now = time.monotonic()
    if now - _CACHE["at"] < _TTL:
        return _CACHE["map"]
    m: dict[str, list[str]] = {}
    try:
        with get_conn() as conn, conn.cursor() as cur:
            for row in fetch_all(cur, "SELECT tool_key, enabled_roles FROM ztpa.tool_settings"):
                m[row["tool_key"]] = list(row.get("enabled_roles") or [])
    except Exception:
        m = _CACHE["map"]  # keep last-known on DB hiccup
    _CACHE.update(at=now, map=m)
    return m


def invalidate_cache() -> None:
    _CACHE.update(at=0.0)


def enabled_roles(key: str) -> list[str]:
    """Roles a tool is enabled for. Absent row -> all roles (default-on)."""
    return _settings_map().get(key, list(ALL_ROLES))


def enabled_for(role: str, key: str) -> bool:
    if key not in TOOLS_BY_KEY:
        return True  # unknown keys aren't gated
    return role in enabled_roles(key)


def is_enabled(key: str) -> bool:
    """Whether the tool is enabled for the CURRENT request's role."""
    return enabled_for(request_ctx.role(), key)
