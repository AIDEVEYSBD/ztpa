"""Single source of truth for every tool / AI capability the app exposes, plus
the per-role enable/disable layer the admin Tools screen drives.

Two kinds of entry, and the difference decides what an outage costs:
  - agent_tool   : a deterministic engine tool the assistant may call. Free,
                   local, and the thing an operator needs in order to look at
                   the estate while diagnosing an incident.
  - ai_capability: an LLM/embedding job (explain, rank, classify, ...). Every
                   one of these SPENDS -- money, tokens, and a third party's
                   view of the estate.

Enablement is per-role, stored in ztpa.tool_settings (a row's enabled_roles
array). An absent row means enabled for all roles (default-on), so the Tools
screen is an opt-out toggle rather than a setup step. The current request's role
comes from request_ctx (set by the proxy-injected header).

WHAT "FAIL-CLOSED" HAS TO MEAN, AND THE THREE TIMES IT DID NOT
--------------------------------------------------------------
This layer is the admin Tools screen's kill switch: turning `rank` off is how an
operator stops a runaway model spend, and turning `assistant` off is how they
stop the estate being narrated to a model at all. A kill switch that a fault can
undo is not a kill switch, and this one has been undone three times.

FIRST BUG -- a failed read cached as a successful one:

    except Exception:
        m = _CACHE["map"]          # {} on a cold process
    _CACHE.update(at=now, map=m)   # ...cached as if it had been READ

`{}` means "no row for this tool", and no row means ALL_ROLES, so the first
query failure on a fresh worker turned every capability on for every role and
refreshed the timestamp so the failure looked like a read. Fixed by returning a
`trusted` bit alongside the map: "the settings say every role" and "we do not
know what the settings say" are different answers.

SECOND BUG -- unknown resolved to admin-ON. The first fix sent the unknown state
to a single constant, `FAIL_CLOSED_ROLES = ["admin"]`, conflating two unrelated
needs: an operator must keep the DIAGNOSTIC surface during an outage, but nobody
needs to keep SPENDING during one. Because /api/actions/recompute is admin-only,
/api/report is admin-reachable and /api/actions spawns a background rank, that
carve-out made the `rank` kill switch fully bypassable by whoever could reach it
-- and the read fails on a partial outage (a renamed table, a revoked grant, a
migration in flight) while the rest of the API is perfectly healthy. Verified end
to end against a real Postgres: `rank` durably `{}` for every role plus an
unreadable ztpa.tool_settings produced three model calls on one admin session.

So the unknown state now resolves per KIND (see UNKNOWN_SPEND_ROLES /
UNKNOWN_TOOL_ROLES): no ai_capability for anyone, admin included, while the
deterministic agent tools stay available to admin. Nothing in the diagnostic path
goes through here at all -- GET /api/admin/tools, /api/health and every read of
the estate are gated by role, not by capability -- so a fail-closed spend layer
costs an operator nothing they need to see the outage.

THIRD BUG -- a durable disable undone by a stale map. `invalidate_cache()` cleared
only the timestamp, keeping map/loaded, so: admin disables `rank` (the row really
is written), the next read fails, and the PRE-disable map is served indefinitely
-- for every role, not just admin. Two things close that. A successful toggle is
now applied into the in-process map (`apply_setting`), so the map a failed read
degrades to already contains the disable; and a map that cannot be refreshed
decays to the unknown answer after `_MAX_STALE`, which is the only thing that
bounds the same hole in a SECOND worker, whose cache the toggle never reached.
Decay can only ever take access away: the stale map is intersected with the
unknown answer, never replaced by it.

Between a blip and that bound, the last-known-good map is served: dropping every
analyst to fail-closed over one dropped connection would be its own outage, and
the answer is genuinely known, just stale.

The consequence is deliberate and worth stating plainly: while the settings are
UNKNOWN -- never read on this worker, or unreadable for longer than `_MAX_STALE`
after the last successful read -- NO role, admin included, gets an ai_capability,
and no non-admin gets an agent tool either.

So breaking the store no longer re-enables anything, and the residual window is
stated rather than hidden: the most an outage can buy is `_MAX_STALE` seconds of
an already-read map in a worker the toggle never reached (render.yaml runs one
worker today, so in the deployed shape apply_setting closes even that), after
which every ai_capability is off for every role."""

from __future__ import annotations

import logging
import time

from . import request_ctx
from .db import fetch_all, get_conn

# A child of the API's logger, so a settings-read failure comes out as one JSON
# line with the request id already attached (app/main.py configures "npr.api").
# The audit's Phase 2 criterion names this exact site: "a structured log line
# with a request id exists for every currently-silent degradation ...
# tools_registry cache miss". It used to be a bare `except Exception: pass`.
log = logging.getLogger("npr.api.tools")

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
     "description": "Draft a fix-as-code in a propose/re-simulate/revise loop, proven by the engine.",
     "example_output": '{"fix_text": "Scope rule R-12 source to 10.20.5.0/24", "validation": {"resolves": true}}'},
    {"key": "campaign", "label": "Remediation campaign", "kind": "ai_capability",
     "description": "Plan a worst-first remediation campaign across all findings, driving the critical count to zero.",
     "example_output": '{"criticals_trajectory": [5, 3, 1, 0], "applied_count": 3, "cleared_all_criticals": true}'},
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

# What an UNKNOWN settings table resolves to. TWO constants, not one, because
# the single `FAIL_CLOSED_ROLES = ["admin"]` this replaces conflated "an operator
# must be able to diagnose the outage" with "an operator may keep spending
# through it". Only the second is a kill switch's business.
#
#   ai_capability -> nobody, admin included. Unknown must not resolve to spend,
#     and the admin routes are exactly the ones that CAN spend (recompute is
#     admin-only), so exempting admin exempted the whole attack.
#   agent_tool    -> admin. Deterministic, free, local: this is the operator
#     looking at the graph while working out why the settings table is gone.
#     (In practice the assistant that calls them is an ai_capability and is off,
#     so this is a floor, not a hole.)
UNKNOWN_SPEND_ROLES: list[str] = []
UNKNOWN_TOOL_ROLES: list[str] = ["admin"]

# tiny TTL cache so per-tool enforcement doesn't hit the DB on every agent call.
#   at      : when the last read was ATTEMPTED (drives the TTL back-off, and is
#             bumped by a failure too -- a per-request connect against a dead
#             database is its own denial of service).
#   read_at : when a read last SUCCEEDED. Only this one ages the map.
#   loaded  : has any read ever succeeded. The bit that separates "the settings
#             say every role" from "we have never managed to read the settings".
_CACHE: dict = {"at": 0.0, "map": {}, "loaded": False, "read_at": 0.0}
_TTL = 5.0
# How long a map that cannot be refreshed may still be served before it decays to
# the unknown answer. Longer than _TTL by a wide margin so a dropped connection
# costs nobody anything; short enough that "keep ztpa.tool_settings unreadable"
# is not a way to keep a killed capability alive. It is also the only bound on
# the stale map of a worker that never saw the toggle -- apply_setting fixes the
# process that served the POST, not its siblings.
_MAX_STALE = 60.0


def _trusted(now: float) -> bool:
    """Whether the cached map may still be believed: read at least once, and read
    recently enough. `read_at` is deliberately NOT bumped by a failed attempt, so
    a database that stays unreadable ages the map out even though `at` keeps
    moving."""
    return bool(_CACHE["loaded"]) and (now - float(_CACHE.get("read_at") or 0.0)) <= _MAX_STALE


def _settings_map() -> tuple[dict[str, list[str]], bool]:
    """(per-tool enabled_roles, whether that map may be trusted).

    The second element is not a nicety: `{}` is both the answer for "an empty
    tool_settings table" and for "the query raised on a cold process", and those
    two must resolve to opposite defaults."""
    now = time.monotonic()
    # `at` is 0.0 on a cold process and after invalidate_cache(), so both force a
    # read rather than trusting the epoch-relative arithmetic.
    if _CACHE["at"] and now - _CACHE["at"] < _TTL:
        return _CACHE["map"], _trusted(now)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            m = {row["tool_key"]: list(row.get("enabled_roles") or [])
                 for row in fetch_all(cur, "SELECT tool_key, enabled_roles FROM ztpa.tool_settings")}
    except Exception as exc:
        # Back off for one TTL, but do NOT record a default-on map as if it had
        # been read, and do NOT touch read_at: the map is now one attempt older.
        _CACHE.update(at=now)
        trusted = _trusted(now)
        log.warning("per-role tool settings could not be read; capabilities resolve to %s",
                    "the last successful read" if trusted else "the fail-closed default (no AI spend)",
                    exc_info=True, extra={"event": "tool_settings_read_failed",
                                          "error": str(exc), "have_last_known": trusted,
                                          "stale_seconds": round(now - float(_CACHE.get("read_at") or 0.0), 1)
                                          if _CACHE["loaded"] else None})
        return _CACHE["map"], trusted
    _CACHE.update(at=now, map=m, loaded=True, read_at=now)
    return m, True


def invalidate_cache() -> None:
    """Force the next lookup to re-read. Clears the timestamp only: what has been
    read stays known, so an invalidation followed by a failed read serves the
    last-known-good map (until _MAX_STALE) rather than locking everyone out."""
    _CACHE.update(at=0.0)


def apply_setting(key: str, roles: list[str]) -> None:
    """Record a just-PERSISTED toggle in this process's map, then re-read.

    Called by the admin Tools route after the row is committed. Invalidating
    alone was not enough and was the third bug in the module docstring: the very
    next read can fail, and the map it then falls back on was the PRE-toggle one,
    so breaking the store reverted a disable an operator had successfully made --
    for every role. The new value is right there at the call site, so write it in
    and let the fallback map already contain it.

    `loaded` is deliberately left alone. A successful write proves the row for
    ONE key, not the whole table, and flipping `loaded` here would turn every
    other capability default-on for a process that has never read the settings."""
    _CACHE["map"] = {**_CACHE["map"], key: list(roles)}
    invalidate_cache()


def _unknown_roles(key: str) -> list[str]:
    """What a key resolves to when the settings are unknown, by kind: no spend for
    anyone on an ai_capability, admin-only on a deterministic agent_tool. An
    unregistered key is not gated at all (see enabled_for), so it never lands
    here; if one somehow does, treat it as the spending kind."""
    return UNKNOWN_TOOL_ROLES if TOOLS_BY_KEY.get(key, {}).get("kind") == "agent_tool" else UNKNOWN_SPEND_ROLES


def enabled_roles(key: str) -> list[str]:
    """Roles a tool is enabled for.

    Trusted map, row present -> what the row says. Trusted map, no row -> all
    roles (default-on). NOT trusted -- never read, or unrefreshable for longer
    than _MAX_STALE -> the fail-closed answer for the kind, INTERSECTED with
    whatever the stale map last said. The intersection is what keeps decay
    one-way: ageing a map out may take a role's access away, never hand it back."""
    m, trusted = _settings_map()
    if trusted:
        return list(m[key]) if key in m else list(ALL_ROLES)
    unknown = _unknown_roles(key)
    stale = m.get(key)
    if stale is None:
        return list(unknown)
    return [r for r in unknown if r in stale]


def enabled_for(role: str, key: str) -> bool:
    if key not in TOOLS_BY_KEY:
        return True  # unknown keys aren't gated
    return role in enabled_roles(key)


def is_enabled(key: str) -> bool:
    """Whether the tool is enabled for the CURRENT request's role."""
    return enabled_for(request_ctx.role(), key)
