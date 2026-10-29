"""The five FRR agents and the orchestrator that hands work between them (FRR-02.1).

    orchestrator               runs the steps below in order, records each
                               step's output in ztpa.frr_runs, owns retries
    1. export intake parser    the accepted export's parsed rulebase (intake.py
                               already parsed and validated it at upload)
    2. effective-policy checker  the deterministic register (review.py)
    3. risk & impact assessor  per-item IMPACT NARRATIVE from the model, grounded
                               in the item's evidence and retrieved standards /
                               runbooks; deterministic fallback text otherwise
    4. change-package drafter  the deterministic package (package.py), stored for
                               review (workflow.py), plus an executive summary

MODEL POLICY (FRR-02.4): steps 1, 2 and the package CONTENTS of step 4 are
deterministic. The model writes prose only, through a schema with no field that
could carry a band, proposal, command or impact -- so it cannot change one. Its
output is validated (pydantic), its citations must be chunks it was actually
given, and any failure falls back to deterministic text labelled as such. The
prompt file and its sha256 are recorded with every narrative (versioned prompts).

COST AND SCALE: model narratives are written for the top NPR_FRR_NARRATE_TOP
items by severity (default 40); the rest get the deterministic rationale. A
5,000-rule review therefore costs ~41 model calls, not 5,000.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, ValidationError, field_validator

from .. import request_ctx, storage
from ..advisory.client import complete, parse_json
from ..jobs import JobContext, handler
from . import knowledge, package as package_mod, workflow

log = logging.getLogger("npr.api.frr_agents")

NARRATE_TOP = int(os.environ.get("NPR_FRR_NARRATE_TOP", "40"))
# Concurrent model calls per run. Bounded so one run cannot exhaust the
# provider's quota; the per-deployment API rate limit does not apply to jobs.
NARRATE_PARALLEL = int(os.environ.get("NPR_FRR_NARRATE_PARALLEL", "6"))
_PROMPTS = Path(__file__).with_name("prompts")

# What shapes a narrative besides the prompt. Part of each agent's fingerprint
# (see `fingerprint`), so changing one needs a passing evaluation like a prompt
# change does (src/frr/prompt_gate.py).
RETRIEVAL_K = 3                # knowledge excerpts retrieved per item
EXCERPT_CHARS = 900            # of each excerpt shown to the model
TEMPERATURE = 0.2
FACTS_CHARS = 12000            # cap on the facts document sent


@dataclass(frozen=True)
class Prompt:
    name: str
    text: str

    @property
    def version(self) -> str:
        return f"{self.name}@{hashlib.sha256(self.text.encode()).hexdigest()[:12]}"


def agent_prompt(agent: str) -> Prompt:
    """The prompt an agent runs with, from the registry (one place to change it)."""
    return prompt(next(a.prompt for a in AGENTS if a.key == agent and a.prompt))


def fingerprint(agent: str) -> str:
    """`agent@hash` over everything tuned for a model-backed agent: prompt text,
    sampling, and for the impact assessor retrieval depth, excerpt size and the
    retrieval query builder (part of its behaviour). Equal fingerprints mean the
    evaluated configuration is the one running."""
    p = agent_prompt(agent)
    knobs = {"temperature": TEMPERATURE, "facts_chars": FACTS_CHARS}
    if agent == "impact_assessor":
        knobs |= {"retrieval_k": RETRIEVAL_K, "excerpt_chars": EXCERPT_CHARS,
                  "query": inspect.getsource(_query_for)}
    blob = json.dumps({"prompt": p.text, **knobs}, sort_keys=True)
    return f"{agent}@{hashlib.sha256(blob.encode()).hexdigest()[:12]}"


def prompt(name: str) -> Prompt:
    return Prompt(name, (_PROMPTS / f"{name}.md").read_text())


@dataclass(frozen=True)
class Agent:
    key: str
    role: str
    model: str          # "deterministic" | "llm-narrative"
    prompt: Optional[str] = None


AGENTS = (
    Agent("orchestrator", "sequences the agents, records each handoff, owns retries", "deterministic"),
    Agent("intake_parser", "parsed, validated rulebase from the accepted export", "deterministic"),
    Agent("policy_checker", "effective policy and the deterministic rule-risk register", "deterministic"),
    Agent("impact_assessor", "availability and business impact narrative per item", "llm-narrative", "impact.v1"),
    Agent("package_drafter", "change package with rollback, plus its executive summary",
          "deterministic + llm-narrative", "package.v2"),
)


# --- validated model output ---------------------------------------------------------
class ImpactNarrative(BaseModel):
    summary: str = Field(..., min_length=1, max_length=600)
    availability_note: str = Field("", max_length=500)
    owner_questions: list[str] = Field(default_factory=list, max_length=5)
    cites: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("owner_questions")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        return [q[:240] for q in v if q.strip()]


class PackageNarrative(BaseModel):
    summary: str = Field(..., min_length=1, max_length=1100)
    key_risks: list[str] = Field(default_factory=list, max_length=5)
    limitations_note: str = Field("", max_length=500)


def _fallback_impact(item: dict) -> dict:
    return {"summary": item["rationale"],
            "availability_note": {"none": "The rule matches no traffic today; removing it changes nothing.",
                                  "possible": "Hit counts can miss seasonal or failover traffic; confirm before removal.",
                                  "likely": "The rule carries traffic; the narrowed rule must keep what is legitimate.",
                                  "changes_behaviour": "Traffic currently allowed will be blocked by this change."
                                  }.get(item["availability_impact"], ""),
            "owner_questions": [], "cites": [], "by": "engine_fallback"}


def _query_for(item: dict) -> str:
    ev = item.get("evidence") or {}
    terms = [item["check"].replace("_", " ").replace("+", " "), item["proposal"].replace("_", " "),
             str(ev.get("port_name") or ""), str(ev.get("service") or ""), str(ev.get("src_zone") or ""),
             "firewall rule", "change", "rollback"]
    return " ".join(t for t in terms if t)


def assess_item(item: dict, context: list[dict], p: Prompt,
                llm: Optional[Callable[..., Any]] = None) -> dict:
    """One item's narrative: model output validated against the schema and the
    retrieved citations, or the deterministic fallback."""
    facts = {"item": {k: item[k] for k in ("rule_number", "rule_name", "layer", "check", "band", "proposal",
                                             "availability_impact", "rationale", "requires_owner_input")}
                     | {"evidence": {k: v for k, v in (item.get("evidence") or {}).items()
                                     if k not in ("severity_vector",)}},
             "context": [{"cite": c["cite"], "kind": c["kind"], "title": c["title"],
                          "heading": c["heading"], "excerpt": c["body"][:EXCERPT_CHARS]} for c in context]}
    r = (llm or complete)(system=p.text, user=json.dumps(facts, default=str)[:FACTS_CHARS], role="prose",
            temperature=TEMPERATURE, expect_json=True, capability="frr_impact",
            subject=f"{item['layer']}#{item['rule_number']}")
    if not getattr(r, "ok", False):
        return _fallback_impact(item) | {"fallback_reason": getattr(r, "error", None) or "model unavailable"}
    try:
        out = ImpactNarrative.model_validate(parse_json(r.text, {}))
    except ValidationError as e:
        return _fallback_impact(item) | {"fallback_reason": f"schema: {e.errors()[0]['msg']}"}
    allowed = {c["cite"] for c in context}
    if any(c not in allowed for c in out.cites):
        # A citation the model was not given is an invented source.
        return _fallback_impact(item) | {"fallback_reason": "cited a source it was not given"}
    return out.model_dump() | {"by": f"{r.provider}:{r.model}", "prompt": p.version}


def summary_stats(drafted: dict) -> dict:
    """The package counts under names that cannot be mistaken for each other: a
    bare `items` was summarised as "183 rules analysed" for 400 rules reviewed."""
    s = drafted["summary"]
    out = {"proposed_changes": s["items"],
           "proposed_changes_by_availability_impact": s["by_impact"],
           "proposed_changes_by_proposal": s["by_proposal"]}
    if s.get("rules_reviewed") is not None:               # packages drafted before it was recorded
        out = {"rules_reviewed": s["rules_reviewed"], **out}
    return out


def summarise_package(drafted: dict, p: Prompt, llm: Optional[Callable[..., Any]] = None) -> dict:
    top = [{k: i[k] for k in ("rule_number", "check", "band", "proposal", "availability_impact", "rationale")}
           for i in drafted["items"][:10]]
    facts = {"stats": summary_stats(drafted), "top_items": top, "limitations": drafted["limitations"][:20]}
    r = (llm or complete)(system=p.text, user=json.dumps(facts, default=str)[:FACTS_CHARS], role="prose",
            temperature=TEMPERATURE, expect_json=True, capability="frr_package")
    if getattr(r, "ok", False):
        try:
            out = PackageNarrative.model_validate(parse_json(r.text, {}))
            return out.model_dump() | {"by": f"{r.provider}:{r.model}", "prompt": p.version}
        except ValidationError:
            pass
    s = drafted["summary"]
    return {"summary": f"{s['items']} proposed changes. By availability impact: "
                       f"{', '.join(f'{k} {v}' for k, v in sorted(s['by_impact'].items()))}.",
            "key_risks": [f"rule {i['rule_number']}: {i['check']} ({i['band']})" for i in top[:5]],
            "limitations_note": "; ".join(drafted["limitations"][:3]), "by": "engine_fallback"}


# --- the orchestrator ------------------------------------------------------------------
def _step(cur, run_id: str, agent: str, status: str, **detail) -> None:
    entry = {"agent": agent, "status": status, "at": datetime.now(timezone.utc).isoformat(), **detail}
    cur.execute("UPDATE ztpa.frr_runs SET steps = steps || %s::jsonb WHERE run_id = %s",
                [json.dumps([entry], default=str), run_id])


@handler("frr.review_run", heavy=True)
def review_run(ctx: JobContext, *, llm: Optional[Callable[..., Any]] = None) -> dict:
    """Runs as the person who started the run: the package and its audit rows
    are theirs (as agent work on their behalf), not unattributed."""
    with ctx.conn.cursor() as cur:
        # The run records the starter's sub (an opaque id under SSO); their email,
        # when the user directory knows them, is what a reader recognises.
        cur.execute("""SELECT r.created_by, u.email FROM ztpa.frr_runs r
                         LEFT JOIN ztpa.app_users u ON u.sso_sub = r.created_by
                        WHERE r.run_id = %s""", [ctx.payload["run_id"]])
        row = cur.fetchone() or {}
    with request_ctx.acting_as(sub=row.get("created_by"), email=row.get("email")):
        return _review_run(ctx, llm=llm)


def _review_run(ctx: JobContext, *, llm: Optional[Callable[..., Any]] = None) -> dict:
    run_id = ctx.payload["run_id"]
    cur = ctx.conn.cursor()
    cur.execute("SELECT r.*, e.status AS export_status, e.parsed_key, e.review_key "
                "FROM ztpa.frr_runs r JOIN ztpa.exports e USING (export_id) WHERE r.run_id = %s", [run_id])
    run = cur.fetchone()
    if run is None:
        return {"skipped": "run no longer exists"}
    # Idempotent restart: a reclaimed job starts the run over from a clean slate.
    cur.execute("UPDATE ztpa.frr_runs SET status = 'running', steps = '[]'::jsonb WHERE run_id = %s", [run_id])
    _step(cur, run_id, "orchestrator", "started", agents=[a.key for a in AGENTS])

    if run["export_status"] != "accepted":
        _step(cur, run_id, "intake_parser", "refused", reason=f"export is {run['export_status']}")
        cur.execute("UPDATE ztpa.frr_runs SET status = 'failed', finished_at = now() WHERE run_id = %s", [run_id])
        return {"status": "failed", "reason": f"export is {run['export_status']}"}

    store = storage.store()
    parsed = json.loads(store.get_bytes(run["parsed_key"]))
    _step(cur, run_id, "intake_parser", "done", rules=parsed["summary"]["rules"],
          grants=parsed["summary"]["grants"], limitations=len(parsed["limitations"]))
    review = json.loads(store.get_bytes(run["review_key"]))
    _step(cur, run_id, "policy_checker", "done", **{k: review["stats"][k] for k in
                                                    ("rules_with_findings", "by_band")})
    ctx.check()

    drafted = package_mod.draft(review, parsed)
    from . import context
    ctx_counts = context.enrich_package(cur, drafted, parsed)
    _step(cur, run_id, "impact_assessor", "context", **ctx_counts)
    impact_prompt, pkg_prompt = agent_prompt("impact_assessor"), agent_prompt("package_drafter")
    narratives: dict[str, dict] = {}
    narrated = fallbacks = 0
    # Retrieval first, in order: it uses this job's one database cursor. Then the
    # model calls in parallel, bounded: they are I/O (seconds each on a large
    # model), and run one by one a 40-item package took minutes. Results are
    # collected by item id, so ordering and outcome do not depend on timing.
    from concurrent.futures import ThreadPoolExecutor, as_completed
    top = drafted["items"][:NARRATE_TOP]
    for item in drafted["items"][NARRATE_TOP:]:
        narratives[item["item_id"]] = _fallback_impact(item) | {"fallback_reason": "outside top-N"}
    contexts = {item["item_id"]: knowledge.search(cur, _query_for(item), k=RETRIEVAL_K) for item in top}
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, NARRATE_PARALLEL)) as pool:
        futures = {pool.submit(assess_item, item, contexts[item["item_id"]], impact_prompt, llm): item
                   for item in top}
        for fut in as_completed(futures):
            item = futures[fut]
            n = fut.result()                       # assess_item never raises: it falls back
            narratives[item["item_id"]] = n
            narrated += n["by"] != "engine_fallback"
            fallbacks += n["by"] == "engine_fallback"
            done += 1
            if done % 5 == 0:
                ctx.progress(step="impact_assessor", done=done, of=len(top))
                ctx.check()
    _step(cur, run_id, "impact_assessor", "done", prompt=impact_prompt.version,
          fingerprint=fingerprint("impact_assessor"), narrated=narrated,
          fallbacks=fallbacks, deterministic=max(0, len(drafted["items"]) - NARRATE_TOP))

    # Never discard human work: a package an owner has started deciding, or one
    # past draft, is not superseded by a re-run.
    cur.execute("""SELECT p.package_id, p.status,
                          (SELECT count(*) FROM ztpa.change_package_items i
                            WHERE i.package_id = p.package_id AND i.owner_decision IS NOT NULL) AS decided
                     FROM ztpa.change_packages p
                    WHERE p.export_id = %s AND p.status <> 'superseded'""", [run["export_id"]])
    live = cur.fetchone()
    if live and (live["status"] != "draft" or live["decided"]):
        reason = (f"package {live['package_id']} for this export is already under review "
                  f"({live['status']}, {live['decided']} item(s) decided); not replaced")
        _step(cur, run_id, "package_drafter", "refused", reason=reason)
        cur.execute("UPDATE ztpa.frr_runs SET status = 'failed', finished_at = now() WHERE run_id = %s",
                    [run_id])
        return {"status": "failed", "reason": reason}
    pkg = workflow.create(cur, str(run["export_id"]), drafted, supersede=True)
    for item_id, n in narratives.items():
        cur.execute("UPDATE ztpa.change_package_items SET narrative = %s WHERE package_id = %s AND item_id = %s",
                    [Jsonb(n), pkg["package_id"], item_id])
    summary = summarise_package(drafted, pkg_prompt, llm)
    cur.execute("UPDATE ztpa.change_packages SET narrative = %s WHERE package_id = %s",
                [Jsonb(summary), pkg["package_id"]])
    _step(cur, run_id, "package_drafter", "done", package_id=str(pkg["package_id"]),
          items=len(drafted["items"]), prompt=pkg_prompt.version,
          fingerprint=fingerprint("package_drafter"), summary_by=summary["by"])
    cur.execute("UPDATE ztpa.frr_runs SET status = 'succeeded', package_id = %s, finished_at = now() "
                "WHERE run_id = %s", [pkg["package_id"], run_id])
    _step(cur, run_id, "orchestrator", "finished")
    return {"status": "succeeded", "package_id": str(pkg["package_id"])}
