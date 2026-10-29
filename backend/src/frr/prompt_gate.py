"""Eval-gated prompt, retrieval and agent tuning (FRR-05.5).

Every model-backed agent has a fingerprint over what was tuned (prompt text,
sampling, retrieval depth and query; `agents.fingerprint`). A configuration is
*evaluated* when the ledger holds a passing narrative evaluation of exactly that
fingerprint. The ledger is committed next to the prompts and written only by

    python -m src.frr.narrative_eval --items 20 --gate --record     # live model calls

which refuses to record a failing run. CI runs the offline check

    python -m src.frr.prompt_gate                                     # no model calls

so a prompt or retrieval change cannot merge without an evaluation of it. Model
calls stay out of CI (they cost money and need cloud credentials); what CI holds
is that the evaluation was done and passed, on which models, and when.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import agents

LEDGER = Path(__file__).with_name("prompts") / "eval-ledger.json"
# Distinct models (provider:model) a fingerprint must have passed on. We ship on
# GCP (Vertex) and Azure (AI Foundry); raise to 2 to require both.
MIN_MODELS = int(os.environ.get("NPR_PROMPT_GATE_MIN_MODELS", "1"))
# Fields of an evaluation kept in the ledger (the rest is per-item detail).
KEPT = ("items", "fallback_rate", "ungrounded_rate", "contradictions", "citation_rate",
        "owner_question_rate_on_narrowing", "package_summary")


def evaluated_agents() -> list[str]:
    return [a.key for a in agents.AGENTS if a.prompt]


def load() -> list[dict]:
    try:
        return json.loads(LEDGER.read_text())["evaluations"]
    except FileNotFoundError:
        return []


def record(metrics: dict, *, path: Path = LEDGER) -> dict:
    """Append a passing evaluation; refuse a failing one."""
    failures = metrics.get("gate", {}).get("failures")
    if failures is None:
        raise ValueError("the evaluation was not gated; run with --gate")
    if failures:
        raise ValueError(f"a failing evaluation is not recorded: {'; '.join(failures)}")
    entry = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "model": metrics["model"],
             "fingerprints": metrics["fingerprints"], "thresholds": metrics["gate"]["thresholds"],
             "metrics": {k: metrics[k] for k in KEPT if k in metrics}}
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        doc = {"evaluations": []}
    doc["evaluations"].append(entry)
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return entry


def status(ledger: list[dict] | None = None) -> dict[str, dict[str, Any]]:
    """Per agent: running fingerprint, whether it is evaluated, and on what."""
    ledger = load() if ledger is None else ledger
    out = {}
    for key in evaluated_agents():
        fp = agents.fingerprint(key)
        runs = [e for e in ledger if e["fingerprints"].get(key) == fp and e.get("model")]
        models = sorted({e["model"] for e in runs})
        out[key] = {"fingerprint": fp, "evaluated": len(models) >= MIN_MODELS, "models": models,
                    "last_evaluated": max((e["at"] for e in runs), default=None)}
    return out


def main(argv=None) -> int:
    st = status()
    print(json.dumps(st, indent=2))
    missing = [k for k, v in st.items() if not v["evaluated"]]
    if missing:
        print(f"\nnot evaluated: {', '.join(st[k]['fingerprint'] for k in missing)} "
              f"(needs a passing evaluation on {MIN_MODELS} model(s)). Run\n"
              "  python -m src.frr.narrative_eval --items 20 --gate --record\n"
              "against each provider and commit src/frr/prompts/eval-ledger.json.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
