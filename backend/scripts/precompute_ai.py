"""Cache the AI-derived artifacts so the live demo is instant + DB-backed:
ranked actions, the two demo change decisions, and (optionally) all explanations.

Usage:  python scripts/precompute_ai.py [--explanations]
The deterministic snapshot (scripts/precompute.py) must have run first.

WHY THE PHASES BELOW ARE SEPARATE. The whole script used to run inside ONE
`with get_conn()` block, so a single pooled connection was held open across every
model call it makes -- one ranking pass, one classification per demo request, and
with `--explanations` one generation per finding (17 on the shipped demo, each up
to `OLLAMA_TIMEOUT` = 600 seconds). Against Neon that is a transaction open for
minutes with nothing happening in it, which is how an idle-in-transaction
connection gets reaped mid-run; against a local Postgres it is one of ten pool
slots held for the duration. The same rule the API now follows applies here, and
for the same reason: COMPUTE with nothing checked out, then write in a short
transaction.

It also fixes a real failure mode of the old shape. Everything was written in one
transaction at the very END, so a model that hung on finding 12 of 17 lost the
ranking and the decisions too -- work that had already succeeded, discarded
because something after it did not.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.advisory.classify_change import classify_change   # noqa: E402
from src.advisory.explain import explain                   # noqa: E402
from src.advisory.rank import rank                          # noqa: E402
from src.analyzers.run_all import run                       # noqa: E402
from src.change.requests import DEMO_REQUESTS               # noqa: E402
from src.change.simulate import simulate_change             # noqa: E402
from src.db import get_conn                                 # noqa: E402
from src.persist import (                                   # noqa: E402
    cache_explanation, persist_change_decision, persist_engine_result, persist_ranked_actions,
)


def main(warm_explanations: bool = False) -> None:
    r = run()

    # 1. the deterministic snapshot must exist before anything can reference it
    #    (ranked_actions and change_requests both carry snapshot_id).
    with get_conn() as conn, conn.cursor() as cur:
        persist_engine_result(cur, r)

    # 2. every model call, with NO connection held.
    ranked = rank(r.findings)
    decisions = []
    for req in DEMO_REQUESTS.values():
        delta = simulate_change(r.records, r.assets, r.alias_map, req.proposed)
        decisions.append((req, classify_change(req, delta)))
    explanations = []
    if warm_explanations:
        for f in r.findings:
            res = explain(f)
            explanations.append((f.id, res["explanation"], res.get("by")))

    # 3. one short transaction for everything they produced.
    with get_conn() as conn, conn.cursor() as cur:
        persist_ranked_actions(cur, r.snapshot_id, ranked)
        print(f"ranked_actions: {len(ranked.actions)} (ranked_by={ranked.ranked_by})")
        for req, decision in decisions:
            persist_change_decision(cur, r.snapshot_id, req, decision)
            print(f"decision {req.id}: {decision.decision} (by={decision.decided_by})")
        for fid, text, by in explanations:
            cache_explanation(cur, fid, text, by)
        if warm_explanations:
            print(f"explanations cached: {len(explanations)}")
    print(f"precompute_ai done for {r.snapshot_id}")


if __name__ == "__main__":
    main(warm_explanations="--explanations" in sys.argv)
