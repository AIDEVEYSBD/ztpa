"""Cache the AI-derived artifacts so the live demo is instant + DB-backed:
ranked actions, the two demo change decisions, and (optionally) all explanations.

Usage:  python scripts/precompute_ai.py [--explanations]
The deterministic snapshot (scripts/precompute.py) must have run first.
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
    with get_conn() as conn, conn.cursor() as cur:
        persist_engine_result(cur, r)  # ensure the deterministic snapshot exists
        ranked = rank(r.findings)
        persist_ranked_actions(cur, r.snapshot_id, ranked)
        print(f"ranked_actions: {len(ranked.actions)} (ranked_by={ranked.ranked_by})")
        for req in DEMO_REQUESTS.values():
            delta = simulate_change(r.records, r.assets, r.alias_map, req.proposed)
            decision = classify_change(req, delta)
            persist_change_decision(cur, r.snapshot_id, req, decision)
            print(f"decision {req.id}: {decision.decision} (by={decision.decided_by})")
        if warm_explanations:
            for f in r.findings:
                cache_explanation(cur, f.id, explain(f)["explanation"])
            print(f"explanations cached: {len(r.findings)}")
    print(f"precompute_ai done for {r.snapshot_id}")


if __name__ == "__main__":
    main(warm_explanations="--explanations" in sys.argv)
