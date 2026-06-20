"""Run the deterministic engine and persist a snapshot to Postgres (ztpa).

This is the demo-proofing step: heavy graph analysis is computed here, ahead of
time, so the live demo depends only on DB reads + robust LLM calls. Deterministic
and re-runnable: the same seed produces the same snapshot id and identical rows.

Usage:  python scripts/precompute.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend root on path

from src.analyzers.run_all import run            # noqa: E402
from src.db import get_conn                       # noqa: E402
from src.persist import persist_engine_result     # noqa: E402


def main(label: str = "seed-demo") -> dict:
    result = run(label)
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, result)
    print("snapshot persisted to ztpa:")
    for k, v in summary.items():
        print(f"  {k:14} {v}")
    return summary


if __name__ == "__main__":
    main()
