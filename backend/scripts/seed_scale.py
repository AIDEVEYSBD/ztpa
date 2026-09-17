#!/usr/bin/env python3
"""Scale-test dataset: the flagship demo grown on BOTH axes, so you can see how
the engine and the map behave at hundreds or thousands of assets.

  python backend/scripts/seed_scale.py 1000   # 1,000 synthetic assets + 250 branch sites
  python backend/scripts/precompute.py        # rebuild the snapshot (then refresh the UI)
  python backend/scripts/seed_demo.py         # ...no. See "RESTORING", below.

One number grows both halves: `n` synthetic policy assets AND `n / 4` branch
sites projected through all seven infrastructure consoles. The planted problems
survive -- both cross-tool paths are still found, and the ranked list still
collapses to the same handful of actions -- which is the whole claim: ranking is
grouping by root cause, so it does not grow with the estate.

WHY THIS IS A SIX-LINE WRAPPER NOW
----------------------------------
It used to build the dataset itself and write it with three bare `write_text`
calls -- the exact non-atomic pattern `scenarios._swap` exists to eliminate, and
the one the module docstring over there calls the dangerous failure rather than a
loud one. It also wrote only the three POLICY exports, so running it left
whatever infrastructure the last scenario had written: 500 synthetic rules beside
a thirteen-device topology, which is the defect that made "At scale" never reach
the picture. Both are fixed by not having a second implementation at all.

RESTORING
---------
    python backend/scripts/seed_demo.py

...which now writes all ten exports through the same scenario writer, so it
genuinely restores the demo rather than leaving the branch topology on disk
beside the demo rulebase.

⚠ SIMULATED DATA, like everything else under data/mock.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scenarios import write_scenario  # noqa: E402


def main(n: int) -> int:
    write_scenario("scale", n)
    print(f"wrote the scale dataset: the demo rulebase + {n} synthetic assets, "
          f"and the estate grown to {n // 4} branch sites.")
    print("next: python backend/scripts/precompute.py  (then refresh the UI)")
    print("restore: see the RESTORING note in this script's docstring.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 1000))
