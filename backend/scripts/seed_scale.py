"""Scale-test dataset: the real demo seed PLUS N synthetic assets + rules, so you
can see how the engine and the map behave at hundreds / thousands of assets.

  python scripts/seed_scale.py 1000     # base demo + 1000 synthetic assets
  python scripts/precompute.py           # rebuild the snapshot (then refresh the UI)
  python scripts/seed_demo.py            # restore the clean ~25-asset demo

The 5 planted problems (incl. the cross-tool path) are preserved, so the hero
story still works while the dataset is large.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from seed_demo import MOCK_DIR, algosec_export, guardicore_export, wiz_export  # noqa: E402


def main(n: int) -> None:
    algo = algosec_export()
    for i in range(n):
        host = f"svc-{i:05d}"
        algo["objects"][host] = {"type": "host", "value": f"10.200.{(i // 254) % 254}.{(i % 254) + 1}", "tags": ["prod"]}
        algo["rules"].append({
            "rule_id": f"SCALE-{i:05d}", "order": 2000 + i,
            "src": f"10.201.{(i // 254) % 254}.0/24", "dst": host,
            "service": "tcp/443", "action": "allow", "comment": "synthetic scale-test rule",
        })
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    (MOCK_DIR / "algosec_export.json").write_text(json.dumps(algo, indent=2) + "\n")
    (MOCK_DIR / "guardicore_export.json").write_text(json.dumps(guardicore_export(), indent=2) + "\n")
    (MOCK_DIR / "wiz_export.json").write_text(json.dumps(wiz_export(), indent=2) + "\n")
    print(f"wrote scale dataset: base demo + {n} synthetic assets/rules.")
    print("next: python scripts/precompute.py  (then refresh the UI; restore with seed_demo.py)")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 1000)
