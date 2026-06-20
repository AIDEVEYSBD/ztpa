"""Switchable demo datasets ("scenarios"). Each writes the three simulated tool
exports to data/mock/, so the engine + dashboard can demo different cases:

  demo        the 5 planted problems incl. one cross-tool path (default)
  multi_path  TWO cross-tool paths to two regulated DBs (shows multi-path handling)
  clean       internal-only policy, no findings (the "all good" / empty state)
  scale       demo + N synthetic assets (stress the graph + engine)

Builders reuse seed_demo so the canonical demo stays the single source of truth.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import seed_demo  # noqa: E402

MOCK_DIR = seed_demo.MOCK_DIR

SCENARIOS = [
    {"id": "demo", "label": "Planted demo", "description": "5 planted problems + one cross-tool path (~25 assets)"},
    {"id": "multi_path", "label": "Multiple paths", "description": "Two cross-tool paths to two regulated databases"},
    {"id": "clean", "label": "Clean estate", "description": "Internal-only policy, no findings (empty state)"},
    {"id": "scale", "label": "At scale", "description": "Demo + synthetic assets (default 500)"},
]


def _write(algo: dict, gc: dict, wiz: dict) -> None:
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    (MOCK_DIR / "algosec_export.json").write_text(json.dumps(algo, indent=2) + "\n")
    (MOCK_DIR / "guardicore_export.json").write_text(json.dumps(gc, indent=2) + "\n")
    (MOCK_DIR / "wiz_export.json").write_text(json.dumps(wiz, indent=2) + "\n")


def _demo():
    _write(seed_demo.algosec_export(), seed_demo.guardicore_export(), seed_demo.wiz_export())


def _multi_path():
    a, g, w = seed_demo.algosec_export(), seed_demo.guardicore_export(), seed_demo.wiz_export()
    # Second regulated DB reachable by a *different* cross-tool chain:
    # internet -> lb-public-02 (Wiz) -> app-server-08 (Wiz) -> data-segment (Guardicore) -> db-prod-02 (AlgoSec)
    a["objects"]["db-prod-02"] = {"type": "host", "value": "10.50.0.30", "tags": ["pci", "customer-data", "prod"]}
    a["objects"]["data-segment"] = {"type": "network", "value": "10.45.0.0/16", "tags": ["prod", "data-segment"]}
    a["rules"].append({"rule_id": "ALGO-031", "order": 31, "src": "data-segment", "dst": "db-prod-02",
                       "service": "tcp/5432", "action": "allow", "comment": "data segment to prod db-02"})
    g["labels"]["data-segment"] = {"role": "segment", "env": "prod", "tags": ["prod", "data-segment"]}
    g["policies"].append({"policy_id": "GC-002", "src_label": "app-server-08", "dst_label": "data-segment",
                          "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "app-east-west"})
    _write(a, g, w)


def _clean():
    a = {"vendor": "AlgoSec", "export_type": "firewall_policy", "device": "afa-edge-fw-01", "objects": {
        "app-server-01": {"type": "host", "value": "10.30.1.1", "tags": ["prod"]},
        "app-server-02": {"type": "host", "value": "10.30.1.2", "tags": ["prod"]},
    }, "rules": [
        {"rule_id": "C-001", "order": 1, "src": "10.30.0.0/24", "dst": "app-server-01", "service": "tcp/443", "action": "allow"},
        {"rule_id": "C-002", "order": 2, "src": "10.30.0.0/24", "dst": "app-server-02", "service": "tcp/443", "action": "allow"},
    ]}
    g = {"vendor": "Guardicore (Akamai)", "export_type": "segmentation_policy",
         "labels": {"app-server-01": {"role": "app", "env": "prod", "tags": ["prod"]},
                    "web-tier": {"role": "web", "env": "prod", "tags": ["prod"]}},
         "policies": [{"policy_id": "GC-001", "src_label": "web-tier", "dst_label": "app-server-01",
                       "port": 443, "protocol": "tcp", "action": "allow", "ruleset": "tiering"}]}
    w = {"vendor": "Wiz", "export_type": "cloud_exposure",
         "assets": {"app-server-01": {"cloud": "aws", "type": "ec2", "internet_facing": False, "ip": "10.30.1.1", "tags": ["prod"]}},
         "exposures": []}
    _write(a, g, w)


def _scale(n: int = 500):
    a, g, w = seed_demo.algosec_export(), seed_demo.guardicore_export(), seed_demo.wiz_export()
    for i in range(n):
        host = f"svc-{i:05d}"
        a["objects"][host] = {"type": "host", "value": f"10.200.{(i // 254) % 254}.{(i % 254) + 1}", "tags": ["prod"]}
        a["rules"].append({"rule_id": f"SCALE-{i:05d}", "order": 2000 + i,
                           "src": f"10.201.{(i // 254) % 254}.0/24", "dst": host,
                           "service": "tcp/443", "action": "allow", "comment": "synthetic"})
    _write(a, g, w)


_BUILDERS = {"demo": _demo, "multi_path": _multi_path, "clean": _clean, "scale": _scale}


def write_scenario(scenario: str, n: int = 500) -> None:
    fn = _BUILDERS.get(scenario)
    if fn is None:
        raise ValueError(f"unknown scenario: {scenario}")
    if scenario == "scale":
        fn(n)
    else:
        fn()
