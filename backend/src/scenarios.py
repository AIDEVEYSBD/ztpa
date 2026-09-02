"""Switchable demo datasets ("scenarios"). Each writes the three simulated tool
exports to data/mock/, so the engine + dashboard can demo different cases:

  demo        the 5 planted problems incl. one cross-tool path (default)
  multi_path  TWO cross-tool paths to two regulated DBs (shows multi-path handling)
  clean       internal-only policy, no findings (the "all good" / empty state)
  scale       demo + N synthetic assets (stress the graph + engine)

Builders reuse seed_demo so the canonical demo stays the single source of truth.

THE THREE FILES ARE ONE DATASET
-------------------------------
`_write` wrote them with three consecutive `write_text` calls, which is a silent
degradation with no exception anywhere: the engine's only input is these three
files, so a process that dies (or a disk that fills) between the first and the
third leaves a *mixed* estate on disk -- AlgoSec from `scale`, Guardicore and Wiz
from `demo`. Nothing in the pipeline can detect that. `normalize_all` reads three
valid JSON documents, the graph builds, findings come out, and the snapshot is
persisted as authoritative over a topology that never existed. Worse, the
truncation case is invisible even to a human: `write_text` on an existing file
truncates FIRST, so an interruption mid-write leaves a short or empty file rather
than the previous good one.

So the three payloads are serialized in full, written to sibling temp files, and
only then moved into place with `os.replace` -- atomic within a filesystem, and
in the loop's own scope the worst case shrinks from "half a JSON document" to
"one of three files is a version behind", which the log line below names.
`_write` is called by `write_scenario`, which the API calls on every cold engine
build and every recompute; the caller (`app/main.py`) already catches and logs a
failure here, and this module now says which scenario it wrote and, on failure,
which files had already moved.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import seed_demo  # noqa: E402

MOCK_DIR = seed_demo.MOCK_DIR

# Child of the API logger; see advisory/client.py for the convention.
log = logging.getLogger("npr.api.scenarios")

SCENARIOS = [
    {"id": "demo", "label": "Planted demo", "description": "5 planted problems + one cross-tool path (~25 assets)"},
    {"id": "multi_path", "label": "Multiple paths", "description": "Two cross-tool paths to two regulated databases"},
    {"id": "clean", "label": "Clean estate", "description": "Internal-only policy, no findings (empty state)"},
    {"id": "scale", "label": "At scale", "description": "Demo + synthetic assets (default 500)"},
]


def _write(algo: dict, gc: dict, wiz: dict) -> None:
    """Replace the three tool exports as close to atomically as a filesystem allows.

    Serialize everything first (a builder that raises must leave the previous
    dataset untouched, not a third of a new one), write each document to a
    sibling `.tmp` in the SAME directory -- `os.replace` is only atomic within a
    filesystem -- then move them into place. See the module docstring for why a
    partially-written dataset is the dangerous case rather than a loud one.
    """
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    payloads = [
        ("algosec_export.json", json.dumps(algo, indent=2) + "\n"),
        ("guardicore_export.json", json.dumps(gc, indent=2) + "\n"),
        ("wiz_export.json", json.dumps(wiz, indent=2) + "\n"),
    ]
    staged: list[tuple[Path, Path]] = []
    moved: list[str] = []
    try:
        for name, text in payloads:
            tmp = MOCK_DIR / f".{name}.tmp"
            tmp.write_text(text)
            staged.append((tmp, MOCK_DIR / name))
        for tmp, final in staged:
            os.replace(tmp, final)             # atomic within the filesystem
            moved.append(final.name)
    except OSError:
        # Name what did and did not move: with some files replaced and others
        # not, the three exports on disk are no longer one estate, and the
        # engine cannot tell. The caller (app/main.py) logs the exception; this
        # line is the part only this function knows.
        log.error("scenario write failed part-way; data/mock may mix two datasets",
                  exc_info=True,
                  extra={"event": "scenario_write_partial", "replaced": moved,
                         "pending": [f.name for _t, f in staged if f.name not in moved]})
        for tmp, _final in staged:             # never leave temp files behind
            tmp.unlink(missing_ok=True)
        raise


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
    """Regenerate data/mock for `scenario`. Raises ValueError on an unknown id.

    Logged because this function OVERWRITES the engine's only input. It runs on
    every cold engine build and every recompute, so "the dataset changed under
    me" is a real support question (it is also the mechanism behind the audit's
    finding that a seeded scale dataset does not survive a restart), and the one
    line here is what makes the answer checkable rather than inferred.
    """
    fn = _BUILDERS.get(scenario)
    if fn is None:
        # Not a silent path -- it raises -- but the log is what ties the 4xx the
        # caller returns to the value that produced it.
        log.error("unknown scenario requested; data/mock left as it was",
                  extra={"event": "scenario_unknown", "scenario": scenario,
                         "known": sorted(_BUILDERS)})
        raise ValueError(f"unknown scenario: {scenario}")
    if scenario == "scale":
        fn(n)
    else:
        fn()
    log.info("scenario written to data/mock", extra={
        "event": "scenario_written", "scenario": scenario,
        "synthetic_assets": n if scenario == "scale" else 0})
