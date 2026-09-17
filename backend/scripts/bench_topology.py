#!/usr/bin/env python3
"""Measure what the topology layer costs as the estate grows.

    python backend/scripts/bench_topology.py                 # 0, 25, 100, 250 branches
    python backend/scripts/bench_topology.py 0 50 500 2000

Answers "how long would this take on a real network" with a measurement rather
than an estimate. Each run grows `src.estate` by N branch sites -- the SAME shape
as the HQ access layer, each dual-homed to the core pair -- so the numbers
describe the real algorithms on a real topology. A thousand disconnected nodes
would be faster and would answer a different question.

WHAT IS TIMED, and why each one is the interesting number:

  project     building each console's export from the estate. Grows linearly and
              is the cheap part; included so it cannot quietly stop being cheap.
  normalize   reading those exports back. Also linear.
  merge       folding N consoles' overlapping views into one. Keyed, so linear.
  containment the adjacency fallback. THE ONE TO WATCH: it groups interfaces by
              address block and pairs within a block. Bounded to exactly-two-device
              blocks, so it is linear -- but the unbounded version of it was
              quadratic and turned one management /24 into a near-complete mesh.
  layers      BFS from the circuit terminations. Linear in nodes + links.
  resilience  articulation points, bridges, and a blast radius PER DEVICE. The
              blast radius is the expensive one: it removes each node and
              recounts connectivity, so it is O(V * (V + E)). This is the number
              that decides how large an estate the "lose this device" interaction
              can stay interactive on.

Deterministic apart from the clock: same estate, same output, every run.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzers.resilience import assess  # noqa: E402
from src.connectors import algosec_topology, carrier, cisco, fortinet, juniper  # noqa: E402
from src.estate import build  # noqa: E402
from src.normalizers import algosec_topology as n_algo  # noqa: E402
from src.normalizers import carrier as n_carrier  # noqa: E402
from src.normalizers import cisco as n_cisco, fortinet as n_forti, juniper as n_juniper  # noqa: E402
from src.normalizers.common import NormalizeResult  # noqa: E402
from src.topology import reconstruct  # noqa: E402
from src.topology.merge import merge_devices, merge_interfaces, merge_links  # noqa: E402

DEFAULT_SCALES = (0, 25, 100, 250)


class _Timer:
    def __init__(self) -> None:
        self.marks: dict[str, float] = {}
        self._t = time.perf_counter()

    def mark(self, name: str) -> None:
        now = time.perf_counter()
        self.marks[name] = (now - self._t) * 1000
        self._t = now


def _run(branches: int) -> dict:
    t = _Timer()
    est = build(branches=branches)
    t.mark("estate")

    exports = [
        (n_algo.normalize, algosec_topology.algosec_topology_export(est)),
        (n_forti.normalize, fortinet.fortimanager_export(est)),
        (n_forti.normalize, fortinet.fortigate_export(est)),
        (n_carrier.normalize, carrier.carrier_portal_export(est)),
        (n_cisco.normalize_catalyst, cisco.catalyst_center_export(est)),
        (n_cisco.normalize_meraki, cisco.meraki_export(est)),
        (n_juniper.normalize, juniper.junos_space_export(est)),
    ]
    t.mark("project")

    nr = NormalizeResult()
    for fn, raw in exports:
        nr.extend(fn(raw))
    t.mark("normalize")

    merge_devices(nr.devices)
    merge_interfaces(nr.interfaces)
    merge_links(nr.links)
    t.mark("merge")

    topo = reconstruct(nr.devices, nr.interfaces, nr.links,
                       nr.vlans, nr.subnets, nr.circuits)
    t.mark("reconstruct")

    report = assess(topo)
    t.mark("resilience")

    return {
        "branches": branches,
        "devices": len(topo.devices),
        "interfaces": len(topo.interfaces),
        "links": len(topo.links),
        "vlans": len(topo.vlans),
        "findings": len(report.findings),
        **{k: round(v, 1) for k, v in t.marks.items()},
        "total": round(sum(t.marks.values()), 1),
    }


def main() -> int:
    scales = [int(a) for a in sys.argv[1:]] or list(DEFAULT_SCALES)
    rows = [_run(n) for n in scales]

    cols = ["branches", "devices", "interfaces", "links", "findings",
            "estate", "project", "normalize", "merge", "reconstruct",
            "resilience", "total"]
    widths = {c: max(len(c), max(len(f"{r[c]:,}" if isinstance(r[c], int) else f"{r[c]}")
                                 for r in rows)) for c in cols}
    print("  ".join(c.rjust(widths[c]) for c in cols))
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join((f"{r[c]:,}" if isinstance(r[c], int) else f"{r[c]}").rjust(widths[c])
                        for c in cols))
    print("\nms per stage. `resilience` includes a per-device blast radius, which is")
    print("O(V*(V+E)) -- it is the number that bounds the interactive 'lose this")
    print("device' view, not the ingest.")

    biggest = rows[-1]
    if biggest["devices"]:
        print(f"\nAt {biggest['devices']:,} devices / {biggest['links']:,} links: "
              f"{biggest['total']:,} ms end to end "
              f"({biggest['total'] / biggest['devices']:.2f} ms per device).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
