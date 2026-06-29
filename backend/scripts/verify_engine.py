"""Assert the deterministic engine meets the BUILD_SPEC acceptance criteria.

Exit 0 = all pass. Run any time: `python backend/scripts/verify_engine.py`.
No DB or model required -- pure deterministic engine.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzers.run_all import run  # noqa: E402

checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    checks.append((name, bool(ok)))


def main() -> int:
    r1, r2 = run(), run()
    fs = r1.findings

    def find(pred):
        return next((f for f in fs if pred(f)), None)

    p1 = find(lambda f: f.type == "over_permissive" and f.signals.get("protocol") == "any" and f.signals.get("source") == "0.0.0.0/0")
    p2 = find(lambda f: f.type == "over_permissive" and f.signals.get("exposed_port") == 3389 and "pci" in f.signals.get("dest_tags", []))
    p3 = find(lambda f: f.type == "cidr_overlap" and f.signals.get("dest") == "app-segment")
    p4 = find(lambda f: f.type == "shadowed_rule" and f.signals.get("shadowed_action") == "deny")
    p5 = find(lambda f: f.type == "cross_tool_path")
    p6 = find(lambda f: f.type == "transport_exposure" and f.signals.get("subtype") == "quic_blind_spot"
              and f.signals.get("source") == "0.0.0.0/0")
    p7 = find(lambda f: f.type == "transport_exposure" and f.signals.get("subtype") == "tls_fallback_not_blocked")

    check("P1 any/any present", p1 is not None)
    check("P1 forced_critical", bool(p1 and p1.forced_critical))
    check("P2 RDP->PCI present", p2 is not None)
    check("P2 forced_critical", bool(p2 and p2.forced_critical))
    check("P3 overlap present + low", bool(p3 and p3.severity_band == "low"))
    check("P4 shadowed-deny present + low", bool(p4 and p4.severity_band == "low"))
    check("P5 cross-tool path present + critical", bool(p5 and p5.severity_band == "critical"))
    if p5:
        path = p5.signals.get("path", [])
        expected = ["0.0.0.0/0", "lb-public-01", "app-server-07", "internal-app", "db-prod-01"]
        check("P5 path is the 5-hop chain", path == expected)
        check("P5 reaches_sensitive", p5.signals.get("reaches_sensitive") is True)
        check("P5 spans 3 tools", len(p5.signals.get("tools", [])) == 3)
    check("exactly one cross-tool path", sum(1 for f in fs if f.type == "cross_tool_path") == 1)
    check("P6 QUIC blind spot present (internet)", p6 is not None)
    check("P6 QUIC blind spot forced_critical", bool(p6 and p6.forced_critical))
    check("P6 QUIC decoded l7_app", bool(p6 and p6.signals.get("l7_app") == "quic"))
    check("P7 TLS fallback-not-blocked present", p7 is not None)
    check("L7 decode: declared App-ID resolved to QUIC transport",
          any(f.signals.get("l7_source") == "declared" for f in fs if f.type == "transport_exposure"))
    check("every finding has a severity_vector", all("severity_vector" in f.signals for f in fs))
    check("determinism (byte-identical re-run)",
          [(f.id, f.severity, f.severity_band) for f in r1.findings] ==
          [(f.id, f.severity, f.severity_band) for f in r2.findings])

    print(f"snapshot {r1.snapshot_id} · {len(fs)} findings\n")
    ok_all = True
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        ok_all = ok_all and ok
    print("\n" + ("ALL CHECKS PASSED" if ok_all else "SOME CHECKS FAILED"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
