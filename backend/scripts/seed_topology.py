#!/usr/bin/env python3
"""Write the infrastructure exports — one file per onboarded console.

    python backend/scripts/seed_topology.py            # every console
    python backend/scripts/seed_topology.py --only algosec_topology meraki
    python backend/scripts/seed_topology.py --clear     # onboard nothing

Each file is one console's PROJECTION of `src.estate`, in that vendor's real API
shape. Which files exist IS the estate's onboarding state: the topology layer
reads whatever is present and names the lanes the rest would have filled.

That makes `--only` the most useful flag here. Onboarding just AlgoSec and
re-running the engine shows exactly what a client with one aggregator and no
console access actually gets — the perimeter, and three dark lanes each naming
the API that would light it. That is the product's central claim, and it is
demonstrable in one command rather than asserted on a slide.

⚠ SIMULATED DATA. Every fact these files produce carries
`Provenance.simulated = True`, and the Sources screen renders that as
"simulated export — not a live connector". Nothing here contacts a vendor.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.connectors import algosec_topology, carrier, cisco, fortinet, juniper  # noqa: E402
from src.estate import Estate, build  # noqa: E402

MOCK_DIR = Path(__file__).resolve().parents[1] / "data" / "mock"

#: filename -> (label, builder). The filename is the contract with
#: `normalizers.OPTIONAL`; a mismatch means the export is written and never read.
EXPORTS = {
    "algosec_topology_export.json": ("AlgoSec ASMS (topology)", algosec_topology.algosec_topology_export),
    "fortimanager_export.json": ("FortiManager", fortinet.fortimanager_export),
    "fortigate_export.json": ("FortiGate (direct)", fortinet.fortigate_export),
    "carrier_portal_export.json": ("Carrier portal", carrier.carrier_portal_export),
    "catalyst_center_export.json": ("Cisco Catalyst Center", cisco.catalyst_center_export),
    "meraki_export.json": ("Cisco Meraki Dashboard", cisco.meraki_export),
    "junos_space_export.json": ("Junos Space", juniper.junos_space_export),
}


def build_exports(est: Estate, only: Iterable[str] | None = None) -> dict[str, dict]:
    """filename -> payload, for each console `only` names (default: all seven).

    The single place that knows which builder produces which file. Extracted from
    `main()` so `src.scenarios` can write the infrastructure half of a scenario
    without re-implementing the projection -- the defect that made that necessary
    was that a scenario switch rewrote three of the estate's ten exports and left
    the other seven from whichever scenario wrote them last, so "clean estate"
    reported zero policy findings beside a thirteen-device topology with four
    designed single points of failure.

    `only` names CONSOLE KEYS (`meraki`), not filenames: that is what `--only`
    takes and what the onboarding tables in `scenarios.py` are written in.
    """
    keys = None if only is None else set(only)
    return {name: builder(est)
            for name, (_label, builder) in sorted(EXPORTS.items())
            if keys is None or name.replace("_export.json", "") in keys}


def _write(path: Path, payload: dict) -> None:
    """Serialize first, then replace. A builder that raises must leave the
    previous export untouched rather than truncating it — the same rule
    `scenarios._write` follows, and for the same reason: a half-written estate is
    the dangerous failure, not a loud one."""
    text = json.dumps(payload, indent=2) + "\n"
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", metavar="CONSOLE",
                    help="console keys to onboard (default: all). "
                         f"Choices: {', '.join(sorted(k.replace('_export.json', '') for k in EXPORTS))}")
    ap.add_argument("--clear", action="store_true",
                    help="remove every infrastructure export (onboard nothing)")
    ap.add_argument("--branches", type=int, default=0, metavar="N",
                    help="grow the estate by N branch sites before projecting "
                         "(what the `scale` scenario writes)")
    args = ap.parse_args()

    MOCK_DIR.mkdir(parents=True, exist_ok=True)

    if args.clear:
        removed = [name for name in EXPORTS if (MOCK_DIR / name).exists()]
        for name in removed:
            (MOCK_DIR / name).unlink()
        print(f"removed {len(removed)} infrastructure export(s); "
              f"the estate is now policy-only")
        return 0

    wanted = set(args.only) if args.only else None
    if wanted:
        known = {k.replace("_export.json", "") for k in EXPORTS}
        unknown = wanted - known
        if unknown:
            # Refused rather than ignored: silently skipping a misspelled console
            # produces an estate missing a lane, and the operator would read that
            # as a finding about their network.
            ap.error(f"unknown console(s): {', '.join(sorted(unknown))}. "
                     f"Known: {', '.join(sorted(known))}")

    est = build(branches=args.branches)
    payloads = build_exports(est, wanted)
    written = []
    for name, (label, _builder) in sorted(EXPORTS.items()):
        if name not in payloads:
            # Removed, not written empty. `normalizers._load_optional` reads an
            # absent file as "this console is not onboarded" and a present one as
            # a console that answered; leaving the previous run's export on disk
            # would onboard a console this command was told to leave off.
            (MOCK_DIR / name).unlink(missing_ok=True)
            continue
        _write(MOCK_DIR / name, payloads[name])
        written.append(label)

    print(f"wrote {len(written)} infrastructure export(s) to {MOCK_DIR}:")
    for label in written:
        print(f"  · {label}")
    print("\nrun `make precompute` to rebuild the snapshot with them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
