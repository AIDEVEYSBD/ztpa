"""Generate the three simulated tool exports with deliberately planted problems.

Deterministic by construction (fixed data, no randomness), so the demo is
byte-identical every run. Each export roughly mirrors its tool's native shape;
all of them normalize cleanly into the canonical model.

Planted problems (BUILD_SPEC section 5):
  1. any/any allow (AlgoSec)            0.0.0.0/0 -> 10.0.0.0/8  proto any   -> over_permissive, FORCED critical
  2. RDP internet -> regulated (AlgoSec) 0.0.0.0/0 -> db-prod-01  tcp/3389    -> over_permissive, FORCED critical
  3. overlapping CIDRs (AlgoSec)         10.20.5.0/24 & 10.0.0.0/8 -> app-segment -> cidr_overlap (low)
  4. shadowed rule (AlgoSec)             broad allow then narrow deny -> app-server-07 -> shadowed_rule (low)
  5. cross-tool path (Wiz+GC+AlgoSec)    internet -> lb-public-01 -> app-server-07 -> internal-app -> db-prod-01
                                          -> cross_tool_path, reaches_sensitive, FORCED critical
Plus benign noise so ranking/grouping has something to cut through.
"""

from __future__ import annotations

import json
from pathlib import Path

MOCK_DIR = Path(__file__).resolve().parents[1] / "data" / "mock"


# --------------------------------------------------------------------------
# AlgoSec — vendor-abstracted ordered firewall rules + an object catalog.
# src/dst may be a raw CIDR or an object name (resolved via `objects`).
# --------------------------------------------------------------------------
def algosec_export() -> dict:
    return {
        "vendor": "AlgoSec",
        "export_type": "firewall_policy",
        "device": "afa-edge-fw-01",
        "generated": "static-demo",
        "objects": {
            "db-prod-01":    {"type": "host",    "value": "10.50.0.10",   "tags": ["pci", "customer-data", "prod"]},
            "app-segment":   {"type": "network", "value": "10.30.0.0/16",  "tags": ["prod"]},
            "app-server-07": {"type": "host",    "value": "10.30.7.7",     "tags": ["prod"]},
            "app-server-08": {"type": "host",    "value": "10.30.7.8",     "tags": ["prod"]},
            "app-server-09": {"type": "host",    "value": "10.30.7.9",     "tags": ["prod"]},
            "internal-app":  {"type": "network", "value": "10.40.0.0/16",  "tags": ["prod", "internal-app"]},
            "dev-box-01":    {"type": "host",    "value": "10.31.0.10",    "tags": ["dev"]},
        },
        "rules": [
            # --- planted problems ---
            {"rule_id": "ALGO-001", "order": 1,  "src": "0.0.0.0/0",     "dst": "10.0.0.0/8",    "service": "any",      "action": "allow", "comment": "temporary broad allow (TODO remove)"},
            {"rule_id": "ALGO-002", "order": 2,  "src": "0.0.0.0/0",     "dst": "db-prod-01",    "service": "tcp/3389", "action": "allow", "comment": "vendor RDP access"},
            {"rule_id": "ALGO-010", "order": 10, "src": "10.20.5.0/24",  "dst": "app-segment",   "service": "tcp/443",  "action": "allow", "comment": "branch office to app"},
            {"rule_id": "ALGO-011", "order": 11, "src": "10.0.0.0/8",    "dst": "app-segment",   "service": "tcp/443",  "action": "allow", "comment": "corp to app"},
            {"rule_id": "ALGO-020", "order": 20, "src": "10.0.0.0/8",    "dst": "app-server-07", "service": "tcp/443",  "action": "allow", "comment": "corp to app-07"},
            {"rule_id": "ALGO-021", "order": 21, "src": "10.20.5.7/32",  "dst": "app-server-07", "service": "tcp/443",  "action": "deny",  "comment": "block compromised host (never fires)"},
            {"rule_id": "ALGO-030", "order": 30, "src": "internal-app",  "dst": "db-prod-01",    "service": "tcp/5432", "action": "allow", "comment": "app tier to prod db"},
            # --- secondary findings (medium) ---
            {"rule_id": "ALGO-046", "order": 46, "src": "172.16.0.0/12", "dst": "app-server-08", "service": "tcp/3389", "action": "allow", "comment": "ops RDP"},
            {"rule_id": "ALGO-050", "order": 50, "src": "10.0.0.0/8",    "dst": "app-server-09", "service": "tcp/22",   "action": "allow", "comment": "corp SSH to app-09"},
            # --- benign noise ---
            {"rule_id": "ALGO-060", "order": 60, "src": "10.30.5.0/24",  "dst": "app-server-08", "service": "tcp/443",  "action": "allow", "comment": "branch to app-08"},
            {"rule_id": "ALGO-061", "order": 61, "src": "10.30.0.0/16",  "dst": "app-server-08", "service": "tcp/443",  "action": "allow", "comment": "app segment to app-08 (redundant)"},
            {"rule_id": "ALGO-070", "order": 70, "src": "10.30.0.0/24",  "dst": "app-server-09", "service": "tcp/443",  "action": "allow", "comment": "web to app-09"},
            {"rule_id": "ALGO-071", "order": 71, "src": "10.31.0.0/24",  "dst": "dev-box-01",    "service": "tcp/22",   "action": "allow", "comment": "dev ssh"},
            {"rule_id": "ALGO-072", "order": 72, "src": "10.10.0.0/24",  "dst": "app-server-08", "service": "tcp/9100", "action": "allow", "comment": "monitoring scrape"},
            # --- transport / application-layer (QUIC / HTTP-3) ---
            # udp/443 decodes to QUIC: internet -> internal app server, uninspectable -> transport_exposure, FORCED critical.
            # app-server-09 already has tcp/443 (ALGO-070), so this trips "TLS fallback not blocked" too. Targets a
            # leaf host (no edge onward) so it does not open a *second* cross-tool path -- the money shot stays singular.
            {"rule_id": "ALGO-080", "order": 80, "src": "0.0.0.0/0",     "dst": "app-server-09", "service": "udp/443", "action": "allow", "comment": "HTTP/3 edge accel (UDP 443) - added for perf"},
            # explicit App-ID rule ("quic" token) -> declared L7 decode, corp source (not internet) -> lower-band blind spot.
            {"rule_id": "ALGO-082", "order": 82, "src": "10.0.0.0/8",    "dst": "app-server-08", "service": "quic",    "action": "allow", "comment": "corp QUIC to app-08 (App-ID rule)"},
        ],
    }


# --------------------------------------------------------------------------
# Guardicore (Akamai) — label/identity-based microsegmentation.
# --------------------------------------------------------------------------
def guardicore_export() -> dict:
    return {
        "vendor": "Guardicore (Akamai)",
        "export_type": "segmentation_policy",
        "labels": {
            "app-server-07":  {"role": "app",        "env": "prod", "tags": ["prod"]},
            "app-server-08":  {"role": "app",        "env": "prod", "tags": ["prod"]},
            "internal-app":   {"role": "segment",    "env": "prod", "tags": ["prod", "internal-app"]},
            "web-tier":       {"role": "web",        "env": "prod", "tags": ["prod"]},
            "app-tier":       {"role": "app",        "env": "prod", "tags": ["prod"]},
            "monitoring":     {"role": "monitoring", "env": "prod", "tags": ["prod"]},
            "ci-runner":      {"role": "ci",         "env": "dev",  "tags": ["dev"]},
            "artifact-store": {"role": "storage",    "env": "dev",  "tags": ["dev"]},
        },
        "policies": [
            {"policy_id": "GC-001", "src_label": "app-server-07", "dst_label": "internal-app",   "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "app-east-west"},
            {"policy_id": "GC-010", "src_label": "web-tier",      "dst_label": "app-tier",       "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "tiering"},
            {"policy_id": "GC-011", "src_label": "monitoring",    "dst_label": "app-server-07",  "port": 9100, "protocol": "tcp", "action": "allow", "ruleset": "observability"},
            {"policy_id": "GC-012", "src_label": "ci-runner",     "dst_label": "artifact-store", "port": 443,  "protocol": "tcp", "action": "allow", "ruleset": "ci"},
            # explicit App-ID policy: Guardicore names the app, not a port -> declared QUIC decode.
            {"policy_id": "GC-020", "src_label": "web-tier",      "dst_label": "app-tier",       "app": "quic", "action": "allow", "ruleset": "tiering-http3"},
        ],
    }


# --------------------------------------------------------------------------
# Wiz — cloud exposure inferred from configuration.
#   internet_ingress: an asset reachable from the internet (source 0.0.0.0/0)
#   lateral:          asset -> asset reachability a security group permits
# --------------------------------------------------------------------------
def wiz_export() -> dict:
    return {
        "vendor": "Wiz",
        "export_type": "cloud_exposure",
        # NB: Wiz refers to app-server-07 by its cloud name "appsrv-07" (same IP).
        # The identity layer merges it back by shared IP -- which is what makes the
        # cross-tool path connect. "rds-prod-customers" is inventory-only (no edge):
        # a near-duplicate of db-prod-01 that the embedding suggester flags for review.
        "assets": {
            "lb-public-01":      {"cloud": "aws", "type": "load_balancer", "internet_facing": True,  "ip": "52.20.10.10", "tags": ["dmz", "internet-facing", "prod", "cloud"]},
            "lb-public-02":      {"cloud": "aws", "type": "load_balancer", "internet_facing": True,  "ip": "52.20.10.11", "tags": ["dmz", "internet-facing", "prod", "cloud"]},
            "appsrv-07":         {"cloud": "aws", "type": "ec2",           "internet_facing": False, "ip": "10.30.7.7",   "tags": ["prod"]},
            "app-server-08":     {"cloud": "aws", "type": "ec2",           "internet_facing": False, "ip": "10.30.7.8",   "tags": ["prod"]},
            "rds-prod-customers": {"cloud": "aws", "type": "rds",          "internet_facing": False, "ip": "10.50.0.20",  "tags": ["pci", "customer-data", "prod", "cloud"]},
        },
        "exposures": [
            {"exposure_id": "WIZ-001", "kind": "internet_ingress", "dst": "lb-public-01", "port": 443,  "protocol": "tcp"},
            {"exposure_id": "WIZ-002", "kind": "lateral", "src": "lb-public-01", "dst": "appsrv-07", "port": 8443, "protocol": "tcp"},
            {"exposure_id": "WIZ-010", "kind": "internet_ingress", "dst": "lb-public-02", "port": 443,  "protocol": "tcp"},
            {"exposure_id": "WIZ-011", "kind": "lateral", "src": "lb-public-02", "dst": "app-server-08", "port": 443,  "protocol": "tcp"},
            # QUIC (udp/443) at the edge and laterally toward app-server-07: extends the cross-tool
            # chain over an uninspectable transport. Edge LB is meant to be exposed (dmz) -> lower band.
            {"exposure_id": "WIZ-020", "kind": "internet_ingress", "dst": "lb-public-01", "port": 443, "protocol": "udp"},
            {"exposure_id": "WIZ-021", "kind": "lateral", "src": "lb-public-01", "dst": "appsrv-07", "port": 443, "protocol": "udp"},
        ],
    }


def main() -> None:
    MOCK_DIR.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "algosec_export.json": algosec_export(),
        "guardicore_export.json": guardicore_export(),
        "wiz_export.json": wiz_export(),
    }
    for name, data in artifacts.items():
        path = MOCK_DIR / name
        path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {path.relative_to(MOCK_DIR.parents[1])}")
    print("seed complete: 3 simulated exports with 5 planted problems + benign noise")


if __name__ == "__main__":
    main()
