"""Generate the three simulated tool exports with deliberately planted problems.

Deterministic by construction (fixed data, no randomness), so the demo is
byte-identical every run. Each export roughly mirrors its tool's native shape;
all of them normalize cleanly into the canonical model.

Planted problems (BUILD_SPEC section 5):
  1. any/any allow (AlgoSec)            0.0.0.0/0 -> 10.0.0.0/8  proto any   -> over_permissive, FORCED critical
  2. RDP internet -> regulated (AlgoSec) 0.0.0.0/0 -> db-prod-01  tcp/3389    -> over_permissive, FORCED critical
  3. overlapping CIDRs (AlgoSec)         10.20.5.0/24 & 10.0.0.0/8 -> app-segment -> cidr_overlap (low)
  4. shadowed rule (AlgoSec)             broad allow then narrow deny -> app-server-07 -> shadowed_rule (low)
  5. cross-tool path (Wiz+GC+AlgoSec)    internet -> lb-public-01 -> app-server-07 -> internal-app-01 -> db-prod-01
                                          -> cross_tool_path, reaches_sensitive, FORCED critical
     Every pivot on it is a CONCRETE host and every hop is a real grant from a
     different tool's export:
         0.0.0.0/0       --wiz WIZ-001--------> lb-public-01     (internet ingress)
         lb-public-01    --wiz WIZ-002--------> appsrv-07        (cloud lateral)
         app-server-07   --guardicore GC-002--> internal-app-01  (east-west)
         internal-app-01 --algosec ALGO-029---> db-prod-01       (app host to PCI db)
     It exists only because BOTH correlations hold: `appsrv-07` (Wiz) and
     `app-server-07` (AlgoSec/Guardicore) fuse on a shared address inside a
     shared declared `vpcId`, and the pivot is the host `internal-app-01` rather
     than the /16 `internal-app`. Neither is a relaxation: `_valid_traversal`
     still refuses the range, and the merge still requires matching tenancy.
Plus benign noise so ranking/grouping has something to cut through.
"""

from __future__ import annotations

import json
from pathlib import Path

MOCK_DIR = Path(__file__).resolve().parents[1] / "data" / "mock"

# The AWS VPC the cloud-resident half of this estate lives in. All three tools
# record it for a cloud workload -- Wiz natively (`vpcId` on every cloud
# resource), Guardicore as an imported cloud label, AlgoSec on the objects it
# pulled from the cloud device fronting the VPC -- so it is the ONE namespace the
# three exports genuinely agree on.
#
# It matters because `identity.resolve_identities` will not fuse two tools' names
# for one address unless BOTH sides declare the same namespace: an RFC 1918
# address identifies a host only relative to the VPC/VRF/account that assigns it.
# That is why Wiz's `appsrv-07` and AlgoSec's `app-server-07` merge here --
# because their declared tenancy MATCHES, not because a check was removed. Strip
# this field and the merge is correctly withheld again as `unscoped_ip`.
VPC_ID = "vpc-0a7d3e91c4b28f56"


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
        # `vpcId` is the TENANCY field, and it is only on the objects AlgoSec
        # imported from the cloud device fronting that VPC. An RFC 1918 address
        # identifies a host only relative to the namespace that assigns it, so
        # this is the field `identity.resolve_identities` requires before it will
        # fuse two tools' names for one address (`normalizers.common.scope_
        # identifiers` lifts it; `identity.context_of` reads it back). The
        # on-prem objects below declare none -- db-prod-01 and dev-box-01 are not
        # in a VPC -- and that absence is meaningful: it means "no scope, do not
        # merge", which is the fail-safe direction.
        "objects": {
            "db-prod-01":      {"type": "host",    "value": "10.50.0.10",   "tags": ["pci", "customer-data", "prod"]},
            "app-segment":     {"type": "network", "value": "10.30.0.0/16",  "tags": ["prod"]},
            "app-server-07":   {"type": "host",    "value": "10.30.7.7",     "tags": ["prod"], "vpcId": VPC_ID},
            "app-server-08":   {"type": "host",    "value": "10.30.7.8",     "tags": ["prod"], "vpcId": VPC_ID},
            "app-server-09":   {"type": "host",    "value": "10.30.7.9",     "tags": ["prod"], "vpcId": VPC_ID},
            "internal-app":    {"type": "network", "value": "10.40.0.0/16",  "tags": ["prod", "internal-app"]},
            # The CONCRETE host inside the internal-app segment. Guardicore sees
            # it too (same name, so the identity layer merges it on hostname),
            # which is what lets a path pivot through a machine instead of
            # through the /16 -- `_valid_traversal` rejects the range, correctly,
            # and nothing about that rule is relaxed to accommodate this.
            "internal-app-01": {"type": "host",    "value": "10.40.0.5",     "tags": ["prod", "internal-app"], "vpcId": VPC_ID},
            "dev-box-01":      {"type": "host",    "value": "10.31.0.10",    "tags": ["dev"]},
        },
        "rules": [
            # --- planted problems ---
            {"rule_id": "ALGO-001", "order": 1,  "src": "0.0.0.0/0",     "dst": "10.0.0.0/8",    "service": "any",      "action": "allow", "comment": "temporary broad allow (TODO remove)"},
            {"rule_id": "ALGO-002", "order": 2,  "src": "0.0.0.0/0",     "dst": "db-prod-01",    "service": "tcp/3389", "action": "allow", "comment": "vendor RDP access"},
            {"rule_id": "ALGO-010", "order": 10, "src": "10.20.5.0/24",  "dst": "app-segment",   "service": "tcp/443",  "action": "allow", "comment": "branch office to app"},
            {"rule_id": "ALGO-011", "order": 11, "src": "10.0.0.0/8",    "dst": "app-segment",   "service": "tcp/443",  "action": "allow", "comment": "corp to app"},
            {"rule_id": "ALGO-020", "order": 20, "src": "10.0.0.0/8",    "dst": "app-server-07", "service": "tcp/443",  "action": "allow", "comment": "corp to app-07"},
            {"rule_id": "ALGO-021", "order": 21, "src": "10.20.5.7/32",  "dst": "app-server-07", "service": "tcp/443",  "action": "deny",  "comment": "block compromised host (never fires)"},
            # The original least-privilege grant: ONE host to the database. ALGO-030
            # below is the later over-broad widening of it, which is why ALGO-030
            # still scores as over_permissive on the /16 it resolves to (P8).
            {"rule_id": "ALGO-029", "order": 29, "src": "internal-app-01", "dst": "db-prod-01",    "service": "tcp/5432", "action": "allow", "comment": "internal app host to prod db"},
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
        # `vpcId` is an imported CLOUD label, and it is the tenancy field the
        # identity layer reads. `env` deliberately is NOT one: every account in
        # the estate is tagged prod, so keying a merge on it would reintroduce
        # the address collision the scope rule exists to prevent.
        "labels": {
            "app-server-07":   {"role": "app",     "env": "prod", "tags": ["prod"], "vpcId": VPC_ID},
            "app-server-08":   {"role": "app",     "env": "prod", "tags": ["prod"], "vpcId": VPC_ID},
            "internal-app":    {"role": "segment", "env": "prod", "tags": ["prod", "internal-app"]},
            # The concrete host inside that segment, with the address that makes
            # it a machine rather than a range: `role: app` (not a SEGMENT_ROLE)
            # and a single /32 both resolve `object_is_abstract` to False, so it
            # is a legal pivot. AlgoSec names it identically, so the two views
            # merge on hostname -- no shared-IP inference needed.
            "internal-app-01": {"role": "app",     "env": "prod", "tags": ["prod", "internal-app"], "ip": "10.40.0.5", "vpcId": VPC_ID},
            "web-tier":       {"role": "web",        "env": "prod", "tags": ["prod"]},
            "app-tier":       {"role": "app",        "env": "prod", "tags": ["prod"]},
            "monitoring":     {"role": "monitoring", "env": "prod", "tags": ["prod"]},
            "ci-runner":      {"role": "ci",         "env": "dev",  "tags": ["dev"]},
            "artifact-store": {"role": "storage",    "env": "dev",  "tags": ["dev"]},
        },
        "policies": [
            {"policy_id": "GC-001", "src_label": "app-server-07", "dst_label": "internal-app",   "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "app-east-west"},
            # The east-west allow to the concrete host. This is the middle hop of
            # the cross-tool path: Guardicore is the only tool that sees it.
            {"policy_id": "GC-002", "src_label": "app-server-07", "dst_label": "internal-app-01", "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "app-east-west"},
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
        # The identity layer merges the two names on `(context, ip)` -- the shared
        # address 10.30.7.7 INSIDE the shared `vpcId` -- which is what makes the
        # cross-tool path connect. Both halves are required: the address alone is
        # an `unscoped_ip` review candidate, never a merge.
        # "rds-prod-customers" is inventory-only (no edge):
        # a near-duplicate of db-prod-01 that the embedding suggester flags for review.
        "assets": {
            "lb-public-01":      {"cloud": "aws", "type": "load_balancer", "internet_facing": True,  "ip": "52.20.10.10", "tags": ["dmz", "internet-facing", "prod", "cloud"], "vpcId": VPC_ID},
            "lb-public-02":      {"cloud": "aws", "type": "load_balancer", "internet_facing": True,  "ip": "52.20.10.11", "tags": ["dmz", "internet-facing", "prod", "cloud"], "vpcId": VPC_ID},
            "appsrv-07":         {"cloud": "aws", "type": "ec2",           "internet_facing": False, "ip": "10.30.7.7",   "tags": ["prod"], "vpcId": VPC_ID},
            "app-server-08":     {"cloud": "aws", "type": "ec2",           "internet_facing": False, "ip": "10.30.7.8",   "tags": ["prod"], "vpcId": VPC_ID},
            "rds-prod-customers": {"cloud": "aws", "type": "rds",          "internet_facing": False, "ip": "10.50.0.20",  "tags": ["pci", "customer-data", "prod", "cloud"], "vpcId": VPC_ID},
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
