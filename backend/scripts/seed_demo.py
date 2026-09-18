"""Generate the three simulated tool exports with deliberately planted problems.

Deterministic by construction (fixed data, no randomness), so the demo is
byte-identical every run. Each export roughly mirrors its tool's native shape;
all of them normalize cleanly into the canonical model.

Planted problems (BUILD_SPEC section 5):
  1. any/any allow (AlgoSec)            0.0.0.0/0 -> 10.0.0.0/8  proto any   -> over_permissive, FORCED critical
  2. RDP internet -> regulated (AlgoSec) 0.0.0.0/0 -> db-prod-01  tcp/3389    -> over_permissive, FORCED critical
  3. overlapping CIDRs (AlgoSec)         10.20.5.0/24 & 10.0.0.0/8 -> app-segment -> cidr_overlap (low)
  4. shadowed rule (AlgoSec)             broad allow then narrow deny -> app-server-07 -> shadowed_rule (low)
  5. cross-tool path A (Wiz+GC+AlgoSec)  internet -> lb-public-01 -> app-server-07 -> internal-app-01 -> db-prod-01
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
  6. cross-tool path B (Wiz+GC+AlgoSec)  internet -> lb-public-02 -> app-server-08 -> data-node-01 -> db-prod-02
                                          -> cross_tool_path, reaches_sensitive, FORCED critical
         0.0.0.0/0     --wiz WIZ-010--------> lb-public-02   (internet ingress)
         lb-public-02  --wiz WIZ-011--------> app-server-08  (cloud lateral)
         app-server-08 --guardicore GC-030--> data-node-01   (east-west)
         data-node-01  --algosec ALGO-031---> db-prod-02     (data host to PCI db)
     A SECOND regulated database reached by a DISJOINT hop set, so cutting path A
     leaves path B standing -- which is the honest shape of a remediation queue
     and the reason the flagship carries both rather than hiding the second one
     behind a "Multiple paths" menu entry. (That entry was deleted: it reported
     ONE path, because its pivot `data-segment` was a /16 and `_valid_traversal`
     correctly refused it. See `src/scenarios.py`.)
Plus benign noise so ranking/grouping has something to cut through.

WHY GC-001 IS ON 9443 AND ALGO-030 SOURCES FROM app-segment
------------------------------------------------------------
These two look arbitrary and they are the entire anti-cheat. The engine does not
model CIDR-membership expansion (docs/ENGINE.md 10.2), so a finding that cites a
narrow rule can be made to DISAPPEAR by deleting that rule while a broader rule
keeps the exact same access alive. Both hops of path A used to be built that way:

  * GC-001 granted `app-server-07 -> internal-app` (the /16) on 8443, which is
    the same service GC-002 grants to `internal-app-01` (a /32 inside it). Remove
    GC-002 and the finding resolves; the flow does not. GC-001 is now on 9443
    (ruleset `app-admin`), so GC-002 is the ONLY grant for that flow and cutting
    it is a real cut.
  * ALGO-030 granted `internal-app` (10.40.0.0/16) -> db-prod-01 on tcp/5432,
    which covers ALGO-029 (10.40.0.5 -> db-prod-01, tcp/5432). Same trap on hop
    4. It now sources from `app-segment` (10.30.0.0/16), which does NOT contain
    10.40.0.5 -- so ALGO-029 stands alone, and the over_permissive finding
    ALGO-030 still produces ("PostgreSQL open from app-segment to db-prod-01",
    70/high) is the more realistic sin anyway: an entire app tier reaching the
    PCI database.

Path B is built with the trap designed out from the start: GC-030 and ALGO-031
are each the sole grant for their hop, with no broader twin on either side.

The demo walks finding -> fix -> gate -> queue -> rollback on one of these paths.
If a hop had a broader twin, the proposed fix would delete the FINDING and leave
the EXPOSURE, on the one screen whose entire pitch is that it does not do that.
"""

from __future__ import annotations

import sys
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
            # --- path B (planted problem 6). A SECOND regulated database and the
            #     concrete host that reaches it. `data-node-01` carries a vpcId
            #     because it is a cloud data-service node; `db-prod-02` does NOT,
            #     because it is on-prem like db-prod-01 -- and that absence is
            #     load-bearing, not an oversight. It is what keeps the second path
            #     honest: the terminal is reached because a rule grants it, never
            #     because two tools' names for it were fused on a bare shared IP.
            "data-node-01":    {"type": "host",    "value": "10.45.0.9",     "tags": ["prod", "data-svc"], "vpcId": VPC_ID},
            "db-prod-02":      {"type": "host",    "value": "10.50.0.30",    "tags": ["pci", "customer-data", "prod"]},
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
            # SOURCED FROM app-segment (10.30.0.0/16), NOT internal-app (10.40.0.0/16),
            # and the difference is the anti-cheat described in the module docstring:
            # 10.40.0.5 is NOT inside 10.30.0.0/16, so this rule does not cover
            # ALGO-029 and "remove ALGO-029" is a real cut rather than a finding
            # that vanishes while the access survives. It is still the widening
            # ALGO-029 was the least-privilege version of, and it still scores
            # over_permissive 70/high on the resolved /16 (P8).
            {"rule_id": "ALGO-030", "order": 30, "src": "app-segment",   "dst": "db-prod-01",    "service": "tcp/5432", "action": "allow", "comment": "app tier to prod db"},
            # Path B's last hop, and the ONLY grant for it: no broader rule in this
            # catalog reaches db-prod-02 on 5432, so cutting ALGO-031 removes the
            # access and not just the finding.
            {"rule_id": "ALGO-031", "order": 31, "src": "data-node-01", "dst": "db-prod-02",    "service": "tcp/5432", "action": "allow", "comment": "data service node to prod db-02"},
            # --- secondary findings (medium) ---
            {"rule_id": "ALGO-046", "order": 46, "src": "172.16.0.0/12", "dst": "app-server-08", "service": "tcp/3389", "action": "allow", "comment": "ops RDP"},
            {"rule_id": "ALGO-050", "order": 50, "src": "10.0.0.0/8",    "dst": "app-server-09", "service": "tcp/22",   "action": "allow", "comment": "corp SSH to app-09"},
            # --- benign noise ---
            {"rule_id": "ALGO-060", "order": 60, "src": "10.30.5.0/24",  "dst": "app-server-08", "service": "tcp/443",  "action": "allow", "comment": "branch to app-08"},
            {"rule_id": "ALGO-061", "order": 61, "src": "10.30.0.0/16",  "dst": "app-server-08", "service": "tcp/443",  "action": "allow", "comment": "app segment to app-08 (redundant)"},
            # Pairs with ALGO-070 below (10.30.0.0/24, the same service, the same
            # destination) to keep a third `cidr_overlap` in the fixture -- the one
            # that re-sourcing ALGO-030 off internal-app would otherwise have cost,
            # since ALGO-029 and ALGO-030 no longer overlap. Aimed at a LEAF host
            # (app-server-09 grants nothing onward), so it opens no third path and
            # the two money shots stay the only two.
            {"rule_id": "ALGO-062", "order": 62, "src": "10.30.0.0/16",  "dst": "app-server-09", "service": "tcp/443",  "action": "allow", "comment": "app segment to app-09 (redundant)"},
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
            # Path B's pivot. Guardicore names it identically to AlgoSec, so the
            # two views merge on HOSTNAME -- no shared-IP inference is needed and
            # none is used. `role: app` (not a SEGMENT_ROLE) and a single /32 both
            # resolve `object_is_abstract` to False, so it is a legal pivot on the
            # same terms as internal-app-01.
            "data-node-01":    {"role": "app",     "env": "prod", "tags": ["prod", "data-svc"], "ip": "10.45.0.9", "vpcId": VPC_ID},
            "web-tier":       {"role": "web",        "env": "prod", "tags": ["prod"]},
            "app-tier":       {"role": "app",        "env": "prod", "tags": ["prod"]},
            "monitoring":     {"role": "monitoring", "env": "prod", "tags": ["prod"]},
            "ci-runner":      {"role": "ci",         "env": "dev",  "tags": ["dev"]},
            "artifact-store": {"role": "storage",    "env": "dev",  "tags": ["dev"]},
        },
        "policies": [
            # 9443 / `app-admin`, NOT 8443 / `app-east-west`. On 8443 this rule
            # granted app-server-07 the same service to the whole 10.40.0.0/16 that
            # GC-002 grants to one host inside it, so "remove GC-002" deleted the
            # cross-tool path finding and left the flow running underneath it. See
            # the module docstring: the engine does not expand CIDR membership, so
            # a covering twin turns the demo's own remediation beat into a lie.
            {"policy_id": "GC-001", "src_label": "app-server-07", "dst_label": "internal-app",   "port": 9443, "protocol": "tcp", "action": "allow", "ruleset": "app-admin"},
            # The east-west allow to the concrete host. This is the middle hop of
            # the cross-tool path: Guardicore is the only tool that sees it.
            {"policy_id": "GC-002", "src_label": "app-server-07", "dst_label": "internal-app-01", "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "app-east-west"},
            {"policy_id": "GC-010", "src_label": "web-tier",      "dst_label": "app-tier",       "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "tiering"},
            {"policy_id": "GC-011", "src_label": "monitoring",    "dst_label": "app-server-07",  "port": 9100, "protocol": "tcp", "action": "allow", "ruleset": "observability"},
            {"policy_id": "GC-012", "src_label": "ci-runner",     "dst_label": "artifact-store", "port": 443,  "protocol": "tcp", "action": "allow", "ruleset": "ci"},
            # Path B's middle hop, and like GC-002 the only tool on earth that sees
            # it: AlgoSec has never heard of the east-west grant and Wiz has never
            # heard of the database on the far side of it.
            {"policy_id": "GC-030", "src_label": "app-server-08", "dst_label": "data-node-01",  "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "app-east-west"},
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


# --------------------------------------------------------------------------
# The CLEAN estate's policy — the control case.
#
# `demo` proves the analyzers find what is there. These three prove they do not
# invent what is not, which is the harder half and the one a technical evaluator
# actually tests: an engine that always returns findings is indistinguishable
# from one that returns them at random. Measured: ZERO findings from all five
# analyzers, and zero identity-review candidates.
#
# Every address lands inside a VLAN of `estate.build_resilient()` (10.20.0.0/24
# dmz, 10.30.0.0/16 app-tier, 10.50.0.0/24 db-tier, 10.60.0.0/24 users), because
# the two halves of a scenario must be ONE estate: a finding -- if there were one
# -- has to have a floor and a switch port, and "which VLAN is this host in" is
# answered by address containment on the Inventory screen.
#
# WHY EACH ANALYZER RETURNS NOTHING, rule by rule, so nobody later "tidies" one
# of these and quietly turns the control case into a second demo:
#
#   over_permissive     every source is a /32 host object, so E == 0.1 -- below
#                       `sensitive_dest_min_E` (0.3) even for the two grants that
#                       reach the PCI database. There is no 0.0.0.0/0 anywhere.
#   cross_tool_path     there is no internet entry at all. Nothing is
#                       internet-facing in Wiz and no rule sources from
#                       0.0.0.0/0, so `reachability.internet_entries` is empty
#                       and no chain can start.
#   cidr_overlap        no two rules grant the same service to the same
#                       destination from sources where one contains the other.
#                       C-003 and C-004 come closest and their sources are two
#                       disjoint /32s.
#   shadowed_rule       no rule precedes another that it subsumes -- there is no
#                       broad allow at the top of the rulebase, which is the one
#                       thing `demo` has and this does not.
#   transport_exposure  no udp/443 and no `quic` token anywhere, and no
#                       destination is reachable on both tcp and udp of one port.
#
# THIS IS NOT "THE EMPTY STATE". It is a real, plausible, internal-only policy of
# eight least-privilege rules across three consoles, which is a much stronger
# claim than an empty firewall: an export with two rules in it produces no
# findings for the same reason an empty one does.
# --------------------------------------------------------------------------

#: Tenancy for the clean estate's cloud-resident pair. Declared on BOTH sides
#: (AlgoSec and Wiz) so the one merge this fixture contains happens on evidence,
#: exactly as it does in `demo` -- which is what makes `clean`'s "0 identity
#: review candidates" an earned zero rather than an artefact of a fixture with
#: nothing to correlate.
CLEAN_VPC_ID = "vpc-0b41c9e77f25d8a30"


def clean_algosec_export() -> dict:
    return {
        "vendor": "AlgoSec",
        "export_type": "firewall_policy",
        "device": "afa-core-fw-01",
        "generated": "static-clean",
        "objects": {
            "web-lb-01":     {"type": "host", "value": "10.20.0.10", "tags": ["dmz", "prod"]},
            "app-server-01": {"type": "host", "value": "10.30.1.10", "tags": ["prod"], "vpcId": CLEAN_VPC_ID},
            "app-server-02": {"type": "host", "value": "10.30.1.11", "tags": ["prod"], "vpcId": CLEAN_VPC_ID},
            # Regulated, and deliberately so: a clean estate is not one with
            # nothing worth protecting. The two grants that reach it are the
            # narrowest a database grant can be, which is the point.
            "db-prod-01":    {"type": "host", "value": "10.50.0.10", "tags": ["pci", "customer-data", "prod"]},
            "jump-01":       {"type": "host", "value": "10.60.0.10", "tags": ["mgmt"]},
            "mon-01":        {"type": "host", "value": "10.60.0.20", "tags": ["mgmt"]},
        },
        "rules": [
            {"rule_id": "C-001", "order": 1, "src": "web-lb-01",     "dst": "app-server-01", "service": "tcp/8443", "action": "allow", "comment": "published app, front end only"},
            {"rule_id": "C-002", "order": 2, "src": "web-lb-01",     "dst": "app-server-02", "service": "tcp/8443", "action": "allow", "comment": "published app, front end only"},
            {"rule_id": "C-003", "order": 3, "src": "app-server-01", "dst": "db-prod-01",    "service": "tcp/5432", "action": "allow", "comment": "app host to prod db"},
            {"rule_id": "C-004", "order": 4, "src": "app-server-02", "dst": "db-prod-01",    "service": "tcp/5432", "action": "allow", "comment": "app host to prod db"},
            {"rule_id": "C-005", "order": 5, "src": "jump-01",       "dst": "app-server-01", "service": "tcp/22",   "action": "allow", "comment": "jump host only"},
            {"rule_id": "C-006", "order": 6, "src": "jump-01",       "dst": "app-server-02", "service": "tcp/22",   "action": "allow", "comment": "jump host only"},
            {"rule_id": "C-007", "order": 7, "src": "mon-01",        "dst": "app-server-01", "service": "tcp/9100", "action": "allow", "comment": "metrics scrape"},
            {"rule_id": "C-008", "order": 8, "src": "mon-01",        "dst": "app-server-02", "service": "tcp/9100", "action": "allow", "comment": "metrics scrape"},
        ],
    }


def clean_guardicore_export() -> dict:
    """The same grants as Guardicore sees them, on the same hostnames.

    Deliberately OVERLAPPING with AlgoSec rather than disjoint: two consoles
    naming the same hosts is what the identity layer is for, and a control case
    in which nothing correlates would not exercise it. They merge on hostname --
    no shared-IP inference, and nothing withheld for review.
    """
    return {
        "vendor": "Guardicore (Akamai)",
        "export_type": "segmentation_policy",
        "labels": {
            "web-lb-01":     {"role": "web", "env": "prod", "tags": ["dmz", "prod"], "ip": "10.20.0.10"},
            "app-server-01": {"role": "app", "env": "prod", "tags": ["prod"], "ip": "10.30.1.10"},
            "app-server-02": {"role": "app", "env": "prod", "tags": ["prod"], "ip": "10.30.1.11"},
            "mon-01":        {"role": "monitoring", "env": "prod", "tags": ["mgmt"], "ip": "10.60.0.20"},
        },
        "policies": [
            {"policy_id": "GCC-001", "src_label": "web-lb-01", "dst_label": "app-server-01", "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "tiering"},
            {"policy_id": "GCC-002", "src_label": "web-lb-01", "dst_label": "app-server-02", "port": 8443, "protocol": "tcp", "action": "allow", "ruleset": "tiering"},
            {"policy_id": "GCC-003", "src_label": "mon-01",    "dst_label": "app-server-01", "port": 9100, "protocol": "tcp", "action": "allow", "ruleset": "observability"},
            {"policy_id": "GCC-004", "src_label": "mon-01",    "dst_label": "app-server-02", "port": 9100, "protocol": "tcp", "action": "allow", "ruleset": "observability"},
        ],
    }


def clean_wiz_export() -> dict:
    """Two cloud workloads, neither published, and `exposures: []`.

    The empty list is the fixture's sharpest single line. Wiz was ASKED and
    answered "nothing is exposed" -- which is a different card on the Sources
    screen from a Wiz that was never onboarded, and `clean` is the scenario where
    that distinction can be shown rather than asserted.

    There is no internet-facing load balancer, and that is not squeamishness: a
    published three-tier app whose web tier reaches an app tier that reaches a
    PCI database IS a cross-tool path, correctly, and the engine reports two
    critical ones for it. A clean estate cannot have an internet ingress that
    reaches regulated data. The alternative -- keeping the LB and breaking the
    chain by routing the database grant through an abstract segment so
    `_valid_traversal` declines the pivot -- would manufacture a clean result out
    of a documented engine limitation (docs/ENGINE.md 10.2), which is the exact
    cheat this whole scenario exists to disprove.
    """
    return {
        "vendor": "Wiz",
        "export_type": "cloud_exposure",
        "assets": {
            "app-server-01": {"cloud": "aws", "type": "ec2", "internet_facing": False, "ip": "10.30.1.10", "tags": ["prod"], "vpcId": CLEAN_VPC_ID},
            "app-server-02": {"cloud": "aws", "type": "ec2", "internet_facing": False, "ip": "10.30.1.11", "tags": ["prod"], "vpcId": CLEAN_VPC_ID},
        },
        "exposures": [],
    }


def main() -> None:
    """Write the WHOLE demo dataset -- all ten exports, not just these three.

    This used to write the three policy exports and stop, which is what `make
    seed` and `python tasks.py seed` both run. The seven infrastructure exports
    were therefore whatever was committed to git, regenerated only by a manual
    `seed_topology.py`, and free to drift from `src/estate.py` with nothing to
    notice: a fresh clone's topology was a function of the repository's history
    rather than of the code. It also left the estate MIXED whenever this script
    was used to "restore the demo" after running a different scenario -- the demo
    rulebase beside the previous scenario's network.

    Delegated to the scenario writer so there is ONE implementation of "write a
    complete estate", with its atomic swap and its removal half. The import is
    local because `src.scenarios` imports this module for the fixtures below.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src.scenarios import INFRA, POLICY, write_scenario

    write_scenario("demo")
    print(f"wrote {len(POLICY) + len(INFRA)} simulated exports to "
          f"{MOCK_DIR.relative_to(MOCK_DIR.parents[2])}")
    print("  · 3 policy exports with 6 planted problems (incl. BOTH cross-tool paths)")
    print("  · 7 infrastructure exports, each one console's projection of src/estate.py")


if __name__ == "__main__":
    main()


# ===========================================================================
# VENDOR FIREWALL POLICY  (planted problems 7-10)
# ===========================================================================
#
# WHY THESE ARE SEPARATE EXPORTS, and separate normalizer modules.
#
# `fortimanager_export.json` and `junos_space_export.json` carry the DEVICE
# inventory those consoles serve, and `normalizers/fortinet.py` and
# `juniper.py` state in their own docstrings that they emit no PolicyRecord.
# That statement is load-bearing: two test modules assert it, and it is what
# makes "this console contributed devices and interfaces" a checkable claim
# rather than a hope. So policy arrives in its OWN files, read by its OWN
# modules, exactly as `algosec_export` and `algosec_topology_export` already
# split one tool across two files and two readers.
#
# WHAT THEY ARE FOR. Before these, every policy record in the product came from
# AlgoSec, Guardicore or Wiz -- so a client with nine consoles onboarded saw
# findings attributed to three of them and reasonably concluded the rest had
# contributed nothing. A FortiManager that yields no firewall policy is not a
# FortiManager ingest.
#
# THE RULES THESE CANNOT BE. Every source/destination/service triple here was
# chosen to avoid becoming a COVERING TWIN for a grant that an existing finding
# cites: if a Fortinet rule granted the same flow as ALGO-029 or GC-002, then
# "remove ALGO-029" would stop closing the access while continuing to resolve
# the finding, and `verify_engine`'s "cutting a cited grant cuts the ACCESS"
# check would fail. None of these rules touch db-prod-01, db-prod-02,
# internal-app-01, data-node-01, app-server-07 or app-server-08, which is what
# keeps the two cross-tool paths and all four sole grants intact.
#
# THE WILDCARD. FortiOS spells the internet `all` and Junos spells it `any`.
# Both resolve to 0.0.0.0/0 today, but they resolve under their OWN NAMES -- so
# left alone they would become three separate graph nodes all meaning the
# internet, and therefore three separate path origins. The emitters canonicalize
# the NAME onto `0.0.0.0/0` and keep the vendor's own word in the audit row.

#: The FortiManager address catalog, in FortiOS's `ipmask` spelling: the value
#: is an [address, netmask] pair, not a CIDR string.
_FMG_ADDRESSES = [
    {"name": "MGMT-NET", "subnet": ["10.255.0.0", "255.255.255.0"], "type": "ipmask",
     "comment": "out-of-band management, VLAN 10"},
    {"name": "USERS-NET", "subnet": ["10.60.0.0", "255.255.255.0"], "type": "ipmask"},
    {"name": "DEV-NET", "subnet": ["10.31.0.0", "255.255.255.0"], "type": "ipmask"},
    {"name": "DMZ-NET", "subnet": ["10.20.0.0", "255.255.255.0"], "type": "ipmask"},
    {"name": "DB-TIER", "subnet": ["10.50.0.0", "255.255.255.0"], "type": "ipmask",
     "comment": "cardholder data environment"},
]

#: An address GROUP whose members are the names of three of the above. This is
#: the shape that made `object_cidrs` return nothing at all when handed a
#: FortiOS catalog directly, which is why the emitter adapts the catalog into
#: the shared `{name: {value, type, tags}}` form before dereferencing it.
_FMG_GROUPS = [
    {"name": "INTERNAL-NETS", "member": [{"name": "DMZ-NET"}, {"name": "DEV-NET"},
                                         {"name": "USERS-NET"}]},
]


def fortimanager_policy_export() -> dict:
    """FortiManager's policy package, in its JSON-RPC envelope.

    Planted problems 7 and 8:

      7. FMG-perim-hq-1 -- `all` -> MGMT-NET on tcp/22. SSH to the out-of-band
         management segment, from the internet, commented as temporary vendor
         access dated 2019. Forced critical: an admin/lateral-movement port
         reachable from 0.0.0.0/0.
      8. FMG-perim-hq-3 grants INTERNAL-NETS -> DB-TIER on ALL, and
         FMG-perim-hq-4 below it denies DEV-NET -> DB-TIER. DEV-NET is a MEMBER
         of INTERNAL-NETS, so under first-match the deny can never fire -- a
         shadowed deny, which is the anomaly an operator most wants found
         because the intent it states is the one that is not enforced.
    """
    return {
        "id": 1,
        "result": [
            {"url": "/pm/config/adom/root/pkg/default/firewall/policy",
             "status": {"code": 0, "message": "OK"},
             "data": [
                 {"policyid": 1, "name": "perim-hq-1",
                  "srcintf": [{"name": "port1"}, {"name": "port2"}],
                  "dstintf": [{"name": "port3"}],
                  "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "MGMT-NET"}],
                  "service": [{"name": "SSH"}], "action": "accept", "status": "enable",
                  "comments": "vendor support access (temporary, 2019)"},
                 {"policyid": 2, "name": "perim-hq-2",
                  "srcintf": [{"name": "port4"}], "dstintf": [{"name": "port3"}],
                  "srcaddr": [{"name": "USERS-NET"}], "dstaddr": [{"name": "MGMT-NET"}],
                  "service": [{"name": "SSH"}], "action": "accept", "status": "enable",
                  "comments": "helpdesk to switches"},
                 {"policyid": 3, "name": "perim-hq-3",
                  "srcintf": [{"name": "port4"}], "dstintf": [{"name": "port5"}],
                  "srcaddr": [{"name": "INTERNAL-NETS"}], "dstaddr": [{"name": "DB-TIER"}],
                  "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                  "comments": "app/jump access to database (legacy, review)"},
                 {"policyid": 4, "name": "perim-hq-4",
                  "srcintf": [{"name": "port4"}], "dstintf": [{"name": "port5"}],
                  "srcaddr": [{"name": "DEV-NET"}], "dstaddr": [{"name": "DB-TIER"}],
                  "service": [{"name": "ALL"}], "action": "deny", "status": "enable",
                  "comments": "dev must never reach prod db"},
             ]},
            {"url": "/pm/config/adom/root/obj/firewall/address",
             "status": {"code": 0, "message": "OK"}, "data": _FMG_ADDRESSES},
            {"url": "/pm/config/adom/root/obj/firewall/addrgrp",
             "status": {"code": 0, "message": "OK"}, "data": _FMG_GROUPS},
        ],
    }


def fortigate_policy_export() -> dict:
    """The HA primary's own rulebase, read straight off the box.

    Planted problem 9: the DMZ web service is published on tcp/443 AND udp/443.
    The QUIC grant is the finding -- HTTP/3 inside UDP, encrypted end to end, so
    most inspection stacks see an opaque UDP flow rather than the web traffic it
    is. Only `fw-perim-01` carries it: the secondary's config is synced but a
    direct read answers from whichever unit you asked.
    """
    return {
        "fw-perim-01": {
            "cmdb/firewall/policy": {
                "http_method": "GET", "status": "success", "http_status": 200,
                "serial": "FG200F1234567890", "version": "v7.4.3", "vdom": "root",
                "path": "firewall", "name": "policy",
                "results": [
                    {"policyid": 1, "name": "dmz-web",
                     "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port3"}],
                     "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "DMZ-NET"}],
                     "service": [{"name": "HTTPS"}], "action": "accept",
                     "status": "enable", "comments": "published web service"},
                    {"policyid": 2, "name": "dmz-web-h3",
                     "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port3"}],
                     "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "DMZ-NET"}],
                     "service": [{"name": "QUIC"}], "action": "accept",
                     "status": "enable", "comments": "HTTP/3 edge acceleration"},
                ],
            },
            "cmdb/firewall/address": {
                "http_method": "GET", "status": "success", "http_status": 200,
                "path": "firewall", "name": "address",
                "results": [
                    {"name": "DMZ-NET", "subnet": ["10.20.0.0", "255.255.255.0"],
                     "type": "ipmask"},
                ],
            },
        },
    }


def junos_space_policy_export() -> dict:
    """Security Director's edge policy.

    Planted problem 10: `any` -> DMZ-NET on a custom service object covering
    tcp/1-65535, described as a temporary full-port test from a 2019 change
    request. The port RANGE is the point -- it is not a named service, so a
    reader cannot tell what it opens without dereferencing the object, and it
    covers every admin port there is.
    """
    return {
        "/api/juniper/sd/policy-management/firewall/policies": {
            "policies": {
                "@size": 1,
                "policy": [{
                    "name": "edge-inbound",
                    "device": "rtr-edge-02",
                    "rules": {"rule": [
                        {"sequence-number": 10, "name": "full-port-test",
                         "source-zone": "untrust", "destination-zone": "trust",
                         "source-address": {"address": [{"name": "any"}]},
                         "destination-address": {"address": [{"name": "DMZ-NET"}]},
                         "service": {"service": [{"name": "any-tcp"}]},
                         "action": "permit", "enable": "true",
                         "description": "temporary full-port test (change CR-2019-118)"},
                    ]},
                }],
            },
        },
        "/api/juniper/sd/address-management/addresses": {
            "addresses": {"address": [
                {"name": "DMZ-NET", "ip-address": "10.20.0.0", "netmask": "255.255.255.0",
                 "address-type": "NETWORK"},
            ]},
        },
        "/api/juniper/sd/service-management/services": {
            "services": {"service": [
                {"name": "any-tcp", "protocols": {"protocol": [
                    {"name": "tcp", "dst-port": "1-65535"}]}},
            ]},
        },
    }


# --- the clean estate's vendor policy --------------------------------------
#
# `_clean` onboards every console over `estate.build_resilient()` and asserts
# ZERO policy findings. These rules exist so the three vendor consoles keep
# CONTRIBUTING RECORDS in that scenario -- without them their Sources cards
# would read "connected, 0 records" in the one scenario meant to show a
# well-built estate, which reads as a broken ingest rather than a clean network.
#
# Every one is least-privilege on purpose: a management or DMZ source, a
# non-sensitive destination, one named port. None is internet-sourced.

def clean_fortimanager_policy_export() -> dict:
    return {
        "id": 1,
        "result": [
            {"url": "/pm/config/adom/root/pkg/default/firewall/policy",
             "status": {"code": 0, "message": "OK"},
             "data": [
                 {"policyid": 1, "name": "dmz-to-app",
                  "srcintf": [{"name": "port3"}], "dstintf": [{"name": "port5"}],
                  "srcaddr": [{"name": "DMZ-NET"}], "dstaddr": [{"name": "APP-NET"}],
                  "service": [{"name": "HTTPS"}], "action": "accept", "status": "enable",
                  "comments": "published app tier"},
                 {"policyid": 2, "name": "mgmt-to-app",
                  "srcintf": [{"name": "port2"}], "dstintf": [{"name": "port5"}],
                  "srcaddr": [{"name": "MGMT-NET"}], "dstaddr": [{"name": "APP-NET"}],
                  "service": [{"name": "SSH"}], "action": "accept", "status": "enable",
                  "comments": "operations access from the OOB segment"},
             ]},
            {"url": "/pm/config/adom/root/obj/firewall/address",
             "status": {"code": 0, "message": "OK"},
             "data": [
                 {"name": "MGMT-NET", "subnet": ["10.255.0.0", "255.255.255.0"], "type": "ipmask"},
                 {"name": "DMZ-NET", "subnet": ["10.20.0.0", "255.255.255.0"], "type": "ipmask"},
                 {"name": "APP-NET", "subnet": ["10.30.0.0", "255.255.0.0"], "type": "ipmask"},
             ]},
        ],
    }


def clean_fortigate_policy_export() -> dict:
    return {
        "fw-perim-01": {
            "cmdb/firewall/policy": {
                "http_method": "GET", "status": "success", "http_status": 200,
                "path": "firewall", "name": "policy",
                "results": [
                    {"policyid": 1, "name": "mgmt-to-dmz",
                     "srcintf": [{"name": "port2"}], "dstintf": [{"name": "port3"}],
                     "srcaddr": [{"name": "MGMT-NET"}], "dstaddr": [{"name": "DMZ-NET"}],
                     "service": [{"name": "SSH"}], "action": "accept",
                     "status": "enable", "comments": "operations access"},
                ],
            },
            "cmdb/firewall/address": {
                "http_method": "GET", "status": "success", "http_status": 200,
                "path": "firewall", "name": "address",
                "results": [
                    {"name": "MGMT-NET", "subnet": ["10.255.0.0", "255.255.255.0"], "type": "ipmask"},
                    {"name": "DMZ-NET", "subnet": ["10.20.0.0", "255.255.255.0"], "type": "ipmask"},
                ],
            },
        },
    }


def clean_junos_space_policy_export() -> dict:
    return {
        "/api/juniper/sd/policy-management/firewall/policies": {
            "policies": {"@size": 1, "policy": [{
                "name": "edge-inbound", "device": "rtr-edge-02",
                "rules": {"rule": [
                    {"sequence-number": 10, "name": "metrics-scrape",
                     "source-zone": "trust", "destination-zone": "trust",
                     "source-address": {"address": [{"name": "MGMT-NET"}]},
                     "destination-address": {"address": [{"name": "APP-NET"}]},
                     "service": {"service": [{"name": "node-exporter"}]},
                     "action": "permit", "enable": "true",
                     "description": "prometheus scrape"},
                ]},
            }]},
        },
        "/api/juniper/sd/address-management/addresses": {
            "addresses": {"address": [
                {"name": "MGMT-NET", "ip-address": "10.255.0.0",
                 "netmask": "255.255.255.0", "address-type": "NETWORK"},
                {"name": "APP-NET", "ip-address": "10.30.0.0",
                 "netmask": "255.255.0.0", "address-type": "NETWORK"},
            ]},
        },
        "/api/juniper/sd/service-management/services": {
            "services": {"service": [
                {"name": "node-exporter", "protocols": {"protocol": [
                    {"name": "tcp", "dst-port": "9100"}]}},
            ]},
        },
    }
