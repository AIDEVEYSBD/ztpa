"""Calibration knobs + categorical lookups for the deterministic engine.

Per BUILD_SPEC section 6: exposure breadth, port sensitivity, and tag
sensitivity are *categorical policy facts* — they are looked up here, never
computed. Every number is a tunable knob; the *shape* of the combination
(in severity.py) is the engineering. Keeping them in one place means scoring
can be recalibrated without touching logic, and re-runs stay byte-identical.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Port / service sensitivity (P) — the kind of access a rule grants.
# --------------------------------------------------------------------------
# Friendly names for display + explanation grounding.
PORT_NAMES: dict[int, str] = {
    22: "SSH", 23: "Telnet", 135: "RPC", 445: "SMB",
    3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS",
    5432: "PostgreSQL", 3306: "MySQL", 1433: "MSSQL",
    27017: "MongoDB", 6379: "Redis",
    6443: "Kubernetes API", 2379: "etcd",
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    53: "DNS", 123: "NTP", 514: "Syslog", 9090: "Prometheus", 9100: "node-exporter",
}

# Port classes -> P value. Membership is by explicit port set; everything else
# falls through to the "general app" / "unknown" defaults below.
ADMIN_LATERAL_PORTS = {22, 23, 135, 445, 3389, 5985, 5986}   # P = 1.0
DATA_STORE_PORTS = {5432, 3306, 1433, 27017, 6379}            # P = 0.9
INFRA_CONTROL_PORTS = {6443, 2379}                            # P = 0.85
GENERAL_APP_PORTS = {80, 443, 8080, 8443, 53, 123}            # P = 0.4

P_ANY_PORT = 1.0          # protocol "any"
P_ADMIN = 1.0             # admin / lateral-movement
P_DATA_STORE = 0.9
P_INFRA_CONTROL = 0.85
P_GENERAL_APP = 0.4
P_UNKNOWN = 0.5           # unmatched / ephemeral

PORT_CLASS_LABEL = {
    P_ANY_PORT: "any-port",
    P_ADMIN: "admin / lateral-movement",
    P_DATA_STORE: "data store",
    P_INFRA_CONTROL: "infra control plane",
    P_GENERAL_APP: "general app / web",
    P_UNKNOWN: "unknown / ephemeral",
}

# --------------------------------------------------------------------------
# Destination sensitivity (D) — max over the destination's tags.
# --------------------------------------------------------------------------
TAG_SENSITIVITY: dict[str, float] = {
    "crown-jewel": 1.0,
    "pci": 0.9, "customer-data": 0.9, "phi": 0.9,
    "prod": 0.6,
    "dev": 0.2, "sandbox": 0.2, "test": 0.2,
}
D_UNTAGGED = 0.4          # untagged / internal default

# Tags that mark a destination "sensitive" for guardrail / over-permissive logic.
SENSITIVE_TAGS = {"crown-jewel", "pci", "customer-data", "phi"}

# --------------------------------------------------------------------------
# Exposure breadth (E) — from source prefix length. Identity sources -> 0.1.
# Stored as (max_prefixlen_inclusive, E) bands, checked in ascending order.
# --------------------------------------------------------------------------
EXPOSURE_BANDS: list[tuple[int, float]] = [
    (0, 1.0),    # /0  -> 1.0 (also "any")
    (8, 0.9),    # /1 .. /8
    (16, 0.7),   # /9 .. /16
    (23, 0.5),   # /17 .. /23
    (27, 0.3),   # /24 .. /27
    (32, 0.1),   # /28 .. /32
]
E_IDENTITY = 0.1          # single identity / label source

# --------------------------------------------------------------------------
# Zones + boundary crossing (B) — multiplier, not an additive term.
# --------------------------------------------------------------------------
# Zone is derived from tags / source kind (see graph.zones.zone_of).
ZONE_INTERNET = "internet"
ZONE_DMZ = "dmz"
ZONE_DEV = "dev"
ZONE_INTERNAL = "internal"   # prod / internal default

# (src_zone, dst_zone) -> multiplier. Unlisted pairs default to 1.0.
# NB: internet -> dmz is intentionally absent: a DMZ asset is *meant* to be
# internet-facing, so that direction is expected (1.0), not a boundary crossing.
BOUNDARY_MULTIPLIERS: dict[tuple[str, str], float] = {
    (ZONE_INTERNET, ZONE_INTERNAL): 1.5,
    (ZONE_DMZ, ZONE_INTERNAL): 1.25,
    (ZONE_DEV, ZONE_INTERNAL): 1.25,   # dev -> prod
}
B_INTRA = 1.0

# Tags that place a node in a zone. Only the literal internet node (0.0.0.0/0)
# is ZONE_INTERNET; an internet-facing asset sits in the DMZ.
ZONE_TAGS = {
    "dmz": ZONE_DMZ, "internet-facing": ZONE_DMZ, "public": ZONE_DMZ,
    "dev": ZONE_DEV, "sandbox": ZONE_DEV, "test": ZONE_DEV,
}
# Priority when a node carries multiple zone tags (most-exposed wins).
ZONE_PRIORITY = [ZONE_DMZ, ZONE_DEV]

# --------------------------------------------------------------------------
# Severity combination + bands + per-type knobs (BUILD_SPEC 6.2 / 6.3 / 6.5).
# --------------------------------------------------------------------------
SEVERITY_CONFIG: dict = {
    # severity = round(100 * min(impact * exposure_factor * B, 1.0))
    # impact          = D * (impact_base + impact_p_weight * P)
    # exposure_factor = exposure_floor + exposure_span * E
    "impact_base": 0.5,
    "impact_p_weight": 0.5,
    "exposure_floor": 0.4,
    "exposure_span": 0.6,
    # Bands (lower-inclusive thresholds).
    "band_critical": 80,
    "band_high": 60,
    "band_medium": 35,
    # cidr_overlap: hygiene, not exposure (stays in the low band even when bumped).
    "overlap_base": 10,
    "overlap_sensitive_bump": 20,    # +bump if either rule touches sensitive dest or broad (<= /8) source
    "overlap_broad_prefixlen": 8,    # "broad source" threshold for the bump
    # shadowed_rule.
    "shadowed_allow_base": 10,       # dead allow config — low fixed
    # (shadowed deny scores via the full formula on the traffic it failed to block)
}

# --------------------------------------------------------------------------
# Over-permissive detection predicate knobs.
# --------------------------------------------------------------------------
OVERPERMISSIVE_CONFIG: dict = {
    # A broad source for "admin/data port from a broad range" — E threshold.
    "broad_source_E": 0.5,           # /23 or broader
    # Exposing a sensitive dest from anything wider than a single host.
    "sensitive_dest_min_E": 0.3,     # /27 or broader
    "admin_data_min_P": 0.85,        # admin / data / infra-control ports
}
