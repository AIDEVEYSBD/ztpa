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
# L7 application identity (App-ID) decoding -- categorical, never computed.
# --------------------------------------------------------------------------
# The transport layer alone (tcp/udp + port) under-describes a rule: udp/443 is
# QUIC/HTTP-3, and most legacy firewalls cannot inspect it. We decode an L7 app
# tag from two sources, both deterministic and audit-flagged (l7_source):
#   - "declared": the source export carried an explicit App-ID token.
#   - "inferred": a fixed (protocol, port) -> app lookup in this table.
# Neither path calls a model. Unknown (protocol, port) -> no l7 tag.

# App-ID tokens we recognize when a source names a service by application, not
# by port (e.g. AlgoSec service "quic", a Guardicore policy "app": "http3").
L7_APPS = {
    "http", "https", "tls", "ssl", "http2", "quic", "http3", "doq", "dns-over-quic",
    "dns", "ssh", "rdp", "smb", "ldap", "ldaps", "ntp", "syslog", "kerberos",
    "mysql", "postgresql", "postgres", "mssql", "mongodb", "redis", "kubernetes",
}

# An App-ID names the application; the transport it rides is fixed. Used to
# resolve a bare app token (e.g. "quic") back to (protocol, port) so the L4
# facts stay populated alongside the L7 tag.
APP_TRANSPORT: dict[str, tuple[str, int]] = {
    "quic": ("udp", 443), "http3": ("udp", 443), "doq": ("udp", 853),
    "dns-over-quic": ("udp", 853),
    "https": ("tcp", 443), "tls": ("tcp", 443), "ssl": ("tcp", 443),
    "http2": ("tcp", 443), "http": ("tcp", 80),
    "dns": ("udp", 53), "ssh": ("tcp", 22), "rdp": ("tcp", 3389), "smb": ("tcp", 445),
    "ldap": ("tcp", 389), "ldaps": ("tcp", 636), "ntp": ("udp", 123),
    "syslog": ("udp", 514), "kerberos": ("tcp", 88),
    "mysql": ("tcp", 3306), "postgresql": ("tcp", 5432), "postgres": ("tcp", 5432),
    "mssql": ("tcp", 1433), "mongodb": ("tcp", 27017), "redis": ("tcp", 6379),
}

# Deterministic L4 -> likely L7 inference: (protocol, port) -> app tag.
# This is the lookup that lets a plain "udp/443" rule be decoded as QUIC.
APP_BY_PORT: dict[tuple[str, int], str] = {
    ("udp", 443): "quic", ("udp", 80): "http3-discovery",
    ("udp", 853): "dns-over-quic", ("udp", 53): "dns", ("tcp", 53): "dns",
    ("tcp", 443): "tls", ("tcp", 8443): "tls", ("tcp", 80): "http", ("tcp", 8080): "http",
    ("tcp", 22): "ssh", ("tcp", 3389): "rdp", ("tcp", 445): "smb",
    ("tcp", 389): "ldap", ("tcp", 636): "ldaps", ("udp", 123): "ntp", ("udp", 514): "syslog",
    ("tcp", 5432): "postgresql", ("tcp", 3306): "mysql", ("tcp", 1433): "mssql",
    ("tcp", 27017): "mongodb", ("tcp", 6379): "redis", ("tcp", 6443): "kubernetes",
}

# Applications that ride encrypted and/or UDP transports legacy firewalls
# typically cannot decrypt or inspect. A reachable allow on one of these is an
# inspection blind spot -- the class of risk this feature surfaces.
INSPECTION_BLIND_APPS = {"quic", "http3", "doq", "dns-over-quic", "http3-discovery"}

# --------------------------------------------------------------------------
# Transport / application-layer exposure (transport_exposure) knobs.
# --------------------------------------------------------------------------
TRANSPORT_CONFIG: dict = {
    # Added to the smooth severity when the exposed app is uninspectable.
    "blind_spot_bump": 15,
    # tcp/443 AND udp/443 both allowed to one dest: an inspectable TLS path
    # exists yet QUIC can silently win -- you cannot force inspection. Fixed base
    # (a hygiene/control-gap finding), bumped if the dest is sensitive.
    "fallback_base": 40,
    "fallback_sensitive_bump": 20,
    # The (protocol, port) pairs whose simultaneous presence trips the
    # "fallback not blocked" check.
    "fallback_pairs": [(("tcp", 443), ("udp", 443))],
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
# AI cost model -- USD per 1M tokens, {input, output}, keyed by provider:model.
# Local Ollama models are $0 (the data-residency + zero-per-call-cost story).
# Hosted prices are list prices for the configured default models; unknown
# models fall through to PRICE_UNKNOWN (cost 0, flagged) so the dashboard never
# invents a number. Keep these as tunable knobs, like the severity weights.
# --------------------------------------------------------------------------
PRICE_PER_MTOK: dict[str, dict[str, float]] = {
    # Anthropic (list price per 1M tokens)
    "anthropic:claude-opus-4-8": {"in": 5.0, "out": 25.0},
    "anthropic:claude-sonnet-4-6": {"in": 3.0, "out": 15.0},
    "anthropic:claude-haiku-4-5": {"in": 1.0, "out": 5.0},
    # OpenAI
    "openai:gpt-4o": {"in": 2.5, "out": 10.0},
    "openai:gpt-4o-mini": {"in": 0.15, "out": 0.6},
    "openai:text-embedding-3-small": {"in": 0.02, "out": 0.0},
}
PRICE_UNKNOWN = {"in": 0.0, "out": 0.0}


def price_for(provider: str, model: str) -> dict[str, float]:
    """Per-MTok {in, out} for a provider:model. Ollama (local) is always free."""
    if provider == "ollama":
        return {"in": 0.0, "out": 0.0}
    return PRICE_PER_MTOK.get(f"{provider}:{model}", PRICE_UNKNOWN)


def est_cost_usd(provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> float:
    p = price_for(provider, model)
    return round((prompt_tokens / 1_000_000) * p["in"] + (completion_tokens / 1_000_000) * p["out"], 6)


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
