"""Deterministic severity: the four sub-scores (all by lookup), the
multiplicative combination, the bands, and the guardrail floor (BUILD_SPEC s6).

risk = likelihood x impact, with impact capped by destination value so a
dev-sandbox finding can never out-rank a crown-jewel one. The floor is separate:
categorically-unacceptable patterns are force-flagged critical regardless of the
smooth score, so no model error downstream can bury a true emergency.
"""

from __future__ import annotations

import ipaddress

from ..config import (
    ADMIN_LATERAL_PORTS, DATA_STORE_PORTS, D_UNTAGGED, EXPOSURE_BANDS, E_IDENTITY,
    GENERAL_APP_PORTS, INFRA_CONTROL_PORTS, P_ADMIN, P_ANY_PORT, P_DATA_STORE,
    P_GENERAL_APP, P_INFRA_CONTROL, P_UNKNOWN, PORT_CLASS_LABEL, SENSITIVE_TAGS,
    SEVERITY_CONFIG, TAG_SENSITIVITY, TRANSPORT_CONFIG,
)
from ..graph.zones import boundary_multiplier
from ..normalizers.common import parse_service


# --- the four sub-scores (categorical lookups; never computed) -------------

def exposure_score(source: str, source_kind: str) -> float:
    """E: exposure breadth from source prefix length; identities -> 0.1."""
    if source_kind == "identity":
        return E_IDENTITY
    try:
        prefixlen = ipaddress.ip_network(source, strict=False).prefixlen
    except ValueError:
        return E_IDENTITY
    for max_prefixlen, e in EXPOSURE_BANDS:
        if prefixlen <= max_prefixlen:
            return e
    return E_IDENTITY


def port_score(protocol: str | None, port: int | None) -> tuple[float, str]:
    """P: the kind of access granted (admin/data/infra/app/any/unknown)."""
    if protocol == "any":
        return P_ANY_PORT, PORT_CLASS_LABEL[P_ANY_PORT]
    if port in ADMIN_LATERAL_PORTS:
        return P_ADMIN, PORT_CLASS_LABEL[P_ADMIN]
    if port in DATA_STORE_PORTS:
        return P_DATA_STORE, PORT_CLASS_LABEL[P_DATA_STORE]
    if port in INFRA_CONTROL_PORTS:
        return P_INFRA_CONTROL, PORT_CLASS_LABEL[P_INFRA_CONTROL]
    if port in GENERAL_APP_PORTS:
        return P_GENERAL_APP, PORT_CLASS_LABEL[P_GENERAL_APP]
    return P_UNKNOWN, PORT_CLASS_LABEL[P_UNKNOWN]


def port_score_from_service(service: str | None) -> tuple[float, str]:
    if not service:
        return port_score("tcp", None)
    svc = parse_service(service)
    return port_score(svc.protocol, svc.port)


def dest_score(tags: list[str]) -> float:
    """D: max sensitivity over the destination's tags; untagged -> 0.4."""
    if not tags:
        return D_UNTAGGED
    return max((TAG_SENSITIVITY.get(t, D_UNTAGGED) for t in tags), default=D_UNTAGGED)


# --- combination + bands ---------------------------------------------------

def severity_from_vector(E: float, P: float, D: float, B: float) -> int:
    c = SEVERITY_CONFIG
    impact = D * (c["impact_base"] + c["impact_p_weight"] * P)        # capped by D
    exposure_factor = c["exposure_floor"] + c["exposure_span"] * E    # floored
    raw = impact * exposure_factor * B
    return round(100 * min(raw, 1.0))


def band(severity: int) -> str:
    c = SEVERITY_CONFIG
    if severity >= c["band_critical"]:
        return "critical"
    if severity >= c["band_high"]:
        return "high"
    if severity >= c["band_medium"]:
        return "medium"
    return "low"


def _is_internet(E: float) -> bool:
    return E >= 1.0          # only 0.0.0.0/0 yields E == 1.0


# --- per-type scoring (BUILD_SPEC s6.5) ------------------------------------

def score_over_permissive(*, source, source_kind, protocol, port, dest_tags,
                          src_zone, dst_zone) -> dict:
    E = exposure_score(source, source_kind)
    P, p_class = port_score(protocol, port)
    D = dest_score(dest_tags)
    B = boundary_multiplier(src_zone, dst_zone)
    severity = severity_from_vector(E, P, D, B)

    forced, reasons = False, []
    sensitive = bool(set(dest_tags) & SENSITIVE_TAGS)
    if _is_internet(E) and protocol == "any":
        forced, _ = True, reasons.append("internet any/any")
    if _is_internet(E) and port in ADMIN_LATERAL_PORTS:
        forced, _ = True, reasons.append("admin/lateral-movement port exposed to the internet")
    if sensitive and _is_internet(E):
        forced, _ = True, reasons.append("regulated/crown-jewel asset reachable from the internet")
    return {
        "severity": severity,
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": forced,
        "forced_reasons": reasons,
        "port_class": p_class,
        "E": E, "P": P, "D": D, "B": B,
    }


def score_transport_exposure(*, subtype, source, source_kind, protocol, port, l7_app,
                             dest_tags, src_zone, dst_zone) -> dict:
    """Severity for transport-/application-layer exposure findings.

    quic_blind_spot: the smooth vector + a bump for the uninspectable app, forced
    critical when it crosses a boundary or reaches a sensitive asset from the
    internet. tls_fallback_not_blocked: a fixed control-gap base (you can't force
    the inspectable path), bumped for a sensitive destination.
    """
    E = exposure_score(source, source_kind)
    P, p_class = port_score(protocol, port)
    D = dest_score(dest_tags)
    B = boundary_multiplier(src_zone, dst_zone)
    base = severity_from_vector(E, P, D, B)
    tc = TRANSPORT_CONFIG
    sensitive = bool(set(dest_tags) & SENSITIVE_TAGS)

    forced, reasons = False, []
    if subtype == "tls_fallback_not_blocked":
        severity = tc["fallback_base"] + (tc["fallback_sensitive_bump"] if sensitive else 0)
    else:  # quic_blind_spot
        severity = base + tc["blind_spot_bump"]
        if _is_internet(E) and (B > 1.0 or sensitive):
            forced = True
            reasons.append(f"uninspectable app ({l7_app}) reachable from the internet to "
                           f"{'a regulated/crown-jewel asset' if sensitive else 'an internal asset'}")
    return {
        "severity": min(severity, 100),
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": forced,
        "forced_reasons": reasons,
        "port_class": p_class,
    }


def score_cross_tool_path(path: dict) -> dict:
    entry = path.get("entry", "")
    entry_kind = "cidr" if "/" in entry else "identity"
    E = exposure_score(entry, entry_kind)
    P, p_class = port_score_from_service(path.get("terminal_service"))
    D = dest_score(path.get("terminal_tags", []))
    B = float(path.get("boundary_multiplier", 1.0))
    severity = severity_from_vector(E, P, D, B)

    reaches_sensitive = bool(set(path.get("terminal_tags", [])) & SENSITIVE_TAGS)
    internet_to_internal = path.get("boundary") == "internet->internal"
    forced = bool(internet_to_internal and reaches_sensitive)
    reasons = []
    if forced:
        reasons.append("cross-tool path crosses internet->internal and reaches a sensitive asset")
    return {
        "severity": severity,
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": forced,
        "forced_reasons": reasons,
        "reaches_sensitive": reaches_sensitive,
        "port_class": p_class,
    }


def score_overlap(*, dest_tags_a, dest_tags_b, source_a, source_kind_a,
                  source_b, source_kind_b) -> int:
    c = SEVERITY_CONFIG
    severity = c["overlap_base"]
    sensitive = bool((set(dest_tags_a) | set(dest_tags_b)) & SENSITIVE_TAGS)

    def is_broad(source: str, kind: str) -> bool:
        if kind != "cidr":
            return False
        try:
            return ipaddress.ip_network(source, strict=False).prefixlen <= c["overlap_broad_prefixlen"]
        except ValueError:
            return False

    if sensitive or is_broad(source_a, source_kind_a) or is_broad(source_b, source_kind_b):
        severity += c["overlap_sensitive_bump"]
    return severity


def score_shadowed(*, shadowed_action, source, source_kind, protocol, port,
                   dest_tags, src_zone, dst_zone) -> dict:
    if shadowed_action == "allow":
        # dead allow config -- low fixed; carries no effective exposure
        return {"severity": SEVERITY_CONFIG["shadowed_allow_base"], "vector": {}, "forced_critical": False}
    # shadowed deny: traffic you intended to block is actually permitted by the
    # earlier broad allow -> score the full formula on that effective exposure.
    E = exposure_score(source, source_kind)
    P, _ = port_score(protocol, port)
    D = dest_score(dest_tags)
    B = boundary_multiplier(src_zone, dst_zone)
    return {
        "severity": severity_from_vector(E, P, D, B),
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": False,
    }


def prefixlen_of(source: str, source_kind: str) -> int | None:
    if source_kind != "cidr":
        return None
    try:
        return ipaddress.ip_network(source, strict=False).prefixlen
    except ValueError:
        return None
