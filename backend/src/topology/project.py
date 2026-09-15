"""Shape the reconstructed topology into rows, once.

Both the persistence layer and the API's degraded path use these functions, for
the reason `main._graph_payload` gives about the policy graph: two copies of
"what a row looks like" drift, and the only place the drift shows is the
fallback path, which is by definition the one nobody exercises until something
is already wrong.

So `persist.persist_engine_result` writes exactly what `_memory_fallback` would
serve, and a column added here reaches both.
"""

from __future__ import annotations

from ..models import Topology


def device_rows(sid: str, t: Topology) -> list[dict]:
    return [{
        "snapshot_id": sid,
        "device_key": d.device_key,
        "name": d.name,
        "role": d.role,
        "role_source": d.role_source,
        "role_reason": d.role_reason,
        "vendor": d.vendor,
        "model": d.model,
        "os_version": d.os_version,
        "serial": d.serial,
        "mgmt_ip": d.mgmt_ip,
        "site": d.site,
        "ha_group": d.ha_group,
        "ha_role": d.ha_role,
        "layer": d.layer,
        "layer_source": d.layer_source,
        "layer_reason": d.layer_reason,
        "tags": list(d.tags),
        "source_tool": d.provenance.source_tool,
        "source_tier": d.provenance.source_tier,
        "raw_ref": d.provenance.raw_ref,
        "simulated": d.provenance.simulated,
    } for d in t.devices]


def interface_rows(sid: str, t: Topology) -> list[dict]:
    return [{
        "snapshot_id": sid,
        "interface_key": i.interface_key,
        "device_key": i.device_key,
        "name": i.name,
        "description": i.description,
        "addresses": list(i.addresses),
        "networks_behind": list(i.networks_behind),
        "vlan_id": i.vlan_id,
        "zone": i.zone,
        # Written as-is including None. The column is nullable precisely so that
        # "the source did not report link state" survives the round trip; a
        # coalesce to false here would invent an outage at persist time.
        "admin_up": i.admin_up,
        "oper_up": i.oper_up,
        "speed_mbps": i.speed_mbps,
        "lag_group": i.lag_group,
        "mac": i.mac,
        "neighbor_device": i.neighbor_device,
        "neighbor_interface": i.neighbor_interface,
        "source_tool": i.provenance.source_tool,
        "source_tier": i.provenance.source_tier,
        "raw_ref": i.provenance.raw_ref,
        "simulated": i.provenance.simulated,
    } for i in t.interfaces]


def link_rows(sid: str, t: Topology) -> list[dict]:
    return [{
        "snapshot_id": sid,
        "link_key": l.link_key,
        "a_device": l.a_device,
        "a_interface": l.a_interface,
        "b_device": l.b_device,
        "b_interface": l.b_interface,
        "evidence": l.evidence,
        "evidence_detail": l.evidence_detail,
        "redundant_group": l.redundant_group,
        "aggregated": l.aggregated,
        "member_count": l.member_count,
        "source_tool": l.provenance.source_tool,
        "source_tier": l.provenance.source_tier,
        "simulated": l.provenance.simulated,
    } for l in t.links]


def vlan_rows(sid: str, t: Topology) -> list[dict]:
    return [{
        "snapshot_id": sid,
        "vlan_id": v.vlan_id,
        "name": v.name,
        "subnets": list(v.subnets),
        "gateways": list(v.gateways),
        "device_keys": list(v.device_keys),
        "tags": list(v.tags),
        "source_tool": v.provenance.source_tool,
        "source_tier": v.provenance.source_tier,
        "raw_ref": v.provenance.raw_ref,
        "simulated": v.provenance.simulated,
    } for v in t.vlans]


def subnet_rows(sid: str, t: Topology) -> list[dict]:
    return [{
        "snapshot_id": sid,
        "cidr": s.cidr,
        "name": s.name,
        "vlan_id": s.vlan_id,
        "gateways": list(s.gateways),
        "device_keys": list(s.device_keys),
        "zone": s.zone,
        "tags": list(s.tags),
        "source_tool": s.provenance.source_tool,
        "source_tier": s.provenance.source_tier,
        "raw_ref": s.provenance.raw_ref,
        "simulated": s.provenance.simulated,
    } for s in t.subnets]


def circuit_rows(sid: str, t: Topology) -> list[dict]:
    return [{
        "snapshot_id": sid,
        "circuit_id": c.circuit_id,
        "provider": c.provider,
        "technology": c.technology,
        "bandwidth_mbps": c.bandwidth_mbps,
        "public_ips": list(c.public_ips),
        "device_key": c.device_key,
        "interface": c.interface,
        "state": c.state,
        "source_tool": c.provenance.source_tool,
        "source_tier": c.provenance.source_tier,
        "raw_ref": c.provenance.raw_ref,
        "simulated": c.provenance.simulated,
    } for c in t.circuits]
