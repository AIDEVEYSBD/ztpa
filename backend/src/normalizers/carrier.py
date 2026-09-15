"""Carrier-portal normalizer: a service-order extract -> circuits, CPE, demarc.

This is the only source in the registry that sees the modem layer, so it is the
only one that can answer the question the resilience analyzer exists to ask:
whether two diverse-looking circuits are sold by one carrier. Everything it
emits is infrastructure — it produces no PolicyRecords, because a carrier has no
policy to report, and a normalizer that invented one would move a snapshot
fingerprint that nothing about this source should be able to move.

What it refuses to do
---------------------
  * It does not report link state. The extract's `status` is the CIRCUIT's, and
    `NetInterface.admin_up` is left None on every port it emits. A standby ISDN
    circuit's CPE port is not "down", and "the source did not say" is a
    different fact from "the port is down" — the column is three-valued for
    exactly this case.
  * It does not emit the handoff ROUTER as a device. The order names it, so the
    link is emitted and evidenced as `declared`; but naming a box is not
    observing it, and a carrier portal that enumerated the customer's routers
    would be a carrier portal that does not exist.
  * It does not read a missing circuit list as an estate with no way out. An
    absent `circuits` key is a failed or truncated export and raises; an empty
    list is a portal with nothing on it and normalizes to nothing.
"""

from __future__ import annotations

from typing import Optional

from ..models import Circuit, NetDevice, NetInterface, NetLink, Provenance
from ..netaddr import parse_net
from ..sources import tier_of
from .common import NormalizeResult
from .profile import NormalizeError

TOOL = "carrier_portal"
TIER = tier_of(TOOL)

# `models.CircuitTechnology` and `models.Circuit.state`, as sets we can test
# membership against. A token outside them becomes "unknown" rather than the
# nearest-looking member: a portal that starts writing "Ethernet-P2P" must widen
# the model deliberately, not get silently filed under `p2p` by a normalizer.
_TECHNOLOGIES = frozenset({"mpls", "p2p", "isdn", "broadband", "fiber", "lte", "satellite"})
_STATES = frozenset({"up", "down", "standby"})


def _text(row: dict, key: str) -> Optional[str]:
    """A trimmed string field, or None for absent/blank/non-string.

    Blank collapses to None on purpose. `cpe_serial: ""` on a service order
    means the order does not carry one, and storing the empty string would put a
    serial column on screen that looks populated and identifies nothing.
    """
    value = row.get(key)
    return value.strip() or None if isinstance(value, str) else None


def _mbps(row: dict, key: str) -> Optional[int]:
    """An integer bandwidth, or None. `bool` is excluded — `True` is not 1 Mbps."""
    value = row.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _provenance(raw_ref: str) -> Provenance:
    """Every fact from this source traces back to a CIRCUIT ID.

    Not to a serial: the portal indexes its CPE by the circuit it was installed
    for, most orders carry no serial at all, and inventing one to make a key
    would break the one trail an operator can actually follow back into the
    portal.
    """
    return Provenance(source_tool=TOOL, source_tier=TIER, raw_ref=raw_ref, simulated=True)


def _technology(row: dict) -> str:
    value = (_text(row, "service_type") or "").lower()
    return value if value in _TECHNOLOGIES else "unknown"


def _state(row: dict) -> str:
    value = (_text(row, "status") or "").lower()
    return value if value in _STATES else "unknown"


def _wan_addresses(row: dict, circuit_id: str) -> list[str]:
    """The assigned public block, verbatim.

    NOT canonicalized to its network. `203.0.113.1/29` and `203.0.113.0/29` are
    different facts about a WAN port — which address in the block the port holds
    is exactly what an operator needs — and `Subnet.cidr` is where canonical
    blocks belong.

    A token that claims to be address space and is not raises rather than being
    dropped: this field is the customer's entire public footprint on that
    circuit, and losing it silently would understate internet exposure.
    """
    block = _text(row, "wan_ip_block")
    if block is None:
        return []
    if parse_net(block) is None:
        raise NormalizeError(
            f"{TOOL}: circuit {circuit_id!r} carries wan_ip_block {block!r}, which is "
            f"not address space; the assigned public block cannot be guessed"
        )
    return [block]


def _rows(raw: dict) -> list[dict]:
    """The circuit rows, or a diagnosable failure.

    An absent (or non-list) `circuits` key is a download that did not complete.
    A portal extract that cannot be read must not arrive as an estate with no
    circuits in it — "no way out to the internet" is a conclusion a reviewer
    would act on, and it would be false.
    """
    rows = raw.get("circuits")
    if not isinstance(rows, list):
        raise NormalizeError(
            f"{TOOL}: the extract carries no 'circuits' list (got "
            f"{type(rows).__name__}); an unreadable export is not a portal with "
            f"no circuits on it"
        )
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise NormalizeError(
                f"{TOOL}: circuit row #{index} is a {type(row).__name__}, not a record"
            )
    return rows


def _device(row: dict, circuit_id: str) -> Optional[NetDevice]:
    """The CPE, as the service order describes it.

    `role_source='declared'`: the order says outright that this is the customer
    premises equipment terminating the circuit. That is a statement of type, not
    an inference from what it terminates, so the reconstruction engine leaves it
    alone.

    `os_version` stays None even though the estate knows the firmware — a
    service order records what was sold, not what is running. The identity layer
    fills that in from a source that actually read the box, if one is onboarded,
    and reports the lane as unfilled if none is.
    """
    name = _text(row, "cpe_name")
    if name is None:
        return None
    return NetDevice(
        device_key=name,
        name=name,
        role="modem",
        role_source="declared",
        role_reason=f"the carrier's service order for {circuit_id} lists it as the "
                    f"CPE terminating the circuit",
        vendor=_text(row, "carrier"),
        model=_text(row, "cpe_model"),
        serial=_text(row, "cpe_serial"),
        # The order states a management ADDRESS. It does not state which port
        # holds it, so no interface is invented to carry it.
        mgmt_ip=_text(row, "cpe_mgmt_ip"),
        site=_text(row, "demarc_location"),
        provenance=_provenance(circuit_id),
    )


def _interfaces(row: dict, device_key: str, circuit_id: str) -> list[NetInterface]:
    """The CPE's WAN port, and the port it hands off on.

    Both carry `admin_up=None`: see the module docstring. The handoff port
    carries no address either — the carrier assigns the WAN block and hands off
    on a port; whatever the customer configured on the inside of the demarc is
    past the edge of what this source can see, and an empty address list says so
    honestly.
    """
    out: list[NetInterface] = []
    carrier = _text(row, "carrier")
    service = (_text(row, "service_type") or "").upper()

    wan = _text(row, "cpe_wan_port")
    if wan is not None:
        out.append(NetInterface(
            interface_key=f"{device_key}:{wan}",
            device_key=device_key,
            name=wan,
            description=" ".join(p for p in (carrier, service, circuit_id) if p),
            addresses=_wan_addresses(row, circuit_id),
            # The contracted service rate. For a carrier handoff it IS the rate
            # the port is provisioned at, which is the only sense in which this
            # source knows a port speed at all.
            speed_mbps=_mbps(row, "bandwidth_mbps"),
            provenance=_provenance(circuit_id),
        ))

    handoff = _text(row, "cpe_handoff_port")
    peer = _text(row, "handoff_device")
    peer_port = _text(row, "handoff_interface")
    if handoff is not None:
        out.append(NetInterface(
            interface_key=f"{device_key}:{handoff}",
            device_key=device_key,
            name=handoff,
            description=" ".join(p for p in ("handoff to", peer, peer_port) if p) or None,
            provenance=_provenance(circuit_id),
        ))
    return out


def _link(row: dict, device_key: str, circuit_id: str) -> Optional[NetLink]:
    """The modem -> handoff-router adjacency the order asserts.

    `declared` is the right evidence class and the honest one: nothing read a
    neighbour table, nothing returned this as topology and no config stanza was
    parsed. A human wrote it on a service order, and the picture should say so —
    which is also why it is not upgraded to `cdp` when a switch console later
    reports the same cable. That is a second, independent observation and it
    arrives under its own key.
    """
    peer = _text(row, "handoff_device")
    if peer is None:
        return None
    peer_port = _text(row, "handoff_interface")
    local_port = _text(row, "cpe_handoff_port")
    carrier = _text(row, "carrier") or "the carrier"
    return NetLink(
        link_key=f"declared:{device_key}:{local_port or ''}~{peer}:{peer_port or ''}",
        a_device=device_key,
        a_interface=local_port,
        b_device=peer,
        b_interface=peer_port,
        evidence="declared",
        evidence_detail=(
            f"the service order for {circuit_id} states that the {carrier} demarc "
            f"hands off to {peer}"
            + (f" {peer_port}" if peer_port else "")
        ),
        provenance=_provenance(circuit_id),
    )


def normalize(raw: dict) -> NormalizeResult:
    """One portal extract -> circuits, the CPE terminating them, and the demarc.

    Deterministic: rows are visited in circuit-id order and every output list is
    sorted by its own key, so two runs over one extract are byte-identical.
    """
    res = NormalizeResult()
    devices: dict[str, NetDevice] = {}
    interfaces: dict[str, NetInterface] = {}
    links: dict[str, NetLink] = {}

    for row in sorted(_rows(raw), key=lambda r: str(r.get("circuit_id", ""))):
        circuit_id = _text(row, "circuit_id")
        if circuit_id is None:
            raise NormalizeError(
                f"{TOOL}: a circuit row carries no circuit_id; it is the only "
                f"identifier this source has and nothing can be traced without it"
            )

        device = _device(row, circuit_id)
        if device is not None and device.device_key not in devices:
            devices[device.device_key] = device
        device_key = device.device_key if device is not None else None

        if device_key is not None:
            for iface in _interfaces(row, device_key, circuit_id):
                interfaces.setdefault(iface.interface_key, iface)
            link = _link(row, device_key, circuit_id)
            if link is not None:
                links.setdefault(link.link_key, link)

        res.circuits.append(Circuit(
            circuit_id=circuit_id,
            provider=_text(row, "carrier"),
            technology=_technology(row),
            bandwidth_mbps=_mbps(row, "bandwidth_mbps"),
            public_ips=_wan_addresses(row, circuit_id),
            # None when the order names no CPE. The circuit is still a real
            # circuit; it is the equipment that is unreported.
            device_key=device_key,
            interface=_text(row, "cpe_wan_port"),
            state=_state(row),
            provenance=_provenance(circuit_id),
        ))

    res.devices = [devices[k] for k in sorted(devices)]
    res.interfaces = [interfaces[k] for k in sorted(interfaces)]
    res.links = [links[k] for k in sorted(links)]
    res.circuits.sort(key=lambda c: c.circuit_id)
    return res
