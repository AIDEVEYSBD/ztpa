"""The carrier portal projection: a service-order extract, not an API response.

Why this one does not look like the others
------------------------------------------
Every other connector in this package renders a machine interface. This one
deliberately does not, because most carriers do not have one. Airtel, BSNL and
essentially every regional carrier expose a web portal and a PDF; the circuit id,
the technology, the assigned public block and the CPE that terminates it are
obtainable from the SERVICE ORDER rather than from an endpoint. So the payload
here is a flat row-per-circuit extract — the shape you get when somebody exports
the portal's circuit list to CSV — and the normalizer is written against that
reality rather than against an API this source does not have.

It is also the only source in the registry that sees the MODEM layer at all, and
the only one that can tell you two diverse-looking circuits were sold by one
carrier. That is the difference between redundancy and a correlated failure
wearing its costume, and no firewall console, switch console or cloud scanner in
this product can answer it.

What a service order does NOT carry
-----------------------------------
A service order records what was sold and installed. It is not a live read, and
the extract below reflects that:

  * no CPE firmware — that is a running fact only the box or a managed-CPE
    console has, and back-filling it from the model number would be a guess;
  * no interface admin state — `status` here is the CIRCUIT's state. A standby
    ISDN circuit's CPE port is not "down", and collapsing the two would report
    an outage on a link that is doing exactly what it was bought to do;
  * no address on the customer side of the demarc — the carrier assigns the WAN
    block and hands off on a port; what the customer configured inside is not
    the carrier's to report.
"""

from __future__ import annotations

from typing import Any, Optional

from ..estate import CircuitSpec, Estate

CARRIER_PORTAL = "carrier_portal"

# The estate's technology vocabulary -> the label a portal prints on the order.
# Anything absent falls back to title case rather than to a guess at the family:
# an unrecognised service type must reach the normalizer as itself, so it lands
# on `technology="unknown"` instead of being rounded to the nearest member.
_SERVICE_TYPE = {
    "mpls": "MPLS",
    "broadband": "Broadband",
    "isdn": "ISDN",
    "p2p": "P2P",
    "fiber": "Fiber",
    "lte": "LTE",
    "satellite": "Satellite",
}


def _handoff_port(est: Estate, circuit: CircuitSpec) -> Optional[str]:
    """The CPE-side port the service order names as the handoff.

    None when the estate declares no cable for this circuit's handoff. The
    normalizer then still emits the link — the order states WHICH router the
    demarc hands off to — with no CPE interface on it, because "we were not told
    which port" and "there is no port" are different facts.
    """
    for link in est.links:
        if (link.a_device == circuit.device
                and link.b_device == circuit.handoff_device
                and link.b_interface == circuit.handoff_interface):
            return link.a_interface
    return None


def carrier_portal_export(est: Estate) -> dict[str, Any]:
    """The estate's circuits as the carrier's portal would list them.

    One row per circuit whose CPE this portal can see. A circuit terminating on
    equipment outside this carrier's estate is not in this carrier's portal, and
    emitting it would make the demo's partial coverage look total.
    """
    visible = {d.key for d in est.devices_seen_by(CARRIER_PORTAL)}
    by_key = {d.key: d for d in est.devices}

    rows: list[dict[str, Any]] = []
    for circuit in sorted(est.circuits, key=lambda c: c.circuit_id):
        if circuit.device not in visible:
            continue
        cpe = by_key[circuit.device]
        rows.append({
            "circuit_id": circuit.circuit_id,
            "service_type": _SERVICE_TYPE.get(circuit.technology,
                                              circuit.technology.title()),
            "carrier": circuit.provider,
            "bandwidth_mbps": circuit.bandwidth_mbps,
            "wan_ip_block": circuit.public_block,
            "cpe_name": cpe.name,
            "cpe_model": cpe.model,
            # Blank because the estate states no serial for the CPE, and a
            # service order frequently does not carry one. It is left blank
            # rather than filled from the circuit id: the normalizer reads a
            # blank as "not stated" and keys the device on the circuit instead,
            # which is how the portal itself indexes its CPE.
            "cpe_serial": cpe.serial,
            "cpe_mgmt_ip": cpe.mgmt_ip,
            "cpe_wan_port": circuit.interface,
            "cpe_handoff_port": _handoff_port(est, circuit),
            "demarc_location": cpe.site,
            # THE CIRCUIT's state (up / standby / down), never a port's.
            "status": circuit.state,
            "handoff_device": circuit.handoff_device,
            "handoff_interface": circuit.handoff_interface,
        })

    return {
        "source": "carrier portal service-order extract",
        "format": "csv",
        # Present and empty means a portal with no circuits on it. ABSENT means
        # the extract could not be read at all, and the normalizer refuses it —
        # a truncated download that yields zero circuits must not arrive as an
        # estate that has no way out to the internet.
        "circuits": rows,
    }
