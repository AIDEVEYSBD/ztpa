"""Junos Space Network Management Platform, projected onto its device REST API.

What Space is onboarded for here
--------------------------------
One box: rtr-edge-02. Junos Space is a Juniper-only platform and this estate has
exactly one Juniper device in it, so the export is a single device record and its
interfaces. That is not a thin export -- it is the correct export, and the
difference matters: an operator looking at a one-device source card should see
"Junos Space manages one device, and here it is", never "Junos Space failed".

Why it reports no adjacency, and why that is the whole story
------------------------------------------------------------
`/api/space/device-management/devices` is an INVENTORY call. It returns what each
managed box is and how it is addressed; it does not return neighbours, and Space
has no equivalent of Catalyst Center's `/topology/physical-topology`. So this
projection renders no adjacency, the normalizer emits no NetLink, and the edge
between rtr-edge-02 and the perimeter is left for `topology.reconstruct` to
derive from the /30s both ends hold -- as a `containment` link, which is the
weaker evidence class it honestly is.

The interfaces therefore have to keep their prefix length. `ipAddress` is
exported as `10.254.0.6/30`, not as a bare host: a /32 shares a block with
nothing, and an export that drops the prefix silently deletes every containment
link the reconstruction engine would have drawn from this device. The picture
does not break in that case -- it just quietly has fewer edges, which is the
harder failure to notice.

Interface names are passed through exactly as the estate spells them, including
`edge-fw-1`, which is not a Junos-shaped name. Renaming it to a plausible
`ge-0/0/3` would make this export look more authentic and would break the join
with every other console's view of the same port.
"""

from __future__ import annotations

from ..estate import Estate, IfaceSpec

TOOL = "junos_space"
# The rung this console speaks from. `sources.py` is the authority and the
# normalizer reads it from there, never from an export -- this constant is the
# projection's own statement of the same fact, asserted equal to the registry by
# test so a connector and the registry cannot drift the way five copies of the
# tool list once did.
TIER = "aggregator"

# Keyed by path for the same reason the AlgoSec projection is: the key is the
# call an operator can make themselves when a row looks wrong.
DEVICES_PATH = "/api/space/device-management/devices"

# Space nests the per-device interface list under the device record; the key is
# its own, hyphen and all.
INTERFACES_KEY = "device-interfaces"


def _interface_row(iface: IfaceSpec) -> dict:
    return {
        "name": iface.name,
        # WITH the prefix. See the module docstring: a bare host address costs
        # every containment link this device would otherwise contribute.
        "ipAddress": iface.addresses[0] if iface.addresses else None,
        "adminStatus": None if iface.admin_up is None else ("up" if iface.admin_up else "down"),
        # Space returns an oper state too. The estate declares an ADMIN state and
        # no oper state, and copying one into the other would manufacture a
        # second observation out of one. The key is present and null so a reader
        # can see the field was collected and had no value -- an omitted key
        # would read as a projection that forgot to ask.
        "operStatus": None,
        "speed": iface.speed_mbps,
        "description": iface.description or None,
    }


def junos_space_export(est: Estate) -> dict:
    """Render the Space device inventory for the devices Space manages.

    Keyed by path, and each value is Space's OWN collection envelope --
    `{"devices": {"@size": n, "device": [...]}}`, the attribute spellings its
    JSON rendering inherits from the XML API. `@size` is not decoration: it is
    the count Space says the collection has, and a response carrying fewer
    records than it claims is a truncated page. The normalizer compares the two
    and fails rather than ingesting a short inventory as a complete one.

    Deterministic: sorted throughout, no clock, no randomness.
    """
    devices = sorted(est.devices_seen_by(TOOL), key=lambda d: d.key)
    records = [
        {
            "name": d.name,
            "platform": d.model,
            "osVersion": d.os_version,
            "serialNumber": d.serial or None,
            "ipAddr": d.mgmt_ip,
            # Space's view of ITS OWN session to the box, which is why a device
            # it returns at all is one it is connected to. It describes the
            # management plane and maps to no field in the canonical model; the
            # normalizer drops it rather than folding it into an interface's
            # admin state, which is a statement about the data plane.
            "connectionStatus": "connected",
            # Space's family string, taken from the OS the estate declares
            # ("Junos 21.4R3-S4" -> "junos") rather than hardcoded, so it cannot
            # outlive a change to the platform. Note it does NOT say what the box
            # DOES: an MX router and an SRX firewall are both "junos", which is
            # exactly why the normalizer leaves the role unknown.
            "deviceFamily": (d.os_version or "").split(" ")[0].lower() or None,
            INTERFACES_KEY: [
                _interface_row(i)
                for i in sorted(est.interfaces_of(d.key), key=lambda i: i.name)
            ],
        }
        for d in devices
    ]
    return {DEVICES_PATH: {"devices": {"@size": len(records), "device": records}}}
