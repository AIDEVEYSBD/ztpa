"""Junos Space's device inventory -> the canonical infrastructure models.

Infrastructure only: no PolicyRecord, no ObservedEntity. Space's firewall-policy
side lives behind a different API family (`/api/juniper/sd/policy-management`)
and is not onboarded here; this module is the device inventory and nothing else.

THIS NORMALIZER EMITS NO LINKS, ON PURPOSE.
-------------------------------------------
Emitting nothing is the correct output, and a reader needs to know it was a
decision rather than an omission, so: Junos Space's device list reports no
adjacency. There is no neighbour table in it, no topology call behind it, and
nothing in the export names a peer. `LinkEvidence` has no "inferred" member and
must never grow one, so there is no honest evidence class available for a line
between rtr-edge-02 and anything else -- and a line drawn because the picture
looked unfinished is a claim about someone's cabling that nobody made.

The adjacency is not lost. `topology.reconstruct` derives it from address
containment: rtr-edge-02's `10.254.1.9/30` and fw-perim-01's `10.254.1.10/30`
provably sit in one /30, which is a real, checkable L3 observation, and it is
stored as the weaker `containment` evidence it is rather than being passed off
as a cable. That is why `_interfaces` below keeps the prefix on every address --
a /32 shares a block with nothing, and dropping the prefix would delete those
derived edges silently.

The role is left unknown, also on purpose
-----------------------------------------
Space reports `platform` ("MX204") and `deviceFamily` ("junos"). Neither states
what the box DOES: an MX router, an EX switch and an SRX firewall are all
"junos". `NetDevice.role_source` is "declared" only when the console states the
type outright, as AlgoSec does; here nothing does, so the role stays unknown and
`reconstruct._derive_role` works it out from what the device terminates. Guessing
"router" from the model string would be us deriving while the row claimed the
vendor had told us.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from ..connectors.juniper import DEVICES_PATH, INTERFACES_KEY, TOOL
from ..models import NetDevice, NetInterface, Provenance
from ..sources import tier_of
from .common import NormalizeResult
from .profile import NormalizeError

REQUIRED_PATHS: tuple[str, ...] = (DEVICES_PATH,)

# Space's collection envelope, whose attribute spellings its JSON rendering
# inherits from the XML API.
_COLLECTION = "devices"
_MEMBER = "device"
_SIZE = "@size"

# Space's interface status vocabulary. Anything outside it leaves `admin_up`
# None: "the source said something we do not understand" and "the port is down"
# are different facts, and only one of them greys a port out on the diagram.
_STATUS: dict[str, bool] = {"up": True, "down": False}


def _provenance(raw_ref: str) -> Provenance:
    # Tier from the registry, never from the payload -- `sources.py` is the one
    # copy. `simulated` is True because this module's input is a projection of
    # the demo estate; a real Space response has no field that says "I am
    # fabricated", and the mistake worth foreclosing is fabricated facts
    # rendering as real.
    return Provenance(source_tool=TOOL, source_tier=tier_of(TOOL),
                      raw_ref=raw_ref, simulated=True)


def _device_records(raw: dict) -> list:
    """The device list, unwrapped from Space's envelope and checked against it.

    Three distinct failures, none of which may reach the output as "Space
    manages nothing":

      * the path is ABSENT          -- the call did not come back at all;
      * the envelope is missing     -- whatever answered was not Space;
      * `@size` disagrees with the  -- a truncated page. Ingesting 20 of 60
        number of records returned     devices as a complete inventory is the
                                       quietest way to under-report an estate,
                                       and the count is right there in the
                                       response saying so.
    """
    if not isinstance(raw, dict):
        raise NormalizeError(
            f"{TOOL}: export must be an object keyed by API path ({DEVICES_PATH}), "
            f"got {type(raw).__name__}")
    for path in REQUIRED_PATHS:
        if path not in raw:
            raise NormalizeError(
                f"{TOOL}: `{path}` is absent from the export. A collection that did "
                f"not return this endpoint is a failure, not a Space with no managed "
                f"devices; an endpoint that returned nothing must be present and empty")
    body = raw[DEVICES_PATH]
    collection = body.get(_COLLECTION) if isinstance(body, dict) else None
    if not isinstance(collection, dict):
        raise NormalizeError(
            f"{TOOL}: `{DEVICES_PATH}` did not return a `{_COLLECTION}` collection; "
            f"got {type(body).__name__}")
    records = collection.get(_MEMBER) or []
    if not isinstance(records, list):
        raise NormalizeError(
            f"{TOOL}: `{DEVICES_PATH}` `{_MEMBER}` must be a list, got "
            f"{type(records).__name__}")
    declared = collection.get(_SIZE)
    if declared is not None and str(declared).isdigit() and int(declared) != len(records):
        raise NormalizeError(
            f"{TOOL}: `{DEVICES_PATH}` declares {_SIZE}={declared} and returned "
            f"{len(records)} device(s) -- a truncated page must not ingest as a "
            f"complete inventory")
    return records


def _text(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _interfaces(device: str, serial: str, rows: object) -> list[NetInterface]:
    out: list[NetInterface] = []
    for entry in rows or []:
        if not isinstance(entry, dict):
            raise NormalizeError(
                f"{TOOL}: {device} has a `{INTERFACES_KEY}` entry that is not an object")
        name = _text(entry.get("name"))
        if name is None:
            raise NormalizeError(f"{TOOL}: {device} has an interface with no `name`")
        raw_ref = f"{serial}:{name}"
        address = _text(entry.get("ipAddress"))
        if address is not None:
            try:
                # Canonical, and the prefix is preserved: `10.254.0.6/30` stays a
                # /30. Space is the only source that reports this interface at
                # all, so a prefix lost here is a containment link the
                # reconstruction engine can never draw.
                address = str(ipaddress.ip_interface(address))
            except ValueError as exc:
                raise NormalizeError(
                    f"{TOOL}: {raw_ref}: cannot read ipAddress "
                    f"{entry.get('ipAddress')!r} ({exc})") from exc
        speed = entry.get("speed")
        out.append(NetInterface(
            interface_key=f"{device}:{name}",
            device_key=device,
            name=name,
            description=_text(entry.get("description")),
            addresses=[address] if address else [],
            admin_up=_STATUS.get((_text(entry.get("adminStatus")) or "").lower()),
            # Space returns an oper state; this estate declares none, so it stays
            # None. None is NOT "down" -- see `NetInterface.admin_up`.
            oper_up=_STATUS.get((_text(entry.get("operStatus")) or "").lower()),
            # Mbps as an integer, or nothing. Some Space versions return a
            # unit-bearing string ("1g"); it is deliberately not parsed, because
            # guessing a unit is how a 1Gb port becomes a 1Mb one on a capacity
            # screen, and an unreported speed is a fact we can render.
            speed_mbps=speed if isinstance(speed, int) and not isinstance(speed, bool) else None,
            provenance=_provenance(raw_ref),
        ))
    return sorted(out, key=lambda i: i.interface_key)


def normalize(raw: dict) -> NormalizeResult:
    """One Junos Space device export -> devices and interfaces. No links (above)."""
    devices: list[NetDevice] = []
    interfaces: list[NetInterface] = []
    for index, row in enumerate(_device_records(raw)):
        if not isinstance(row, dict):
            raise NormalizeError(f"{TOOL}: {DEVICES_PATH} #{index + 1} is not an object")
        name = _text(row.get("name"))
        if name is None:
            raise NormalizeError(
                f"{TOOL}: {DEVICES_PATH} #{index + 1} has no `name`; a device with no "
                f"identifier cannot be traced back to the console")
        serial = _text(row.get("serialNumber"))
        # The serial is what Space identifies the chassis by and is what an
        # operator can search on, so it is the raw_ref. Falling back to the name
        # keeps a device with no serial traceable rather than unprovenanced.
        raw_ref = serial or name
        devices.append(NetDevice(
            device_key=name,
            name=name,
            # role / role_source left at their defaults. See the module
            # docstring: "junos" and "MX204" say what the box is made of, not
            # what it does.
            #
            # The vendor is not a guess about this row: Space manages Junos
            # devices and nothing else, so it is a property of the product that
            # returned the record.
            vendor="Juniper",
            model=_text(row.get("platform")),
            os_version=_text(row.get("osVersion")),
            serial=serial,
            mgmt_ip=_text(row.get("ipAddr")),
            provenance=_provenance(raw_ref),
        ))
        interfaces.extend(_interfaces(name, raw_ref, row.get(INTERFACES_KEY)))

    return NormalizeResult(
        devices=sorted(devices, key=lambda d: d.device_key),
        interfaces=sorted(interfaces, key=lambda i: i.interface_key),
        # links stays empty. Deliberately. See the module docstring.
    )
