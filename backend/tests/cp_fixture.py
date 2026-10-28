"""A Check Point Management API export, shaped like `show-access-rulebase ...
details-level full use-object-dictionary true show-hits true` and
`show-nat-rulebase`. Synthetic data; every planted condition is named.
"""

from __future__ import annotations

import copy

ANY = "97aeb369-9aea-11d5-bd16-0090272ccb30"


def _o(uid, name, type_, **kw):
    return {"uid": uid, "name": name, "type": type_, **kw}


OBJECTS = [
    _o(ANY, "Any", "CpmiAnyObject"),
    _o("act-accept", "Accept", "RulebaseAction"),
    _o("act-drop", "Drop", "RulebaseAction"),
    _o("act-ask", "Ask", "RulebaseAction"),
    _o("h-web1", "web-01", "host", **{"ipv4-address": "10.10.1.10"}),
    _o("h-web2", "web-02", "host", **{"ipv4-address": "10.10.1.11"}),
    _o("n-dmz", "dmz-net", "network", subnet4="10.10.1.0", **{"mask-length4": 24}),
    _o("n-corp", "corp-net", "network", subnet4="10.20.0.0", **{"mask-length4": 16}),
    _o("n-dc", "dc-servers", "network", subnet4="10.30.0.0", **{"mask-length4": 24}),
    _o("r-jump", "jump-range", "address-range",
       **{"ipv4-address-first": "10.40.0.10", "ipv4-address-last": "10.40.0.20"}),
    _o("g-web", "web-farm", "group", members=["h-web1", "h-web2"]),
    _o("g-outer", "all-servers", "group", members=["g-web", "n-dc"]),
    _o("ar-admins", "Admins", "access-role"),
    _o("s-ssh", "ssh", "service-tcp", port="22"),
    _o("s-rdp", "rdp", "service-tcp", port="3389"),
    _o("s-https", "https", "service-tcp", port="443"),
    _o("s-high", "high-ports", "service-tcp", port=">1023"),
    _o("s-dns", "domain-udp", "service-udp", port="53"),
    _o("sg-admin", "admin-svcs", "service-group", members=["s-ssh", "s-rdp"]),
    _o("app-fb", "Facebook", "application-site"),
    _o("t-past", "until-2026-01", "time", **{"end-never": False,
                                            "end": {"iso-8601": "2026-01-31T00:00:00Z"}}),
    _o("t-future", "until-2027-06", "time", **{"end-never": False,
                                              "end": {"iso-8601": "2027-06-30T00:00:00Z"}}),
    _o("gw-1", "edge-gw-1", "simple-gateway"),
    _o("pt", "Policy Targets", "Global"),
]


def _rule(n, name, src, dst, svc, action="act-accept", hits=None, **kw):
    r = {"type": "access-rule", "uid": f"rule-{n}", "rule-number": n, "name": name,
         "enabled": True, "source": src, "destination": dst, "service": svc, "action": action,
         "time": [ANY], "install-on": ["pt"], "source-negate": False,
         "destination-negate": False, "service-negate": False}
    if hits is not None:
        r["hits"] = {"value": hits[0], "last-date": {"iso-8601": hits[1]} if hits[1] else None}
    r.update(kw)
    return r


RULES = [
    {"type": "access-section", "name": "Legacy", "uid": "sec-legacy", "rulebase": [
        _rule(1, "temp any any", [ANY], [ANY], [ANY], hits=(0, None)),                     # any-any, unused
    ]},
    {"type": "access-section", "name": "Inbound", "uid": "sec-in", "rulebase": [
        _rule(2, "web inbound", [ANY], ["g-web"], ["s-https"], hits=(15200, "2026-10-26T09:00:00Z")),
        _rule(3, "web-01 https", [ANY], ["h-web1"], ["s-https"], hits=(0, None)),            # shadowed by 2
    ]},
    {"type": "access-section", "name": "Admin", "uid": "sec-admin", "rulebase": [
        _rule(4, "corp admin to dc", ["n-corp"], ["n-dc"], ["sg-admin"],                       # admin ports, broad source
              hits=(31, "2026-10-20T08:00:00Z")),
        _rule(5, "not jump", ["r-jump"], ["n-dc"], ["s-ssh"], hits=(4, "2026-09-01T00:00:00Z"),
              **{"source-negate": True}),                                                     # negated
        _rule(6, "old vendor", ["n-corp"], ["all-servers"], ["s-high"], hits=(0, None),
              enabled=False),                                                                 # disabled
        _rule(7, "project x", ["n-corp"], ["n-dmz"], ["s-ssh"], hits=(2, "2025-12-01T00:00:00Z"),
              time=["t-past"]),                                                               # expired
        _rule(8, "migration window", ["n-corp"], ["n-dmz"], ["s-https"], hits=(9, "2026-10-01T00:00:00Z"),
              time=["t-future"]),                                                             # time-bound, live
        _rule(9, "admins web", ["ar-admins"], ["n-dmz"], ["app-fb"], action="act-ask",
              hits=(1, "2026-10-02T00:00:00Z")),                                              # app + identity
    ]},
    _rule(10, "cleanup", [ANY], [ANY], [ANY], action="act-drop", hits=(99000, "2026-10-27T00:00:00Z")),
]

NAT = [
    {"type": "nat-rule", "uid": "nat-1", "rule-number": 1, "enabled": True, "method": "hide",
     "auto-generated": False, "original-source": "n-corp", "original-destination": ANY,
     "original-service": ANY, "translated-source": "gw-1", "translated-destination": "Original",
     "translated-service": "Original", "install-on": ["pt"]},
    {"type": "nat-rule", "uid": "nat-2", "rule-number": 2, "enabled": True, "method": "static",
     "auto-generated": True, "original-source": ANY, "original-destination": "h-web1",
     "original-service": "s-https", "translated-source": "Original",
     "translated-destination": "h-web2", "translated-service": "Original", "install-on": ["gw-1"]},
]


def export(**overrides) -> dict:
    """The bundled shape, deep-copied so a test can mutate it."""
    e = {
        "exported_at": "2026-10-27T12:00:00Z",
        "access_layers": [{"uid": "layer-net", "name": "Network", "from": 1, "to": 10, "total": 10,
                           "rulebase": RULES, "objects-dictionary": OBJECTS}],
        "nat_packages": [{"uid": "pkg-std", "name": "Standard", "from": 1, "to": 2, "total": 2,
                          "rulebase": NAT, "objects-dictionary": OBJECTS}],
    }
    e.update(overrides)
    return copy.deepcopy(e)
