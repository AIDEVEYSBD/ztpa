"""Resilience: single points of failure, and what each one takes with it.

The question this answers, and why a diagram cannot
---------------------------------------------------
It is the most-repeated ask in the brief, put three ways: "you don't want one
internet connection to fail because of one modem", "you don't want to go down
because of one edge router failing", "2 switches, mostly criss-cross
connections". All three are one question — WHERE IS THE SINGLE POINT OF FAILURE
— and a picture cannot answer it, because a picture draws two lines whether or
not those lines are two failure domains. Two circuits landing on one router are
two lines. Two circuits from one carrier are two lines. Neither is redundancy.

Finding cut vertices is the easy half; networkx does it in linear time. The hard
half is NOT reporting the criss-cross. This estate is deliberately cabled the
right way nearly everywhere: either edge router reaches either firewall, either
firewall reaches either core, two of the three access switches are dual-homed.
An analyzer that flags every edge is not cautious, it is useless — it buries the
four real findings in fourteen false ones, and the operator learns to ignore it.
So every suppression this module makes is PUBLISHED, in `ResilienceReport.
suppressed`, with the sibling link or the LAG member count that justifies it. A
filter you cannot audit is indistinguishable from a bug.

The four things that are actually wrong here
--------------------------------------------
    1. rtr-edge-01 is the only path to CIRC-A *and* CIRC-C — two of three
       circuits ride one router.
    2. CIRC-A and CIRC-C are both Carrier-A — diverse links, one carrier. This
       is the most valuable finding in the set precisely because it is the one
       that looks like redundancy on every diagram anyone has ever drawn of it.
    3. asw-acc-03 is single-homed to csw-core-01, where its two peers are
       criss-crossed to both cores.
    4. ap-wifi-01 hangs off asw-acc-01 alone.

None of them is found by matching names, and the same code finds them in an
estate whose devices are called something else entirely.

Why this does not reuse the policy severity vector
--------------------------------------------------
`severity.py` scores E·P·D·B — exposure, port class, destination value, boundary
crossing. Not one of those terms describes a cut vertex: a broken uplink has no
port and no destination tag, and publishing a vector whose named factors do not
describe the finding is worse than publishing no vector at all, because a client
recomputing it by hand gets a number that means nothing. So this module keeps
severity.py's SHAPE (named constants, published table, hand-recomputable) and
its BANDS (imported, not copied, so "high" means the same thing across finding
types) with its own three terms:

    severity = round(100 * min(1, R * L * S))

      R  blast fraction   how much of the estate's circuit reachability this
                          failure destroys — measured, not assumed
      L  layer weight     how long it stays destroyed, by lane
      S  domain multiplier  how much the redundancy that is supposed to cover
                          this failure is nominal rather than real

R is rounded to four places BEFORE it is multiplied, so the published numbers
reproduce the published severity exactly rather than approximately.

What "no findings" is allowed to mean
-------------------------------------
A device no console reported cannot be a single point of failure, and an estate
nobody observed is not a resilient estate. `assess()` therefore returns a report
that distinguishes "nothing was found" from "there was nothing to look at", the
way `run_all.EngineResult` distinguishes a clean snapshot from a degraded one.
`analyze()` returns the bare list for callers that want it; the empty list it
returns for an unobserved topology is exactly the ambiguity `assess()` exists to
remove, which is why the docstring says so and why `summary()` never prints the
words "no single point of failure" unless something was actually analysed.

Deterministic throughout: no clock, no randomness, every emitted collection
sorted, no set iterated in an output path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, Optional

import networkx as nx

from ..models import Circuit, NetDevice, NetInterface, NetLink, Topology
from ..netaddr import parse_net
from .severity import band

# ── The severity vector ────────────────────────────────────────────────────
#
#   severity = round(100 * min(1, R * L * S))
#
# Every constant below is published, named, and justified where it sits. None of
# them is computed: a client takes R, L and S off a finding and reproduces the
# severity with a calculator, which is the property the policy severity model
# already promises and the reason it is worth matching.

# L — how long a failure in this lane stays a failure. R says how much breaks; L
# says how hard it is to unbreak, which is the half of risk that a connectivity
# count cannot see. The ordering is substitutability, not importance: an access
# switch is replaced within the hour by whoever is on the floor, an edge router
# is not replaced without the carrier's hand-off configuration.
LAYER_WEIGHT: dict[str, float] = {
    # Carrier-owned CPE. Ours to lose, not ours to replace: a dead modem is a
    # carrier dispatch measured in days, which is why it outranks our own core.
    "modem": 0.9,
    # The reference weight. An edge router carries the carrier-facing config;
    # its replacement is a rebuild plus a circuit re-test.
    "edge": 1.0,
    # Same reference: a firewall carries policy state, so a swap is a config
    # restore and a maintenance window, not a cable move.
    "perimeter": 1.0,
    # Ours, on site, templated — but still a change window and still the box
    # every VLAN's gateway lives on.
    "core": 0.9,
    # The spares cupboard lane. Losing one is disruptive for a floor, for an
    # hour.
    "access": 0.6,
    # A host. Its loss is a service question, not a network one, and the network
    # answer to a dead host is "rebuild it".
    "endpoint": 0.4,
}
# A device `reconstruct.assign_layers` could not place gets NO DISCOUNT. The
# alternative — defaulting it to the cheapest lane, or to a middling 0.7 — would
# let an unplaced device quietly score lower than an identical placed one, so
# the analyzer's output would depend on how much of the estate we managed to
# lay out. Unknown lane means unknown mitigation cost; price it at the top.
UNPLACED_LAYER_WEIGHT = 1.0

# S — how nominal the redundancy covering this failure is. All of these are
# above 1.0 on purpose: a multiplier that can lower a score would let a
# shared-domain finding rank below the same failure with no shared domain.
DOMAIN_NONE = 1.0
# The highest multiplier here, because it is the only failure mode that is
# INVISIBLE in the picture. Two circuits, two technologies, two CPEs, two
# physical paths into the building — and one carrier's backhaul, one carrier's
# maintenance window, one carrier's fibre cut. The estate believes it has
# diversity right up until the morning it does not.
DOMAIN_SHARED_CARRIER = 1.5
# Two circuits landing on one device. Expensive, but at least visible to anyone
# who follows the lines on the diagram, which is why it prices below carrier.
DOMAIN_SHARED_HANDOFF = 1.4
# An HA pair with a dependency both members share: the cluster still fails over
# perfectly, it just has nothing left to fail over to.
DOMAIN_SHARED_HA_DOMAIN = 1.3

# How blast radius was measured. Published on every report and every finding,
# because the two bases answer DIFFERENT QUESTIONS and silently substituting one
# for the other would make the number a lie in an estate with no carrier
# onboarding (which is a normal estate, not a broken one).
BLAST_BASIS_CIRCUIT = "circuit_reachability"
BLAST_BASIS_CONNECTIVITY = "device_connectivity"

def _n(count: int, noun: str, plural: str = "") -> str:
    """Count a noun: 1 device, 3 devices.

    Every string this module emits is read by an operator deciding whether to
    believe it, and `1 device(s) lose every path` reads like a template nobody
    finished. Cheap to do once, here.
    """
    return f"{count} {noun if count == 1 else (plural or noun + 's')}"


ResilienceKind = Literal[
    "shared_circuit_handoff",     # one device is the only path to 2+ circuits
    "shared_carrier",             # 2+ circuits from one provider
    "single_homed_device",        # one uplink where the lane above has peers
    "ha_shared_failure_domain",   # an HA pair both of whose members one failure takes
    "articulation_point",         # a cut vertex not explained by any of the above
    "fragile_link",               # a single cable holding two halves together
]


# ── What the analyzer emits ────────────────────────────────────────────────

@dataclass(frozen=True)
class BlastRadius:
    """What the estate loses when one device (or one set of them) goes away.

    Exact, never sampled: the removal is actually performed on the graph and
    connectivity is recounted, because this powers a "lose this device" control
    and an operator who clicks a box is entitled to the real answer.
    """

    device_key: str
    basis: str                          # BLAST_BASIS_* — which question the numbers answer
    # (device, circuit) reachability pairs destroyed, over the pairs that
    # existed before. `fraction` is rounded to 4 places because it is the R the
    # published severity is computed from.
    paths_lost: int
    paths_before: int
    fraction: float
    # Devices that lose EVERY path to EVERY circuit: they go dark.
    devices_isolated: tuple[str, ...] = ()
    # Devices that keep a circuit but lose one they had: redundancy gone,
    # service retained. Counted separately because conflating "degraded" with
    # "down" is how a resilience report stops being believed.
    devices_degraded: int = 0
    # Circuits the body of the estate can no longer reach.
    circuits_stranded: tuple[str, ...] = ()
    components_after: int = 1


@dataclass(frozen=True)
class ResilienceFinding:
    """One structural fact about how this estate fails.

    Deliberately NOT a `models.Finding`: `models.FindingType` is a closed Literal
    mirrored by a DB CHECK (db/schema.sql:195, :211, :317) and
    `persist.ensure_finding_types` was removed on purpose, so the first insert of
    an unknown type raises instead of self-healing. Widening it is a migration,
    and a migration is the lead's to own.
    """

    id: str
    kind: ResilienceKind
    title: str
    # The specific observation, in the words an engineer would use to check it.
    # Never "this looks fragile": always which device, which circuits, which
    # sibling link does or does not exist.
    detail: str
    severity: int
    severity_band: str
    # The published vector: {"R": .., "L": .., "S": .., "product": ..}. severity
    # == round(100 * min(1, R * L * S)) exactly, from these numbers.
    vector: dict
    blast: BlastRadius
    devices: tuple[str, ...] = ()        # every device the finding turns on
    failing: tuple[str, ...] = ()        # the element whose loss causes the damage
    circuits: tuple[str, ...] = ()
    links: tuple[str, ...] = ()
    # Provenance, carried the way every other fact in this system carries it:
    # which consoles said so, and what they called it.
    source_tools: tuple[str, ...] = ()
    raw_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResilienceReport:
    """Findings, plus everything needed to know what the findings MEAN.

    The three lists after `findings` are what make an empty `findings` readable:
    what could not be analysed, what was deliberately not flagged and why, and
    which adjacencies were kept out of the graph. Without them, "no single points
    of failure" and "we could not see the network" render identically, and the
    second one dressed as the first is the single most damaging thing this
    product could say.
    """

    analysable: bool
    not_analysable_reasons: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()
    findings: tuple[ResilienceFinding, ...] = ()
    blast_radius: tuple[BlastRadius, ...] = ()
    suppressed: tuple[dict, ...] = ()
    excluded_adjacencies: tuple[dict, ...] = ()
    blast_basis: str = ""
    device_count: int = 0
    adjacency_count: int = 0
    circuit_count: int = 0

    @property
    def clean(self) -> bool:
        """The ONLY state that may be rendered as "no single points of failure".

        Both halves are load-bearing: an unanalysable topology has no findings
        either, and that is not a clean bill of health."""
        return self.analysable and not self.findings

    def summary(self) -> str:
        """One sentence a screen may print verbatim.

        It never says "no single point of failure" unless something was actually
        analysed — the whole reason this method exists rather than the caller
        formatting `len(findings)`."""
        if not self.analysable:
            return ("Resilience was NOT analysed: "
                    + "; ".join(self.not_analysable_reasons)
                    + ". This is not a finding of resilience.")
        scope = (f"{_n(self.device_count, 'device')}, "
                 f"{_n(self.adjacency_count, 'adjacency', 'adjacencies')} and "
                 f"{_n(self.circuit_count, 'circuit')} observed")
        if not self.findings:
            return (f"No single point of failure found in the {scope}. "
                    f"That is a statement about what the onboarded sources reported, "
                    f"not about the estate.")
        worst = self.findings[0]
        return (f"{_n(len(self.findings), 'single point of failure', 'single points of failure')} "
                f"in the {scope}; worst: {worst.title} "
                f"({worst.severity_band}, {worst.severity}).")


# ── Entry points ───────────────────────────────────────────────────────────

def analyze(topology: Topology) -> list[ResilienceFinding]:
    """The findings, sorted worst-first.

    CAUTION, and it is the reason `assess()` exists: an empty list from here means
    "nothing found OR nothing to look at", and those are different facts. Any
    caller that renders this list to a human must use `assess()` and read
    `ResilienceReport.clean` / `summary()`, which cannot conflate them.
    """
    return list(assess(topology).findings)


def assess(topology: Topology) -> ResilienceReport:
    """Everything `analyze` returns, plus what it means. Pure and deterministic."""
    devices = sorted(topology.devices, key=lambda d: d.device_key)
    by_key = {d.device_key: d for d in devices}

    if not devices:
        # An estate nobody observed is not an estate with no SPOFs. There is
        # nothing here to be resilient OR fragile.
        return ResilienceReport(
            analysable=False,
            not_analysable_reasons=(
                "no device was observed in this snapshot, so there is nothing whose "
                "failure could be analysed",
            ),
            blast_basis=BLAST_BASIS_CONNECTIVITY,
        )

    graph, excluded, links_by_pair = _resilience_graph(topology, by_key)

    if graph.number_of_edges() == 0:
        # Devices with no observed adjacency between them. Every device looks
        # like an island, so every blast radius is zero and no cut vertex
        # exists — which would render as a perfectly resilient estate. It is the
        # opposite: we cannot see a single cable.
        reasons = [
            f"no adjacency was observed between the {_n(len(devices), 'device')} in this "
            f"snapshot, so no path, cut vertex or blast radius can be computed; every "
            f"finding class here is UNAVAILABLE, not empty",
        ]
        if excluded:
            reasons.append(
                f"{_n(len(excluded), 'reported adjacency', 'reported adjacencies')} "
                f"were excluded from the graph "
                f"(see excluded_adjacencies)")
        return ResilienceReport(
            analysable=False,
            not_analysable_reasons=tuple(reasons),
            excluded_adjacencies=tuple(excluded),
            blast_basis=BLAST_BASIS_CONNECTIVITY,
            device_count=len(devices),
            circuit_count=len(topology.circuits),
        )

    caveats: list[str] = []
    cpe_circuits, circuit_by_id = _circuit_seeds(topology, by_key, caveats)
    basis = BLAST_BASIS_CIRCUIT if cpe_circuits else BLAST_BASIS_CONNECTIVITY
    if basis == BLAST_BASIS_CONNECTIVITY:
        caveats.append(
            "no circuit with an observed terminating device is present, so blast "
            "radius is measured as loss of contact with the body of the estate, not "
            "as loss of a path to the internet; the two are different questions and "
            "`blast_basis` says which one these numbers answer")

    calc = _Impact(graph, cpe_circuits, basis)
    blast = {d.device_key: calc.of(d.device_key, removed_nodes=(d.device_key,))
             for d in devices}

    suppressed: list[dict] = []
    findings: list[ResilienceFinding] = []
    # Devices already named as the FAILING element of a specific finding. A
    # generic "this is a cut vertex" on top of "asw-acc-03 is single-homed to
    # this cut vertex" is the same fact twice, and duplicate findings are how a
    # report's severity ordering stops meaning anything.
    explained: set[str] = set()

    findings += _shared_handoff_findings(devices, by_key, blast, circuit_by_id, explained)
    findings += _shared_carrier_findings(topology, by_key, calc, circuit_by_id, caveats,
                                         suppressed)
    findings += _single_homed_findings(graph, devices, by_key, links_by_pair, blast,
                                       explained, suppressed)
    findings += _ha_findings(devices, by_key, blast, calc, explained, suppressed)
    findings += _articulation_findings(graph, by_key, blast, explained)
    findings += _fragile_link_findings(graph, by_key, links_by_pair, calc, suppressed)

    findings.sort(key=lambda f: (-f.severity, f.kind, f.id))
    return ResilienceReport(
        analysable=True,
        caveats=tuple(caveats),
        findings=tuple(findings),
        blast_radius=tuple(blast[d.device_key] for d in devices),
        suppressed=tuple(sorted(suppressed, key=lambda s: (s["kind"], s["candidate"]))),
        excluded_adjacencies=tuple(excluded),
        blast_basis=basis,
        device_count=len(devices),
        adjacency_count=graph.number_of_edges(),
        circuit_count=len(topology.circuits),
    )


# ── The graph the analysis runs on ─────────────────────────────────────────

def _resilience_graph(
    topology: Topology, by_key: dict[str, NetDevice],
) -> tuple[nx.Graph, list[dict], dict[tuple[str, str], list[NetLink]]]:
    """The undirected device graph, and every adjacency deliberately left out of it.

    One exclusion here decides whether this analyzer works at all. Every device
    in a normal estate holds a management address in one management /24 — and
    `topology.reconstruct._containment_links` turns "two interfaces share a
    block" into an adjacency, which is a real and useful L3 observation
    everywhere except here. Left in, this estate's 13 management addresses
    produce 60 phantom edges, the graph becomes a near-complete mesh, and the
    report comes back clean: rtr-edge-01 is no longer a cut vertex, asw-acc-03
    looks dual-homed, and all four designed single points of failure disappear.

    A broadcast domain is not a bundle of point-to-point cables. So a
    containment adjacency is kept only when the block the two devices share is
    point-to-point (at most two devices hold addresses in it — a /30 transit,
    an FHRP pair), and dropped when more devices sit in it, because what those
    devices share is a SEGMENT, which is a shared failure domain rather than a
    set of diverse paths. Cabled evidence (lldp/cdp/api_topology/config/
    routing/declared) is never second-guessed: somebody reported a cable.
    """
    graph = nx.Graph()
    for key in sorted(by_key):
        graph.add_node(key)

    blocks_by_device, devices_by_block = _address_blocks(topology.interfaces, by_key)
    excluded: list[dict] = []
    links_by_pair: dict[tuple[str, str], list[NetLink]] = {}

    for link in sorted(topology.links, key=lambda l: l.link_key):
        if link.a_device not in by_key or link.b_device not in by_key:
            missing = sorted({e for e in (link.a_device, link.b_device) if e not in by_key})
            excluded.append({
                "link_key": link.link_key, "reason": "endpoint_not_observed",
                "detail": (f"{', '.join(missing)} is not a device in this snapshot, so "
                           f"this adjacency cannot be reasoned about"),
            })
            continue
        if link.a_device == link.b_device:
            excluded.append({
                "link_key": link.link_key, "reason": "self_adjacency",
                "detail": f"both ends land on {link.a_device}; it says nothing about paths",
            })
            continue
        if link.evidence == "containment":
            shared = sorted(blocks_by_device.get(link.a_device, frozenset())
                            & blocks_by_device.get(link.b_device, frozenset()))
            p2p = [b for b in shared if len(devices_by_block[b]) <= 2]
            if not p2p:
                widest = shared[0] if shared else "(no shared block)"
                members = len(devices_by_block.get(widest, ()))
                excluded.append({
                    "link_key": link.link_key, "reason": "shared_segment_not_a_path",
                    "detail": (f"{link.a_device} and {link.b_device} share {widest}, which "
                               f"{members} devices sit in — a broadcast domain, not a "
                               f"point-to-point path, and counting it as one would hide "
                               f"every cut vertex behind it"),
                })
                continue
        pair = (link.a_device, link.b_device) if link.a_device < link.b_device \
            else (link.b_device, link.a_device)
        links_by_pair.setdefault(pair, []).append(link)
        graph.add_edge(*pair)

    return graph, excluded, links_by_pair


def _address_blocks(
    interfaces: Iterable[NetInterface], by_key: dict[str, NetDevice],
) -> tuple[dict[str, frozenset[str]], dict[str, list[str]]]:
    """(device -> blocks it holds an address in, block -> the devices in it).

    Both directions are needed to tell a /30 transit from a management /24, and
    the block -> devices map is what makes that a counted fact rather than a
    guess at a prefix length.
    """
    per_device: dict[str, set[str]] = {}
    per_block: dict[str, set[str]] = {}
    for iface in interfaces:
        if iface.device_key not in by_key:
            continue
        for raw in iface.addresses:
            net = parse_net(raw)
            if net is None:
                continue
            block = str(net)
            per_device.setdefault(iface.device_key, set()).add(block)
            per_block.setdefault(block, set()).add(iface.device_key)
    return ({dev: frozenset(blocks) for dev, blocks in per_device.items()},
            {block: sorted(devs) for block, devs in per_block.items()})


def _circuit_seeds(
    topology: Topology, by_key: dict[str, NetDevice], caveats: list[str],
) -> tuple[dict[str, tuple[str, ...]], dict[str, Circuit]]:
    """Circuit-terminating devices, and the circuits they carry.

    A circuit whose terminating device this snapshot never saw is NOT quietly
    dropped: it cannot participate in a reachability count (there is no node to
    count from), so it is named in a caveat instead. Silently omitting it would
    make the estate look like it has fewer paths to the outside than it does.
    """
    seeds: dict[str, list[str]] = {}
    by_id: dict[str, Circuit] = {}
    unlocated: list[str] = []
    for circuit in sorted(topology.circuits, key=lambda c: c.circuit_id):
        by_id[circuit.circuit_id] = circuit
        if circuit.device_key and circuit.device_key in by_key:
            seeds.setdefault(circuit.device_key, []).append(circuit.circuit_id)
        else:
            unlocated.append(circuit.circuit_id)
    if unlocated:
        caveats.append(
            f"{', '.join(sorted(unlocated))} report no terminating device this "
            f"snapshot observed, so they are absent from every blast radius here: those "
            f"numbers are a lower bound on what a failure costs")
    return ({dev: tuple(sorted(ids)) for dev, ids in seeds.items()}, by_id)


# ── Blast radius ───────────────────────────────────────────────────────────

class _Impact:
    """Recount connectivity with something removed. Exact, never sampled.

    Each call is one `restricted_view` (O(1)) plus one connected-components pass
    (O(V+E)), so a whole-estate blast radius map is O(V*(V+E)) with no copying.
    That matters because this powers an interactive "lose this device" control:
    an approximation would be a different product.
    """

    def __init__(self, graph: nx.Graph, cpe_circuits: dict[str, tuple[str, ...]],
                 basis: str) -> None:
        self._graph = graph
        self._cpe = cpe_circuits
        self._basis = basis
        comps = self._components(graph)
        self._before = self._reach(comps)
        self._body_before = self._seeds_of(comps[0]) if comps else frozenset()

    def of(self, label: str, removed_nodes: tuple[str, ...] = (),
           removed_edges: tuple[tuple[str, str], ...] = ()) -> BlastRadius:
        view = nx.restricted_view(self._graph, list(removed_nodes), list(removed_edges))
        # ONE components pass per removal, reused for reachability, for the body
        # and for the piece count. It used to be three, which on a 400-device
        # estate is the difference between an interactive control and a spinner.
        comps = self._components(view)
        after = self._reach(comps)
        gone = frozenset(removed_nodes)

        lost = before = degraded = 0
        isolated: list[str] = []
        for node in sorted(self._graph):
            if node in gone:
                continue
            had, has = self._before.get(node, frozenset()), after.get(node, frozenset())
            before += len(had)
            missing = had - has
            if not missing:
                continue
            lost += len(missing)
            if has:
                degraded += 1
            else:
                isolated.append(node)

        body_after = self._seeds_of(comps[0]) if comps else frozenset()
        stranded = () if self._basis == BLAST_BASIS_CONNECTIVITY else tuple(
            sorted(self._body_before - body_after))
        return BlastRadius(
            device_key=label,
            basis=self._basis,
            paths_lost=lost,
            paths_before=before,
            # Rounded here, once, so the R published on a finding is the exact R
            # its severity was computed from. A severity derived from full
            # precision and published against a rounded vector cannot be
            # reproduced by hand, which defeats the point of publishing it.
            fraction=round(lost / before, 4) if before else 0.0,
            devices_isolated=tuple(isolated),
            devices_degraded=degraded,
            circuits_stranded=stranded,
            components_after=len(comps),
        )

    def _components(self, graph) -> list[frozenset[str]]:
        """The pieces of the estate, BODY FIRST.

        "Body" is the largest piece, ties broken on circuit count and then on the
        lowest device key — never on iteration order. Both tie-breaks earn their
        place: a graph that shatters into equal pieces (hub-and-spoke losing its
        hub) has no obvious body, and the piece that still reaches the outside is
        the one an operator would call the estate; leaving it to set order would
        let two runs over identical input disagree about which half is stranded.
        """
        return sorted(
            (frozenset(c) for c in nx.connected_components(graph)),
            key=lambda c: (-len(c), -len(self._seeds_of(c)), min(c)))

    def _seeds_of(self, comp: frozenset[str]) -> frozenset[str]:
        return frozenset(cid for node in comp for cid in self._cpe.get(node, ()))

    def _reach(self, comps: list[frozenset[str]]) -> dict[str, frozenset[str]]:
        """device -> the seeds it can still reach.

        Under the circuit basis a seed is a circuit id, which makes "lost a path
        to the outside" the thing being counted. With no circuit in the snapshot
        the seed is membership of the estate's body, so the same arithmetic
        answers the weaker question `blast_basis` then advertises.
        """
        out: dict[str, frozenset[str]] = {}
        for index, comp in enumerate(comps):
            if self._basis == BLAST_BASIS_CIRCUIT:
                seeds = self._seeds_of(comp)
            else:
                # comps[0] is the body, so membership of it IS the seed.
                seeds = frozenset({"body"}) if index == 0 else frozenset()
            for node in comp:
                out[node] = seeds
        return out


# ── Scoring ────────────────────────────────────────────────────────────────

def _layer_weight(keys: Iterable[str], by_key: dict[str, NetDevice]) -> tuple[float, str]:
    """The heaviest lane among the devices a finding turns on, and why.

    Heaviest rather than the dependent's own lane: a mitigation has to be carried
    out at the hardest end of the dependency, and taking the softest would let an
    access-lane device discount a core-lane repair.
    """
    best, why = 0.0, ""
    for key in sorted(set(keys)):
        dev = by_key.get(key)
        lane = dev.layer if dev is not None else None
        if lane is None:
            weight, reason = UNPLACED_LAYER_WEIGHT, f"{key} could not be placed in a lane"
        else:
            weight = LAYER_WEIGHT.get(lane, UNPLACED_LAYER_WEIGHT)
            reason = f"{key} is in the {lane} lane"
        if weight > best:
            best, why = weight, reason
    return (best or UNPLACED_LAYER_WEIGHT), why


def _score(blast: BlastRadius, layer_weight: float, domain: float) -> tuple[int, str, dict]:
    product = blast.fraction * layer_weight * domain
    severity = round(100 * min(product, 1.0))
    return severity, band(severity), {
        "R": blast.fraction, "L": layer_weight, "S": domain,
        "product": round(product, 4), "basis": blast.basis,
    }


def _provenance_of(keys: Iterable[str], by_key: dict[str, NetDevice],
                   circuits: Iterable[Circuit] = ()) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(source tools, raw refs) for everything a finding names.

    Carried for the same reason every other fact in this system carries it: a row
    an operator cannot take back to the console it came from is a row they have
    to take on trust.
    """
    tools, refs = set(), set()
    for key in keys:
        dev = by_key.get(key)
        if dev is not None:
            tools.add(dev.provenance.source_tool)
            refs.add(dev.provenance.raw_ref)
    for circuit in circuits:
        tools.add(circuit.provenance.source_tool)
        refs.add(circuit.provenance.raw_ref)
    return tuple(sorted(tools)), tuple(sorted(refs))


# ── The rules ──────────────────────────────────────────────────────────────

def _shared_handoff_findings(
    devices: list[NetDevice], by_key: dict[str, NetDevice],
    blast: dict[str, BlastRadius], circuit_by_id: dict[str, Circuit],
    explained: set[str],
) -> list[ResilienceFinding]:
    """One device standing between the estate and two or more circuits (SPOF #1).

    Derived from the graph rather than from a handoff field, because
    `models.Circuit` carries the CPE and not the router it hands off to — and
    because the graph answers the better question anyway: the shared dependency
    is found wherever it sits, including two hops back, and a device that is the
    sole path to two circuits is a single point of failure whether or not it is
    the box the carrier calls the handoff.
    """
    out: list[ResilienceFinding] = []
    for dev in devices:
        radius = blast[dev.device_key]
        if len(radius.circuits_stranded) < 2:
            continue
        stranded = radius.circuits_stranded
        survivors = tuple(sorted(set(circuit_by_id) - set(stranded)))
        weight, why = _layer_weight((dev.device_key,), by_key)
        severity, sev_band, vector = _score(radius, weight, DOMAIN_SHARED_HANDOFF)
        tools, refs = _provenance_of((dev.device_key,), by_key,
                                     [circuit_by_id[c] for c in stranded])
        out.append(ResilienceFinding(
            id=f"resilience:shared_circuit_handoff:{dev.device_key}",
            kind="shared_circuit_handoff",
            title=f"{dev.device_key} is the only path to {len(stranded)} circuits",
            detail=(
                f"{dev.device_key} is the sole path between the estate and "
                f"{', '.join(stranded)}. Losing it takes {len(stranded)} of "
                f"{_n(len(circuit_by_id), 'circuit')} with it"
                + (f", leaving {', '.join(survivors)}" if survivors
                   else ", leaving no path to the outside at all")
                + f". {_n(radius.devices_degraded + len(radius.devices_isolated), 'device')} "
                f"lose a path they had; {len(radius.devices_isolated)} lose every one. "
                f"{why}."
            ),
            severity=severity, severity_band=sev_band, vector=vector, blast=radius,
            devices=(dev.device_key,), failing=(dev.device_key,), circuits=stranded,
            source_tools=tools, raw_refs=refs,
        ))
        explained.add(dev.device_key)
    return out


def _shared_carrier_findings(
    topology: Topology, by_key: dict[str, NetDevice], calc: "_Impact",
    circuit_by_id: dict[str, Circuit], caveats: list[str], suppressed: list[dict],
) -> list[ResilienceFinding]:
    """Two circuits, one carrier (SPOF #2) — diverse links inside one failure domain.

    Grouped case-insensitively on the provider string, because a source that
    spells one carrier two ways would otherwise read as diversity; the provider
    is reported back exactly as the source spelled it.

    A circuit whose provider the source did not report is NEVER grouped with
    another such circuit. "Unknown" is not a carrier, two unknowns are not known
    to be the same one, and a finding that says they are would be invented. The
    unverifiable diversity is stated as a caveat instead.
    """
    groups: dict[str, list[Circuit]] = {}
    unnamed: list[str] = []
    for circuit in sorted(topology.circuits, key=lambda c: c.circuit_id):
        provider = (circuit.provider or "").strip()
        if not provider:
            unnamed.append(circuit.circuit_id)
            continue
        groups.setdefault(provider.casefold(), []).append(circuit)
    if unnamed:
        caveats.append(
            f"{', '.join(sorted(unnamed))} report no provider, so carrier "
            f"diversity CANNOT be confirmed for them — they are not evidence of "
            f"diversity and they are not evidence of a shared carrier either")

    out: list[ResilienceFinding] = []
    for key in sorted(groups):
        members = groups[key]
        if len(members) < 2:
            continue
        provider = members[0].provider or ""
        ids = tuple(c.circuit_id for c in members)
        cpes = tuple(sorted({c.device_key for c in members
                             if c.device_key and c.device_key in by_key}))
        if not cpes:
            # The fact is still true and must not vanish; what cannot be done is
            # put a measured number on it, so it is stated rather than scored.
            suppressed.append({
                "kind": "shared_carrier", "candidate": provider,
                "reason": "terminating devices not observed",
                "detail": (f"{', '.join(ids)} are all {provider}, but no terminating "
                           f"device for them is in this snapshot, so the blast radius "
                           f"cannot be measured"),
            })
            caveats.append(
                f"{', '.join(ids)} are all carried by {provider}: that is a shared "
                f"failure domain, but none of their terminating devices was observed, "
                f"so it could not be scored")
            continue
        missing = tuple(sorted({c.circuit_id for c in members
                                if not c.device_key or c.device_key not in by_key}))
        if missing:
            caveats.append(
                f"{', '.join(missing)} terminate on a device this snapshot did not "
                f"observe, so the {provider} blast radius below counts only the "
                f"circuits whose CPE we can see")
        radius = calc.of(f"carrier:{provider}", removed_nodes=cpes)
        weight, why = _layer_weight(cpes, by_key)
        severity, sev_band, vector = _score(radius, weight, DOMAIN_SHARED_CARRIER)
        tools, refs = _provenance_of(cpes, by_key, members)
        techs = ", ".join(sorted({c.technology for c in members}))
        out.append(ResilienceFinding(
            id=f"resilience:shared_carrier:{provider}",
            kind="shared_carrier",
            title=f"{len(ids)} circuits ride one carrier ({provider})",
            detail=(
                f"{', '.join(ids)} are {'both' if len(ids) == 2 else 'all'} provided by "
                f"{provider} ({techs}). They are "
                f"separate services on separate CPE ({', '.join(cpes)}) and they draw as "
                f"separate lines, but one carrier's backhaul, maintenance window or "
                f"fibre cut takes every one of them: losing {provider} strands "
                f"{_n(len(radius.circuits_stranded) or len(ids), 'circuit')} and costs "
                f"{radius.paths_lost} of {radius.paths_before} device-to-circuit paths. "
                f"{why}."
            ),
            severity=severity, severity_band=sev_band, vector=vector, blast=radius,
            devices=cpes, failing=cpes, circuits=ids,
            source_tools=tools, raw_refs=refs,
        ))
    return out


def _single_homed_findings(
    graph: nx.Graph, devices: list[NetDevice], by_key: dict[str, NetDevice],
    links_by_pair: dict[tuple[str, str], list[NetLink]], blast: dict[str, BlastRadius],
    explained: set[str], suppressed: list[dict],
) -> list[ResilienceFinding]:
    """Devices reaching the estate through exactly one neighbour (SPOF #3, #4).

    This is where the false-positive discipline earns its keep, and the estate is
    built to punish getting it wrong. Five devices have a single adjacency; only
    two of them are findings.

    The three modems are not, and the reason is not "modems are special": each
    one's uplink sits in the `wan-handoff` redundant group WITH A LIVE SIBLING
    landing on a different router, so the purpose that link serves survives its
    loss. The CPE itself does not — which is exactly the residual that
    `shared_circuit_handoff` and `shared_carrier` report, so the risk is
    reported once, in the place it is actionable, rather than five times.

    An endpoint is not a finding either: a server with one NIC is the design, and
    an analyzer that flags every host in a real estate has flagged nothing.
    """
    out: list[ResilienceFinding] = []
    for dev in devices:
        key = dev.device_key
        neighbours = sorted(graph.neighbors(key))
        if len(neighbours) != 1:
            continue
        parent = neighbours[0]
        pair = (key, parent) if key < parent else (parent, key)
        links = links_by_pair.get(pair, [])

        if dev.layer == "endpoint":
            suppressed.append({
                "kind": "single_homed_device", "candidate": key,
                "reason": "endpoint with one uplink",
                "detail": (f"{key} sits in the endpoint lane; a host with a single "
                           f"uplink is the design, not a defect"),
            })
            continue

        sibling = _live_sibling(links, links_by_pair, graph)
        if sibling is not None:
            link, sib = sibling
            suppressed.append({
                "kind": "single_homed_device", "candidate": key,
                "reason": "redundant group has a live sibling",
                "detail": (f"{key}'s only link ({link.link_key}) is in redundant group "
                           f"'{link.redundant_group}', whose sibling {sib.link_key} lands "
                           f"on {sib.a_device}/{sib.b_device} — the purpose this link "
                           f"serves survives its loss, even though {key} does not"),
            })
            continue

        peers = tuple(sorted(
            d.device_key for d in devices
            if d.device_key not in (key, parent)
            and d.layer is not None and d.layer == by_key[parent].layer
            and not graph.has_edge(key, d.device_key)))
        radius = blast[parent]
        weight, why = _layer_weight((key, parent), by_key)
        severity, sev_band, vector = _score(radius, weight, DOMAIN_NONE)
        tools, refs = _provenance_of((key, parent), by_key)
        lane = by_key[parent].layer
        if peers:
            available = (f"{', '.join(peers)} {'sits' if len(peers) == 1 else 'sit'} in "
                         f"the same {lane} lane and {key} has no link to "
                         f"{'it' if len(peers) == 1 else 'any of them'}, so the second "
                         f"uplink it is missing exists in this estate already. ")
        elif lane is None:
            # The reconstruction engine could not place `parent`, so we do not
            # know what its peers would be. Saying "there is nowhere to home a
            # second uplink" would turn a gap in our own coverage into a claim
            # about their cabling.
            available = (f"{parent} could not be placed in a lane from what this "
                         f"snapshot observed, so whether a second uplink was available "
                         f"is unknown rather than no. ")
        else:
            available = (f"No other device sits in the {lane} lane, so there is nowhere "
                         f"in this snapshot to home a second uplink. ")
        out.append(ResilienceFinding(
            id=f"resilience:single_homed_device:{key}",
            kind="single_homed_device",
            title=f"{key} is single-homed to {parent}",
            detail=(
                f"{key} reaches the rest of the estate through {parent} and nothing "
                f"else; its only adjacency is in no redundant group. "
                + available
                + f"Losing {parent} costs {radius.paths_lost} of {radius.paths_before} "
                f"device-to-circuit paths and leaves "
                f"{_n(len(radius.devices_isolated), 'device')} with none. {why}."
            ),
            severity=severity, severity_band=sev_band, vector=vector, blast=radius,
            devices=(key, parent), failing=(parent,),
            links=tuple(sorted(l.link_key for l in links)),
            source_tools=tools, raw_refs=refs,
        ))
        explained.add(parent)
    return out


def _ha_findings(
    devices: list[NetDevice], by_key: dict[str, NetDevice], blast: dict[str, BlastRadius],
    calc: "_Impact", explained: set[str], suppressed: list[dict],
) -> list[ResilienceFinding]:
    """HA pairs whose members share a failure domain.

    Two domains are tested, and both are structural:

      * ONE DEVICE DEFEATS BOTH MEMBERS. If some third device's failure leaves
        every member of the pair with no path to a circuit, the cluster's
        failover is perfect and worthless. This is the finding worth having.
      * ONE SITE, WHEN THERE IS ANOTHER. Members sharing a site matter only if
        the estate HAS a second site; in a single-site estate every device
        shares it, so "both firewalls are in the same building" is a description
        of the building, not a finding.

    Matched model and firmware are deliberately NOT a finding. Every vendor
    REQUIRES matched firmware across a cluster; reporting the vendor's own
    supported configuration as a defect is how a tool teaches operators to
    ignore it.
    """
    groups: dict[str, list[NetDevice]] = {}
    for dev in devices:
        if dev.ha_group:
            groups.setdefault(dev.ha_group, []).append(dev)

    sites = {d.site for d in devices if d.site}
    out: list[ResilienceFinding] = []
    for group in sorted(groups):
        members = sorted(d.device_key for d in groups[group])
        if len(members) < 2:
            continue

        common = [key for key in sorted(blast)
                  if key not in members
                  and all(m in blast[key].devices_isolated for m in members)]
        if common:
            # Several devices can each defeat one pair. Anchor the score on the
            # WORST of them rather than on the first: `sorted()` would make the
            # published severity depend on somebody's naming convention, and all
            # of them are named in the detail either way.
            culprit = min(common, key=lambda k: (-blast[k].paths_lost, k))
            others = tuple(k for k in common if k != culprit)
            radius = blast[culprit]
            weight, why = _layer_weight(tuple(members) + (culprit,), by_key)
            severity, sev_band, vector = _score(radius, weight, DOMAIN_SHARED_HA_DOMAIN)
            tools, refs = _provenance_of(tuple(members) + (culprit,), by_key)
            out.append(ResilienceFinding(
                id=f"resilience:ha_shared_failure_domain:{group}",
                kind="ha_shared_failure_domain",
                title=f"HA pair {group} is defeated by {culprit}",
                detail=(
                    f"{' and '.join(members)} are an HA pair, and losing {culprit} leaves "
                    f"BOTH of them with no path to any circuit. The cluster fails over "
                    f"exactly as designed and has nothing to fail over to. "
                    f"{radius.paths_lost} of {radius.paths_before} device-to-circuit "
                    f"paths go with it"
                    + (f"; {', '.join(others)} "
                       f"{'defeats' if len(others) == 1 else 'defeat'} the pair the same way"
                       if others else "")
                    + f". {why}."
                ),
                severity=severity, severity_band=sev_band, vector=vector, blast=radius,
                # `failing` is the device the published blast radius was measured
                # against; every other device that defeats the pair is carried in
                # `devices` and named in the detail, so none of them is hidden by
                # the choice of anchor.
                devices=tuple(members) + tuple(common), failing=(culprit,),
                circuits=radius.circuits_stranded, source_tools=tools, raw_refs=refs,
            ))
            explained.add(culprit)
            continue

        member_sites = {by_key[m].site for m in members if by_key[m].site}
        if len(member_sites) == 1 and len(sites) > 1:
            site = sorted(member_sites)[0]
            radius = calc.of(f"ha:{group}", removed_nodes=tuple(members))
            weight, why = _layer_weight(members, by_key)
            severity, sev_band, vector = _score(radius, weight, DOMAIN_SHARED_HA_DOMAIN)
            tools, refs = _provenance_of(members, by_key)
            out.append(ResilienceFinding(
                id=f"resilience:ha_shared_failure_domain:{group}",
                kind="ha_shared_failure_domain",
                title=f"HA pair {group} is entirely at site {site}",
                detail=(
                    f"{' and '.join(members)} are an HA pair and both sit at {site}, while "
                    f"this estate spans {len(sites)} sites. Power, cooling and building "
                    f"access are one domain for both members. Losing the pair costs "
                    f"{radius.paths_lost} of {radius.paths_before} device-to-circuit "
                    f"paths. {why}."
                ),
                severity=severity, severity_band=sev_band, vector=vector, blast=radius,
                devices=tuple(members), failing=tuple(members),
                circuits=radius.circuits_stranded, source_tools=tools, raw_refs=refs,
            ))
            continue

        suppressed.append({
            "kind": "ha_shared_failure_domain", "candidate": group,
            "reason": "no shared domain observed",
            "detail": (
                f"{', '.join(members)} keep a path to a circuit through separate "
                f"neighbours when any single other device fails"
                + (f", and {'/'.join(sorted(member_sites))} is the estate's only site, "
                   f"so sharing it distinguishes nothing"
                   if len(sites) <= 1 else "")
                + " — matched model and firmware are not counted here, because every "
                  "vendor requires them across a cluster"),
        })
    return out


def _articulation_findings(
    graph: nx.Graph, by_key: dict[str, NetDevice], blast: dict[str, BlastRadius],
    explained: set[str],
) -> list[ResilienceFinding]:
    """Cut vertices no more specific rule already explained (Hopcroft-Tarjan).

    The specific rules run first and claim their device, so this reports the
    residue: a box whose loss splits the estate for a reason nobody has already
    named. A device that is a cut vertex AND the shared handoff is
    one risk, not two.
    """
    out: list[ResilienceFinding] = []
    for key in sorted(set(nx.articulation_points(graph))):
        if key in explained:
            continue
        radius = blast[key]
        weight, why = _layer_weight((key,), by_key)
        severity, sev_band, vector = _score(radius, weight, DOMAIN_NONE)
        tools, refs = _provenance_of((key,), by_key)
        severed = radius.devices_isolated
        out.append(ResilienceFinding(
            id=f"resilience:articulation_point:{key}",
            kind="articulation_point",
            title=f"{key} is a cut vertex",
            detail=(
                f"Removing {key} breaks the estate into "
                f"{_n(radius.components_after, 'piece')}. "
                + (f"{', '.join(radius.circuits_stranded)} "
                   f"{'is' if len(radius.circuits_stranded) == 1 else 'are'} no longer "
                   f"reachable from the body of the estate. " if radius.circuits_stranded else "")
                + (f"{', '.join(severed)} lose every path to a circuit. " if severed else "")
                + f"{radius.paths_lost} of {radius.paths_before} device-to-circuit paths "
                f"go with it. {why}."
            ),
            severity=severity, severity_band=sev_band, vector=vector, blast=radius,
            devices=(key,), failing=(key,), circuits=radius.circuits_stranded,
            source_tools=tools, raw_refs=refs,
        ))
        explained.add(key)
    return out


def _fragile_link_findings(
    graph: nx.Graph, by_key: dict[str, NetDevice],
    links_by_pair: dict[tuple[str, str], list[NetLink]], calc: "_Impact",
    suppressed: list[dict],
) -> list[ResilienceFinding]:
    """Single cables holding two halves of the estate together.

    A bridge is only a fragile CABLE when one cable is all there is. Three things
    disqualify it, and each is recorded rather than silently applied:

      * a redundant group with a live sibling — the criss-cross, which is the
        false positive this whole module is built to avoid;
      * more than one cable between the same pair, or a LAG with more than one
        member: losing a member does not lose the adjacency;
      * a leaf on either end, which `single_homed_device` already explained (or
        published its reason for declining to).
    """
    out: list[ResilienceFinding] = []
    for a, b in sorted(tuple(sorted(edge)) for edge in nx.bridges(graph)):
        pair = (a, b)
        links = links_by_pair.get(pair, [])
        label = f"{a}~{b}"

        if graph.degree(a) == 1 or graph.degree(b) == 1:
            # The dangling device IS the finding, and `single_homed_device` has
            # already made it (or published why it did not). Reporting the cable
            # as well would be the same risk counted twice.
            continue

        sibling = _live_sibling(links, links_by_pair, graph)
        if sibling is not None:
            link, sib = sibling
            suppressed.append({
                "kind": "fragile_link", "candidate": label,
                "reason": "redundant group has a live sibling",
                "detail": (f"{link.link_key} is in redundant group "
                           f"'{link.redundant_group}' with live sibling {sib.link_key}"),
            })
            continue

        members = sum(max(l.member_count, 1) for l in links)
        if len(links) > 1 or members > 1:
            suppressed.append({
                "kind": "fragile_link", "candidate": label,
                "reason": "adjacency carried by more than one member",
                "detail": (f"{a} and {b} are joined by {_n(len(links), 'link')} totalling "
                           f"{_n(members, 'member')}; losing one member does not lose "
                           f"the adjacency"),
            })
            continue

        radius = calc.of(label, removed_edges=(pair,))
        weight, why = _layer_weight(pair, by_key)
        severity, sev_band, vector = _score(radius, weight, DOMAIN_NONE)
        tools, refs = _provenance_of(pair, by_key)
        out.append(ResilienceFinding(
            id=f"resilience:fragile_link:{label}",
            kind="fragile_link",
            title=f"one cable joins {a} and {b}",
            detail=(
                f"The only adjacency between {a} and {b} is a single link "
                f"({', '.join(sorted(l.link_key for l in links))}) in no redundant group. "
                f"Cutting it splits the estate into "
                f"{_n(radius.components_after, 'piece')} and "
                f"costs {radius.paths_lost} of {radius.paths_before} device-to-circuit "
                f"paths. {why}."
            ),
            severity=severity, severity_band=sev_band, vector=vector, blast=radius,
            devices=pair, failing=(label,), circuits=radius.circuits_stranded,
            links=tuple(sorted(l.link_key for l in links)),
            source_tools=tools, raw_refs=refs,
        ))
    return out


def _live_sibling(
    links: list[NetLink], links_by_pair: dict[tuple[str, str], list[NetLink]],
    graph: nx.Graph,
) -> Optional[tuple[NetLink, NetLink]]:
    """(this link, a sibling that is still standing) or None.

    THE filter this module turns on. A link in a `redundant_group` is an
    alternate path for one purpose, and a sibling in that group which lands on a
    different pair of devices — and is still in the graph — means the purpose
    survives this link's loss. Without it, the criss-cross uplinks and the WAN
    handoff read as five fragile cables and the four real findings drown.

    "Still in the graph" is checked rather than assumed: a sibling whose devices
    this snapshot never saw, or whose adjacency was excluded as a shared segment,
    is not redundancy, and treating it as such would let an unobserved device
    launder a single point of failure into a clean report.
    """
    for link in sorted(links, key=lambda l: l.link_key):
        if not link.redundant_group:
            continue
        own = (link.a_device, link.b_device) if link.a_device < link.b_device \
            else (link.b_device, link.a_device)
        for pair in sorted(links_by_pair):
            if pair == own or not graph.has_edge(*pair):
                continue
            for sib in sorted(links_by_pair[pair], key=lambda l: l.link_key):
                if sib.redundant_group == link.redundant_group:
                    return link, sib
    return None
