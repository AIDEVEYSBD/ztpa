# Network Analyser revamp — plan

**Status:** awaiting approval
**Author:** drafted 2026-09-15
**Target:** Wednesday 2026-09-17 review, then a follow-on phase

---

## 1. What was asked for

The ask, reduced to its spine, is that the product follow the order a network reviewer
actually works in:

> **Sources → Inventory → Insights/Risk → Remediation → Gaps (with evidence)**

Today the console starts at step 3. It opens on a reachability graph of unified assets and
never says where any of it came from, what kind of thing each node is, or what the network
physically looks like. The three additions are the two missing front steps and a topology
picture that a network engineer recognises.

Specific asks, each tracked to a section below:

| Ask | Where it lands |
|---|---|
| Standard network icons | §6 — 18 hand-drawn SVG glyphs on Cisco visual conventions |
| Depict network in topography, gateway router | §6 — the layered canvas |
| Data in VLANs; "these many subnets / VLANs / X" | §6.3 counts readout, §5 inventory |
| Sources: Wiz, FortiTelemetry, the 4 manufacturers | §4 — the source ladder + catalogue |
| Management consoles, bridges, connectors | §4 — source tier is first-class |
| Multiple internet connections, modem per connection | §6.1 lanes 1–2, §7 resilience |
| Don't go down because of one modem / one edge router | §7 — SPOF + blast radius |
| 2 switches, criss-cross, L3 routes at switch level | §6.2 — L2 vs L3 glyphs, SVI gateways |
| Different make and model | §5 — inventory carries platform/model/OS |
| Inventory types (asset, workstation, router, switch, hub, virtual appliance, VLAN, subnet, public IP) | §5 — `DeviceRole` + entity kinds |
| Where did we find it — which subnet, which VLAN, which source | §5 — provenance columns |
| Insights: stale rules, overlapping rules | §7 — anomaly taxonomy; stale reads *unknown* with the API that would close it |
| Remediation and recommendation | §8 — existing loop, extended for non-policy findings |
| Gaps: provision to attach evidence | §9 — OSCAL-shaped register |
| Finding by finding, agent explains, on the visualiser | §6.4 — walkthrough mode |
| Minute level: what policies are associated with this IP | §10 — address drill-down |
| List filters: IP address and source | §5 — hard requirement, both |
| Order of tables: Sources, then Assets | §3 — sidebar and report ordering |

---

## 2. The two decisions that shape everything

### 2.1 We extend AlgoSec rather than inventing a fourth source

The research turned up something that changes the cheapest path materially. **AlgoSec's own
API already returns the device, interface, routing and zone data the topology needs:**

- `GET /api/v1/interfaces` — per-interface hardware name, IP, zone type, and *"IPs behind
  interface"*, which is the single most useful field for topology reconstruction
- `GET /api/v1/interfaces/routingInformation` — `routes[] {dest, mask, gatewayIp, sourceInterface}`
  plus per-device `interfaces[] {interfaceId, ip, hwName, logicalName, vips[]}`
- `GET /api/v1/deviceZones` — zones with member interfaces

AlgoSec is multi-vendor by construction, so its device inventory *is* "different make and
model". It is also the top of the ladder the ask itself describes — *"AlgoSec will give you
visibility of everything."*

So the Wednesday cut extends `backend/data/mock/algosec_export.json` with those three real
payload shapes plus a device inventory. That avoids widening `SourceTool`, `_KNOWN_TOOLS`,
the `sources.tool` DB CHECK, `persist._DEVICE`, `MAX_IP_FANOUT` and four test files — every
one of which is a way to break the engine in the week we cannot afford to.

A Fortinet normalizer (FortiManager JSON-RPC + FortiGate REST) lands in the follow-on phase,
with all that widening done properly in one commit, including deleting the known
`profile.py:813` overreach that relabels unknown tools as `"algosec"`.

**One correction to carry into the room, politely and with evidence:** AlgoSec gives
excellent visibility of *enforcement points*, their policies and L3 reachability. It is a
security-policy model, not a network-inventory model — it will not give you access switches,
VLANs on an access port, or workstations. That is what the console tier and the device tier
exist for, and saying so on the Sources screen is the most valuable thing that screen can do.

### 2.2 Source tier is first-class

The ask states a fallback ladder outright: *aggregator → central management console →
individual devices in their scope*. That becomes an attribute, not a footnote:

```python
SourceTier = Literal["aggregator", "management_console", "device"]
```

It renders on every source card **and on every inventory row**, so a device read from AlgoSec
rather than from its own console says so. That directly answers *"all these devices are
vendor logged-in devices… I read your management console, I get information about all your
devices"* at the row level, which no amount of tool badges on findings does.

---

## 3. Information architecture

Sidebar, after the revamp — Sources first, Assets second, as asked:

```
REVIEW
  Sources          ← new      what we read, at which tier, and what it cannot tell us
  Inventory        ← replaces "Assets & Identity"
  Topology         ← replaces "Network Map"
  Insights         ← new      findings by class, incl. the anomaly taxonomy + resilience
  Risk To-Do                  unchanged (remediation)
  Change Gate                 unchanged
  Staging Area                unchanged
  Gaps             ← new      register with evidence attachment
  Ask the Network             unchanged
  Posture Report              unchanged (section order updated to Sources → Assets)
ADMIN                         unchanged
```

`NetworkMap.tsx` is **not deleted**. The cross-tool path is the one computation no single
console can do, and it stays reachable: the Topology screen has two modes — **Topography**
(the new layered canvas) and **Reachability** (today's graph, moved verbatim). Retiring the
old screen outright is a follow-on decision, not a demo-week one.

---

## 4. Sources screen

Three connected sources (AlgoSec, Guardicore, Wiz) and a catalogue of what else we can read.

Each connected card: tool, **tier**, device/console it represents, last sync, what it
contributed to this snapshot (records, entities, devices, interfaces, VLANs), and — read back
from `sources.config.mode`, which the repo already writes as `{"mode": "simulated_export"}`
and currently nothing reads — an explicit **"simulated export — not a live connector"**
badge. That flag exists today and is invisible; making it visible closes a real honesty hole
before we put 20 vendor logos on a screen.

Catalogue entries carry the real API families from the research, e.g.:

| Vendor | Console | Tier | API | Yields |
|---|---|---|---|---|
| Cisco | Catalyst Center | mgmt console | Intent API `/dna/intent/api/v1/network-device`, `/topology/physical-topology`, `/topology/vlan/vlan-names` | devices, platform/OS, interfaces, VLANs, IP pools, CDP/LLDP links |
| Cisco | Meraki Dashboard | mgmt console | `/organizations/{id}/devices`, `…/devices/uplinks/addresses/byDevice`, `/networks/{id}/appliance/vlans` | **whole multi-WAN picture in one call** — per-uplink private+public IP, gateway, DNS, VLAN |
| Cisco | Secure FMC | mgmt console | REST `/api/fmc_config/v1/domain/{d}/policy/accesspolicies`, `/devices/devicerecords` | policies, rules, objects, HA pairs |
| Fortinet | FortiManager | aggregator | JSON-RPC `/dvmdb/adom/{a}/device`, `/pm/config/adom/{a}/pkg/{p}/firewall/policy` | managed devices + model + firmware, policy packages, address objects, zones |
| Fortinet | FortiGate | device | REST `cmdb/system/interface`, `cmdb/system/sdwan`, `monitor/router/ipv4`, `cmdb/system/ha` | interfaces, VLAN subinterfaces, SD-WAN members, routing, HA |
| Fortinet | Security Fabric (**FortiTelemetry**) | device | `monitor/system/csf` on the **fabric root** | downstream device registration tree |
| Palo Alto | Panorama | aggregator | XML `type=config`, REST `/restapi/v10.2/Policies/SecurityRules` | device groups, rules, objects, templates |
| Palo Alto | PAN-OS | device | `op` cmds: interfaces, routing, HA; **Policy Optimizer `rule-hit-count`** | the only clean source of rule last-hit |
| Juniper | Mist | mgmt console | `/api/v1/sites/{id}/devices`, `…/networks` | WAN edge, switches, VLANs |
| Juniper | Junos Space / Security Director | aggregator | Space REST device + policy APIs | device inventory, policies, zones |
| AlgoSec | ASMS | **aggregator** | `/api/v1/devices`, `/api/v1/interfaces`, `/api/v1/interfaces/routingInformation`, `/api/v1/deviceZones`, `POST /api/v1/rules/hit-count` | multi-vendor devices, interfaces, routing, zones, **rule hit counts** |
| Wiz | Wiz | aggregator | GraphQL `CloudResource`, `NetworkExposure` | VPCs, subnets, security groups, public IPs, exposure paths |
| Guardicore | Akamai Segmentation | aggregator | `/api/v3.0/assets`, `/visibility/policy` | labelled assets, flows, segmentation policy |
| Carrier | ISP / carrier portal (e.g. Airtel) | device | varies, often no API | circuit ID, technology, provider, public IP block |

**FortiTelemetry gets explicit disambiguating copy.** There are two unrelated Fortinet things
with that name. The one meant here is the Security Fabric control plane on TCP/8013 — it has
no public API of its own; you read what it *populated*, via `monitor/system/csf`, and only
from the fabric root. If someone says "we have FortiTelemetry" the screen must already know
the difference.

**Test:** no catalogue entry may declare a count, a percentage, or the word "all". A 20-card
grid must not read as 20 live integrations.

---

## 5. Inventory screen

Replaces Assets & Identity; keeps the existing merge/duplicate panel.

**Entity kinds** (the ask's list, plus what the sources actually yield):
`workstation`, `server`, `router`, `l3_switch`, `l2_switch`, `hub`, `bridge`, `firewall`,
`modem`, `load_balancer`, `wireless_ap`, `virtual_appliance`, `container`, `vlan`, `subnet`,
`public_ip`, `wan_circuit`, `interface`, `unknown`.

`l2_switch` and `l3_switch` are **distinct members**, not a tag — *"unless this switch is L3,
you can't do routes"* is a real distinction and the diagram has to show it.

Columns: Name · Kind · Make/Model · OS · Addresses · **VLAN** · **Subnet** · Zone · Tags ·
**Source (+ tier)** · Findings.

Filters — both are hard requirements:
- **IP address**, with containment semantics (`intersects` / `contains` / `contained_by` /
  `exact`), so `10.30.0.0/16` finds the hosts inside it
- **Source**, plus facets for kind, VLAN, subnet, zone

Header counts, the readout that was asked for verbatim:

```
14 devices · 4 VLANs · 9 subnets · 3 public IPs · 2 WAN circuits · 61 assets
```

Any count no source declared renders `—` with a reason on hover. Never `0`.

**Honesty rules:** a declared kind carries `kind_source` (`declared` | `derived`), enforced
by a DB CHECK so a named role with no provenance cannot be stored. Two sources declaring
different kinds for one entity record a **conflict** rather than silently picking a winner.

---

## 6. Topology canvas

### 6.1 Layers

```
0  Internet
1  WAN circuits          MPLS · P2P · ISDN · broadband · fibre · LTE   (provider named)
2  Modems / CSU-DSU
3  Edge routers
4  Perimeter firewalls   (HA pairs drawn as a bracketed pair)
5  Core / distribution   L3 switches — SVI gateway addresses shown
6  Access switches       L2
7  Segments              VLANs and subnets
8  Hosts and workloads
```

Layout runs **server-side** (`backend/src/topology/order.py`) so node ordering is
deterministic and inside the snapshot fingerprint; the client does only `lane/order → x,y`
arithmetic. The layout returns a `crossings` count so a layout regression is visible.

### 6.2 Icons

18 hand-drawn SVG glyphs, stroke-only, 24×24, `currentColor` (so they theme automatically),
following the well-known Cisco *visual conventions* — which are ideas, not protected files —
rather than shipping Cisco's artwork. Router = puck with four arrows; L2 switch = flat slab
with crossed arrows; L3 switch = cube with crossed *and* straight arrows; firewall = brick
wall; modem = slab with a wave; hub = slab, no arrows; load balancer = 1→3 fan-out; cloud =
**outline, not solid** (Cisco's own convention for "not our equipment" — a free, conventional
way to render the boundary honestly).

### 6.3 Reading the picture

- **Redundancy**: paired devices share a bracket; criss-cross uplinks draw as real links with
  a `redundant_group` tint; aggregated links carry `×2`.
- **VLANs**: 8-colour palette assigned by sorted VLAN id, hatch overlay past 8, `[group VLANs ▾]`
  collapses to zone lanes. Every lane and node also carries a **text label**
  (`VLAN 30 · app-tier`) so colour is never the only carrier.
- **Counts** in the header, as §5.
- **Scale**: collapse-by-default group nodes with explicit expand, not truncate-and-warn. A
  `caps` block (`nodes_shown` / `nodes_total` / `capped_lanes`) is on the response from the
  first commit.
- **Degraded strip**: `analysis_complete`, `degraded_analyzers` and `truncations` are on every
  payload today and read by nothing. The canvas renders them, or a picture over a partial
  analysis looks complete.

### 6.4 Finding-by-finding walkthrough

A `◂ 3 of 17 ▸` stepper. Each step: the canvas focuses and highlights the involved nodes and
links, the side panel shows the deterministic explanation, the rule refs, the severity vector,
and — where available — the model's prose, clearly attributed. Prev/next, keyboard-driven,
and a "raise as gap" button that prefills from the **deterministic** explanation, never the
LLM one.

### 6.5 The no-placeholder rule

**A layer with no observed node is named, not drawn.** No ghost modem, no illustrative
switch, no "typical" topology. An unobserved lane renders an `UnavailableState` carrying the
reason and the exact console API that would fill it, and one click to a tracked gap.

Enforced in the schema, not by discipline:

```sql
-- topology_links.evidence: 'inferred' is deliberately NOT a member.
-- A line with no observation behind it is not storable and therefore not drawable.
CHECK (evidence IN ('lldp','cdp','api_topology','config','routing','declared','containment'))
CHECK ((layer IS NULL) = (layer_source = 'unknown'))
```

---

## 7. Insights

### 7.1 Rule anomalies — the formal taxonomy

The Al-Shaer & Hamed classification, mapped onto findings the engine already produces, in a
UI-layer `lib/anomaly.ts` with a Python contract test. No new `FindingType` in the Wednesday
cut — adding one requires a migration widening the `findings.type` CHECK (`db/schema.sql:195`,
`:211`, `:317`), because `persist.ensure_finding_types` was deliberately removed and the first
insert of an unknown type now raises rather than self-healing.

| Class | Definition | Source today |
|---|---|---|
| Shadowing | earlier rule fully matches a later rule's packets, different action | `shadowed_rule` |
| Generalization | later rule is a superset of an earlier one, different action | `shadowed_rule` signals |
| Correlation | rules partially intersect with different actions | — *not computed* |
| Redundancy | removing the rule does not change the policy | `cidr_overlap` (partial) |
| Over-permissive | any/any, broad CIDR, wildcard service | `over_permissive` |

`cidr_overlap` may **not** be mapped to a conflict class — it compares allow records only and
cannot observe an action difference. Asserted by test.

### 7.2 Stale rules

Named as a row, reading **unknown**, with the exact APIs that would compute it:
AlgoSec `POST /api/v1/rules/hit-count`, Palo Alto Policy Optimizer `rule-hit-count`,
FortiManager `_last_hit`, Panorama `last-hit-timestamp`. Not hidden, not faked.

The engine-side function returns `([], [gap])` when hit counts are absent, with a property
test asserting it can never return `([], [])` — so "no stale rules" can never be printed from
an absence of data.

### 7.3 Resilience — in the Wednesday cut, not deferred

Single-point-of-failure is the most-repeated item in the ask, stated three separate ways, and
it is cheap: articulation points and bridges over the topology link graph is one
Hopcroft–Tarjan pass, and `networkx` is already a dependency.

- **SPOF**: articulation points, bridges, single gateway per segment, single-member LAG,
  HA pair inside one failure domain, circuits sharing a carrier
- **Blast radius**: *"lose this device"* — click a node, everything that loses reachability
  dims. Implemented as a diff of two reachability runs over the existing `reachable()` /
  `who_can_reach()` primitives, which is how Batfish's `differentialReachability` works. No
  new analyzer theory and no telemetry needed.

Resilience findings get **their own severity vector** (`blast_radius`, `D`, `layer_weight`,
`srlg_shared`) rather than borrowing the policy vector `E·P·D·B`, whose named terms would not
describe the finding. The vector is published and hand-recomputable, like the existing one.

---

## 8. Remediation — the step that silently breaks

`RiskTodo`'s accept button is `disabled={sending || !rem.validation.resolves}`, and
`validation.resolves` comes from re-simulating a proposed `PolicyRecord` delta. **A resilience
finding has no policy change.** So new finding classes would arrive at a remediation loop
whose accept path is permanently greyed out — step 4 of the five-step process, broken by the
revamp.

Fix: findings declare a `remediation_kind` — `policy_change` (today's path, unchanged) or
`advisory` (a recommendation with no simulable delta, which routes to the Gaps register with
an owner and a due date instead of to the Change Gate).

Also in scope: `rank_deterministic` and the campaign planner need type weighting, or hygiene
findings swamp the Risk To-Do and the top-ranked action becomes "add a comment to rule
ALGO-014".

And `advisory/explain.py` needs a branch per new finding class — it is what powers the
walkthrough, and without it the headline interaction reads worst on exactly the findings the
revamp introduces.

---

## 9. Gaps and evidence

OSCAL vocabularies, used verbatim so the register exports as assessment-results / POA&M
nearly free:

- `GapStatus`: `open` · `investigating` · `remediating` · `deviation-requested` ·
  `deviation-approved` · `closed`
- `Determination`: `satisfied` · `not_satisfied` · **`not_determined`** — kept distinct,
  because collapsing "could not determine" into a failure is as wrong as collapsing it into a
  pass
- `EvidenceMethod`: `EXAMINE` · `INTERVIEW` · `TEST`
- Evidence requires a non-empty `description` (`min_length=1`, refused at the API, not
  discouraged in the UI); carries `collected_at` and `expires_at`, and expired evidence does
  not count toward closure
- Append-only `gap_events` status log, on the existing `(thread_id, seq)` pattern

Gaps are **governance data, not snapshot data**: `snapshot_id` is nullable with `ON DELETE
SET NULL`, like `change_requests`, so a recompute never destroys the register.

Gaps are also *generated*: `coverage_report()` crosses the analytics we could run against the
data classes present in the snapshot and emits one idempotent gap per analytic that could not
run, each naming the vendor API that would close it. That is the operational form of
"completeness of process" — and it makes "what we cannot compute" a derived artefact rather
than a hand-maintained list that rots.

On a historical snapshot the register is read-only, consistent with the existing rule.

---

## 10. Address drill-down — "what policies are associated with this IP"

`GET /api/ip?address=10.30.7.7&mode=intersects`

A drawer, opened from ⌘K in the Topbar and from every address chip in the product. Policies
grouped by relation:

```
EXACT MATCHES (2)      rules naming this address
COVERING RULES (4)     rules whose source/dest contains it   ← the one people forget
CONTAINED RULES (1)    rules inside it, when the query is a block
```

Each row carries `matched_via` (`containment` · `alias_map` · `interface` · `nat`) so the set
arithmetic is visible, plus the owning asset, its VLAN and subnet, its interfaces, and the
findings it appears in.

The effective-access block prints the **ENGINE.md §10.1 deny-union caveat on screen**, next
to the "reachable from the internet: no" claim it qualifies — not buried in a doc.

---

## 11. Bugs found while planning — fixed first, independently of the feature

| # | Bug | Evidence |
|---|---|---|
| B1 | `/api/graph` re-derives zones with the **2-arg** `zone_of(node_id, tags)` while the engine uses the 4-arg form with `ip_set` and `kind`. A named object resolving to `0.0.0.0/0` renders `internal` where the engine scored `internet` — the console shows a different zone than the severity used | `backend/app/main.py:1035` vs `graph/build.py` |
| B2 | Tool colours duplicated across three files; a topology legend would make it four | `NetworkMap.tsx`, `ui/Badges.tsx`, `Landing.tsx` |
| B3 | `api.findings` is not typed to read `total` / `has_more` / `analysis_complete` / `degraded_analyzers` / `truncations`; band counters computed from one page under-report silently | `frontend/lib/api.ts` |
| B4 | The `traced` toggle dims every node to 32% and every edge to 0.18 when there are no paths — a clean snapshot renders as an unexplained smear | `NetworkMap.tsx` |
| B5 | `ZTNode.sub` renders only `ip_set[0]`, hiding addresses on multi-homed assets | `NetworkMap.tsx` |
| B6 | `GET /api/findings/{fid}` hardcodes `sid()` and 404s on a historical snapshot | `backend/app/main.py:1212` |
| B7 | `sources.config = {"mode": "simulated_export"}` is written and read by nothing — the product knows its sources are simulated and never says so | `persist.py:118` |

**Verified not a problem:** multi-interval services (`tcp/80,443`) *are* recoverable — the
analyzers already re-derive them via `parse_service(rec.service).ports`
(`shadowing.py:78`, `over_permissive.py:83`, `transport_exposure.py:72`).

---

## 12. The engine risks this must not trip

1. **The `abstract` fold is how the two-graph separation leaks.** `Asset.kind` is folded as
   `abstract = all(e.abstract for e in ents)` — one dissenting tool view makes the merged
   asset concrete. Inventory work changes exactly those inputs. If a new source calls a
   subnet-denoting object a device, that node becomes a legal intermediate hop in
   `_valid_traversal` and **the engine fabricates a cross-tool path**. This needs no code in
   `graph/` to change. Guard: a test asserting no inventory classification can flip an entity
   from abstract to concrete.
2. **Two-graph firewall.** Topology links live in their own graph. A test greps
   `backend/src/graph/` for any `src.topology` import, and a `verify_engine.py` gate asserts
   `cross_tool_paths` is byte-identical with and without topology data present.
3. **`MAX_IP_FANOUT = 3` is hardcoded** and must become `len(HOST_DESCRIBING_TOOLS)`, raised
   in the same commit as any new host-describing normalizer. A withheld four-tool merge
   silently splits an asset and can make the five-hop path vanish with no error.
4. **Golden re-baseline.** Any snapshot change re-baselines `test_demo_golden.py`. Follow the
   documented procedure: diff the full output, attribute each difference beside the number,
   and treat any unattributable difference as a regression. `verify_engine.py` P5's fifteen
   sub-checks on the cross-tool path stay green and unchanged. The fixture is written to
   contribute **zero `PolicyRecord`s**, and its management addresses sit in an unused
   `10.255.0.0/24` with no declared scope, so the diff is three attributable facts: snapshot
   id, asset count, new asset fields.
5. `pyproject.toml` sets `filterwarnings = ["error"]`. One `datetime.utcnow()` or one
   unclosed cursor reds the whole suite.

---

## 13. Delivery

**Phase 0 — land the branch (before anything else).**
`remediation/prod-readiness` is 17 commits ahead of `main`, 0 behind, never pushed, and green
(1674 pass, 61 skip, `tsc` clean). Merge it, correct the stale `REMEDIATION-LOG.md` header,
and start this work on a fresh branch.

**Phase 1 — bugs + spine (§11 + §2).** B1–B7, the source-tier model, the AlgoSec topology
export extension, the inventory migration, the golden re-baseline. Re-baseline lands
*immediately* after the normalizer, not the night before.

**Phase 2 — Sources + Inventory screens (§4, §5).** Both filters, the counts readout, the
provenance columns.

**Phase 3 — Topology canvas (§6).** Glyphs, layers, VLAN banding, walkthrough, `caps`,
degraded strip. The `Reachability` mode carries today's graph across unchanged.

**Phase 4 — Resilience + address drill-down (§7.3, §10).**

**Phase 5 — Gaps + evidence (§9), remediation routing (§8).**

**Cut order if time runs short:** cut Phase 5's write path before Phase 4; cut the catalogue
breadth before the canvas. **Never cut:** the fixture, the layered canvas, the IP filter, the
walkthrough, or any honesty invariant in §6.5 / §12.

**Follow-on (not this week):** the Fortinet normalizer with the full `SourceTool` widening and
the `profile.py:813` relabel deleted in the same commit; live connectors; OSCAL export.

---

## 14. The risk worth naming out loud

Every honesty decision above is individually right. Nobody has designed the **ratio**.

On the day, the dominant visual mass of this revamp could be absence — named-but-empty lanes,
a "not computed" section, a gaps register whose first rows are the engine confessing what it
could not run, inferred-vs-declared markers on every row, truncation disclosures on every
payload. A reviewer who spends four minutes reading a product tell him what it cannot do will
not remember the thing it uniquely can.

Two mitigations are built into the plan. The topology lands **fixture-backed with real device
data**, so what fills the screen is the network, not a styled void. And absence is
**concentrated** — one collapsible strip and the Gaps register — rather than sprayed across
every lane and every row.

The cross-tool path stays reachable as a mode of the Topology screen. It is still the only
thing here that no single console can compute, and the revamp must not bury it.
