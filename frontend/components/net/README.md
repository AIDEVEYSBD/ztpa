# Network device glyphs

`icons.tsx` is a hand-drawn set of 19 stroke-only SVG glyphs for the things a
network topology screen has to draw: the thirteen `DeviceRole` members in
`backend/src/models.py`, the other infrastructure entities (VLAN, subnet,
circuit), the two boundary marks (cloud, public IP), and a container shape.

A network engineer should recognise every one of them without a legend. That is
the entire acceptance criterion.

---

## Why these are drawn and not downloaded

The brief says "use standard network icons". The standard icons that phrase
refers to are Cisco's — the puck-shaped router, the crossed-arrow switch, the
brick-wall firewall. **We do not ship Cisco's icon files.** Those files are
Cisco's artwork, their licence does not permit redistribution inside a
commercial product, and this is a commercial product.

What we do ship is our own artwork drawn on the **visual conventions** those
stencils established. A convention — four arrows on a puck means "this box picks
a path", crossing arrows mean "this box swaps ports", offset brick courses mean
"this box is a wall" — is an idea. Ideas are not protected expression, and the
reason to follow this one is not that it is free: it is that thirty years of
network diagrams have made it *legible*. An engineer reads these at a glance
because they have read the same shapes on every whiteboard of their career.

**So: do not "helpfully" replace these with copied vendor assets.** Not a Cisco
stencil, not a Visio shape library, not an icon pack with a "free for personal
use" line in its licence, not something scraped off a diagram tool. If a glyph
here is wrong, redraw it — the geometry is a handful of numbers in one file and
there is a contact-sheet recipe at the bottom of this page.

## Using them

```tsx
import { NetIcon, NET_ICONS, RouterIcon, isKnownNetIconKind } from "@/components/net/icons";

<NetIcon kind={device.role} size={18} className="text-text2" />   // dispatcher
<NetIcon kind="vlan" title="VLAN 30" />                           // labelled
<RouterIcon size={16} />                                          // direct
```

Props are `{ size?: number; className?: string; title?: string }`, default size
24 — the same shape as a `lucide-react` icon, so these drop in beside `Server`,
`Globe` and the rest without a wrapper.

* **Colour comes from `currentColor` and nothing else.** Every glyph is
  `fill="none" stroke="currentColor"`. Colour it with the text utilities
  (`text-text2`, `text-accent-fg`, `text-sev-critical`). There is not a single
  hex value in `icons.tsx` and there must never be one: `globals.css` redefines
  the whole palette under `[data-theme]`, so a hardcoded colour produces an icon
  that is invisible in one of the two themes, and an invisible device on a
  topology map is a device the operator does not know they have.
* **Accessibility.** Pass `title` and the glyph becomes `role="img"` with a
  `<title>` child. Omit it and the glyph is `aria-hidden="true"` — an icon
  sitting next to its own text label is decoration, and announcing it twice is
  worse than not announcing it at all.
* **Style.** Flat, squared, hairline, `strokeWidth={1.5}`, zero corner radius —
  the house language. The only curves in the set are the ones the convention
  genuinely requires: the cloud, the AP's arcs, the modem's waveform, the
  router's cylinder ends, the globe, and the dots.

## The keys

`NET_ICONS` is keyed by the strings the backend actually emits, so a caller can
pass `device.role` straight through without a mapping table in the middle.

| Key | Where the string comes from |
| --- | --- |
| `modem` `router` `firewall` `l3_switch` `l2_switch` `hub` `bridge` `load_balancer` `wireless_ap` `server` `workstation` `virtual_appliance` `unknown` | `DeviceRole` in `backend/src/models.py` — all thirteen members |
| `vlan` `subnet` `circuit` | the `Vlan` / `Subnet` / `Circuit` models |
| `internet` | the `TopologyLayer` member for the boundary |
| `wan_circuit` | alias for `circuit` |
| `cloud` | alias for `internet` |
| `public_ip` | entries of `Circuit.public_ips`; no literal of its own |
| `container` | a workload shape a cloud console reports; **not** a `DeviceRole` |

The two aliases exist so a caller can spell either name; they resolve to one
component, never to two different claims. `container` is deliberately not mapped
onto any `DeviceRole` — Wiz calling a workload a container is not the estate
declaring a device type, and the two must not be conflated.

`NET_ICON_KINDS` is the sorted key list (build legends from it — sorted, so it
is stable between renders). `isKnownNetIconKind(kind)` says whether a kind has a
glyph of its own; see the fallback rule below for why that matters.

Only six of the thirteen roles appear in the demo estate (`backend/src/estate.py`
has modems, routers, firewalls, L3 and L2 switches and an AP). The other seven
are drawn anyway, because the set covers the model's vocabulary rather than one
estate's contents, and a client whose first onboarding turns up a load balancer
should not meet a question mark.

---

## The glyphs, and the convention each one follows

### Forwarding

These five are built from two shared marks, because the relationships between
them are the point — an L3 switch is an L2 switch that also routes, and the icon
says so with the same strokes rather than with a different drawing.

| Key | Convention | What is drawn |
| --- | --- | --- |
| `router` | puck + four arrows | Squat cylinder; above it two arrows leaving (diverging) over two arriving (converging). Choosing a path is the one thing a router does that nothing else here does. |
| `l3_switch` | box + straight arrows + crossed arrows | The slab, the crossed pair, **and** a straight opposed pair above it. Both marks, because the box does both jobs. |
| `l2_switch` | box + crossed arrows | The slab and the crossed pair alone. Crossing is the convention for "a frame arrives on one port and leaves by another". |
| `hub` | box, no arrows | The slab with ports on its face and nothing above it. |
| `bridge` | box + two opposed arrows | Two arrows that do **not** cross. A bridge joins two segments; it does not switch among many. |

The `l2_switch` / `l3_switch` distinction is load-bearing in this product, not
decorative. `models.py` keeps them as separate roles because whether a switch
routes decides whether inter-VLAN traffic is a policy decision on that box or a
trip to the gateway — a diagram that cannot show the difference cannot be used
to reason about either. The extra straight pair is the whole difference, and it
must stay.

The `hub` glyph is deliberately the emptiest in the set. A hub makes no
forwarding decision, so it gets no arrows, and the bare face is the statement.
**If you find yourself adding an arrow to make it feel finished, stop — you have
just drawn a switch.**

### Perimeter and edge

| Key | Convention | What is drawn |
| --- | --- | --- |
| `firewall` | brick wall | Three courses with offset joints. Aligned joints read as a grid or a table; offset ones read as masonry. |
| `modem` | slab + sine wave | The waveform passes through the box: where a signal stops being a signal and starts being a frame. |
| `load_balancer` | one in, three out | A single inbound arrow, a box, and a three-way fan. The fan is the glyph; the box is only what it happens behind. |
| `wireless_ap` | radiating arcs | Three widening arcs over a small slab. One arc is a signal meter; three are an access point. |

### Hosts and workloads

| Key | Convention | What is drawn |
| --- | --- | --- |
| `server` | tower with slots | Tall and narrow with drive slots and a status light — never mistakable for one of the wide forwarding slabs. |
| `workstation` | monitor on a stand | The only glyph in the set that is a person. |
| `virtual_appliance` | dashed server | `server` with a dashed **outline** and a solid interior. |
| `container` | stacked bars | Three identical crates. Identical is the point: the unit is interchangeable. |

`virtual_appliance` keeps the server's interior on purpose. A virtual firewall
is the same function as the physical one; only its outline is provisional.
Dashing the whole glyph would say "we are unsure what this is", which is a
different claim and belongs to the fallback.

### Boundaries and abstractions

| Key | Convention | What is drawn |
| --- | --- | --- |
| `cloud` / `internet` | outline cloud | An **unfilled** cloud. See the rule below. |
| `vlan` | notched tag | A label with a pointed end and a hole. A VLAN is something a frame carries, not a place. |
| `subnet` | bracketed address block | Brackets around a block, split where the prefix ends — the network part and the host part, which is all a CIDR actually says. |
| `public_ip` | globe + pin | Reachable from anywhere, pinned to one place. The pair is the point. |
| `wan_circuit` / `circuit` | line with a zigzag | A span between two terminations, the carrier's segment drawn as a zigzag: the part of the path that is somebody else's. |
| `unknown` | box with a question mark | See the rule below. |

---

## Two rules that are not style

### 1. The cloud is an outline, and stays one

`CloudIcon` is unfilled on purpose. It is the mark for **"not our equipment, not
modelled"** — the far side of a boundary, the carrier's core, the `internet`
lane that `TopologyLayer` describes as "never a device we own".

This product needs to draw that limit constantly. Coverage is partial at every
client and partial in a different way at each one; an estate whose AlgoSec
covers only the perimeter has a real, honest edge past which we know nothing,
and `topology/reconstruct.py` goes to some length to report unobserved layers as
named absences rather than drawing ghosts. The outline cloud is the free,
standard, instantly-read way to render that edge. Fill it, shade it, give it a
drop shadow, and it stops being a boundary and becomes an object we are claiming
to know something about.

### 2. The fallback is visibly generic, and never a plausible device

`NetIcon` falls back to `UnknownIcon` — a plain box with a question mark, drawn
to look like nothing on the network.

The tempting alternative is to fall back to something plausible: a router, a
server, or whichever glyph the kind string most resembles. **Do not.** An unknown
device drawn as a router is the diagram telling a lie — it puts a role on screen
that no console ever reported. `NetDevice` carries `role_source` precisely so a
role that was never declared or derived stays visible as one, and this glyph is
that field's picture.

For the same reason the lookup is exact: no lower-casing, no trimming, no prefix
matching. A key that nearly matches is a gap between this file and the backend's
vocabulary, and it has to *show* so somebody closes it.

One consequence worth knowing: the question-mark box appears both for
`role === "unknown"` (an honest reported state) and for a kind this file has no
art for (a coverage gap here). They look identical and are not the same problem,
so anything that reports on icon coverage should call `isKnownNetIconKind()`
rather than counting question marks.

---

## Where these deviate from the large-format stencils, and why

* **`l3_switch` carries one straight pair, not two.** A large Cisco multilayer
  stencil shows the router's full four straight arrows over the switch's crossed
  pair. At 24 px with a 1.5 hairline, six arrowheads plus a box collapse into
  noise — the head arms alone need more vertical room than the canvas has. The
  straight set is reduced to the opposed pair that carries the meaning. The
  glyph still says "this box routes *and* switches", which is the distinction
  the product depends on.
* **`container`'s bars are squared, not rounded.** The convention is three
  identical stacked units; the corner radius is not part of what makes it
  readable, and this design system has zero radius everywhere.
* **Bodies are flat rectangles, not 3-D boxes.** The stencils draw isometric
  cubes. This design language is flat and squared, and an isometric box beside a
  `lucide-react` icon looks like it wandered in from another product.

## Legibility floor

Rendered at 13 px the denser glyphs (`l3_switch`, `firewall`, `public_ip`) turn
into texture. They are correct from about **16 px** and comfortable at 18–20 px,
which is where a topology node or a legend row should render them. The simple
ones (`cloud`, `vlan`, `server`, `workstation`, `unknown`) hold up to 13 px and
are safe inline in a table cell.

## Checking a change

There are no snapshot tests — an icon is judged by looking at it. To produce a
contact sheet of every glyph at 96/24/18/13 px, compile the file with the
project's TypeScript, render it with `react-dom/server` into a small HTML grid,
and open that. Two things to check on any change: the glyph still reads at
18 px, and it still reads *against its neighbours* — most of these are
distinguished from a sibling by one mark, and it is the sibling comparison, not
the glyph alone, that catches a regression.

`npx tsc --noEmit` from `frontend/` must stay clean.
