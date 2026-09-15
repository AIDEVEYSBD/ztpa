/**
 * Network device glyphs — hand-drawn on the standard visual conventions.
 *
 * Every shape in this file was authored here. None of it is traced from, or
 * copied out of, a vendor stencil: this is a commercial product and a vendor's
 * icon artwork is that vendor's copyright. What we follow is the CONVENTION the
 * stencils established — a puck with four arrows is a router, a box whose arrows
 * cross is a switch, a brick wall is a firewall — and a convention is an idea,
 * which is what makes it free to use and, more to the point, what makes it
 * useful: a network engineer reads these without a legend.
 *
 * See ./README.md before changing anything here. It records why each glyph looks
 * the way it does, and the two rules that are load-bearing rather than aesthetic:
 * the cloud is an OUTLINE because it marks equipment we do not model, and an
 * unknown kind draws a question-mark box because a diagram must not guess.
 */

import type { ComponentType, ReactNode } from "react";

export interface NetIconProps {
  /** Rendered square edge, px. Matches lucide-react's `size`. */
  size?: number;
  className?: string;
  /**
   * Accessible name. Given one, the glyph becomes `role="img"` and carries a
   * `<title>`; without one it is `aria-hidden` — an icon next to its own text
   * label is decoration, and announcing it twice is worse than not at all.
   */
  title?: string;
}

export type IconComponent = ComponentType<NetIconProps>;

/**
 * The shared frame. Every glyph goes through it, so stroke weight, cap/join and
 * the accessibility contract are decided in exactly one place.
 *
 * `stroke="currentColor"` is not a default to be overridden — it is the only
 * colour any glyph may have. The palette flips wholesale between light and dark
 * (see app/globals.css, where every token is redefined under [data-theme]), so a
 * hardcoded hex produces an icon that is invisible in one of the two themes. An
 * invisible device on a topology map is a device the operator does not know they
 * have.
 */
function Glyph({ size = 24, className, title, children }: NetIconProps & { children: ReactNode }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
    >
      {title ? <title>{title}</title> : null}
      {children}
    </svg>
  );
}

// ── Shared motifs ──────────────────────────────────────────────────────────
//
// The forwarding glyphs are deliberately built from two reusable marks, because
// the relationships between them are the whole point: an L3 switch is an L2
// switch that also routes, and the icon has to say so with the same strokes the
// other two use rather than with a different drawing.

/**
 * One straight arrow along the x axis, head at `to`.
 *
 * Heads are drawn as arms trailing back down the shaft, and every arrow in this
 * set runs horizontally (or bends to horizontal) before its head. That is not
 * laziness: rotated heads hand-computed at a 1.5 hairline come out visibly
 * uneven from one glyph to the next, and an icon set that looks hand-wobbled
 * beside lucide-react reads as unfinished product.
 */
function HArrow({ from, to, y }: { from: number; to: number; y: number }) {
  const back = to > from ? to - 2 : to + 2;
  return <path d={`M${from} ${y}H${to}M${back} ${y - 1.5}L${to} ${y}L${back} ${y + 1.5}`} />;
}

/**
 * The switch mark: two arrows that swap sides, crossing at the centre.
 *
 * `y` is the row carrying the two heads; the tails sit 4.5 below it. Crossing is
 * the convention for "this box moves a frame from one port to another", and it
 * is the ONLY mark an L2 switch gets — see `L2SwitchIcon`.
 */
function CrossedArrows({ y }: { y: number }) {
  const tail = y + 4.5;
  return (
    <>
      <path d={`M2.5 ${tail}H8L16 ${y}H21.5M19.5 ${y - 1.5}L21.5 ${y}L19.5 ${y + 1.5}`} />
      <path d={`M21.5 ${tail}H16L8 ${y}H2.5M4.5 ${y - 1.5}L2.5 ${y}L4.5 ${y + 1.5}`} />
    </>
  );
}

/** The flat slab shared by the switch family, so l2 / l3 / bridge read as kin. */
function Slab() {
  return <rect x="2.5" y="17.5" width="19" height="4" />;
}

// ── Forwarding ─────────────────────────────────────────────────────────────

/**
 * ROUTER — the squat puck, four arrows on top: two leaving, two arriving.
 * Diverging row above a converging row is the readable form of "it chooses a
 * path", which is the one thing a router does that nothing else here does.
 */
export function RouterIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <HArrow from={10.5} to={2.5} y={5.5} />
      <HArrow from={13.5} to={21.5} y={5.5} />
      <HArrow from={2.5} to={10.5} y={9.5} />
      <HArrow from={21.5} to={13.5} y={9.5} />
      <ellipse cx="12" cy="16" rx="8.6" ry="2.5" />
      <path d="M3.4 16V18.7M20.6 16V18.7" />
      <path d="M3.4 18.7A8.6 2.5 0 0 0 20.6 18.7" />
    </Glyph>
  );
}

/**
 * L3 SWITCH — the switch slab carrying BOTH marks: the crossed pair it shares
 * with `L2SwitchIcon`, and a straight opposed pair above it for the routed path.
 *
 * This glyph is why the set exists. `models.py` keeps `l2_switch` and
 * `l3_switch` as distinct roles because whether a switch routes decides whether
 * inter-VLAN traffic is a policy decision on that box or a trip to the gateway,
 * and a picture that cannot show the difference cannot be used to reason about
 * either. So the difference here is an added mark, never a redrawn shape.
 */
export function L3SwitchIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <HArrow from={11} to={2.5} y={4.5} />
      <HArrow from={13} to={21.5} y={4.5} />
      <CrossedArrows y={10} />
      <Slab />
    </Glyph>
  );
}

/** L2 SWITCH — the slab and the crossed pair alone: it switches, it does not route. */
export function L2SwitchIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <CrossedArrows y={7} />
      <Slab />
    </Glyph>
  );
}

/**
 * HUB — the same slab, and nothing on it.
 *
 * The emptiness is the statement: a hub makes no forwarding decision, so it gets
 * no arrows. The face carries ports instead, which is all a repeater is. If you
 * are tempted to add an arrow here to make the glyph feel finished, stop — you
 * have just drawn a switch.
 */
export function HubIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="3" y="8.5" width="18" height="7" />
      <path d="M7 11.5V13.8M10.3 11.5V13.8M13.7 11.5V13.8M17 11.5V13.8" />
    </Glyph>
  );
}

/**
 * BRIDGE — the slab with two opposed arrows that do NOT cross. A bridge joins
 * two segments; it does not switch among many, and the absent crossing is how
 * the glyph says that next to `L2SwitchIcon`.
 */
export function BridgeIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <HArrow from={2.5} to={21.5} y={7.5} />
      <HArrow from={21.5} to={2.5} y={12} />
      <Slab />
    </Glyph>
  );
}

// ── Perimeter and edge ─────────────────────────────────────────────────────

/** FIREWALL — the brick wall. Courses are offset, because a wall drawn with its
 *  joints aligned reads as a grid or a table, not as masonry. */
export function FirewallIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="2.5" y="6" width="19" height="12" />
      <path d="M2.5 10H21.5M2.5 14H21.5" />
      <path d="M8.8 6V10M15.2 6V10" />
      <path d="M5.7 10V14M12 10V14M18.3 10V14" />
      <path d="M8.8 14V18M15.2 14V18" />
    </Glyph>
  );
}

/** MODEM — the slab with a carrier waveform passing through it: the box where a
 *  signal stops being a signal and starts being a frame. */
export function ModemIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="2.5" y="7" width="19" height="10" />
      <path d="M5 12q2.35-4.2 4.7 0t4.7 0t4.7 0" />
    </Glyph>
  );
}

/** LOAD BALANCER — one path in, three out. The fan is the whole glyph; the box
 *  is just what the fan happens behind. */
export function LoadBalancerIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <HArrow from={1.5} to={7} y={12} />
      <rect x="8.5" y="8.5" width="7" height="7" />
      <path d="M15.5 10L18.5 6.5H21.5M19.5 5L21.5 6.5L19.5 8" />
      <path d="M15.5 12H21.5M19.5 10.5L21.5 12L19.5 13.5" />
      <path d="M15.5 14L18.5 17.5H21.5M19.5 16L21.5 17.5L19.5 19" />
    </Glyph>
  );
}

/** WIRELESS AP — the radiating arcs. Three of them, widening: one arc is a
 *  signal indicator, three are an access point. */
export function WirelessApIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <path d="M2.81 8.31A13 13 0 0 1 21.19 8.31" />
      <path d="M5.64 11.14A9 9 0 0 1 18.36 11.14" />
      <path d="M8.46 13.96A5 5 0 0 1 15.54 13.96" />
      <rect x="7.5" y="17.5" width="9" height="4" />
    </Glyph>
  );
}

// ── Hosts and workloads ────────────────────────────────────────────────────

/** SERVER — the tower with horizontal drive slots and a status light. Tall and
 *  narrow, so it never reads as one of the wide forwarding slabs. */
export function ServerIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="6" y="2.5" width="12" height="19" />
      <path d="M8.5 7H15.5M8.5 11H15.5M8.5 15H15.5" />
      <path d="M8.5 18.5v.01" />
    </Glyph>
  );
}

/** WORKSTATION — monitor on a stand. The one glyph here that is a person. */
export function WorkstationIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="2.5" y="3.5" width="19" height="13" />
      <path d="M12 16.5V20M7.5 20H16.5" />
    </Glyph>
  );
}

/**
 * VIRTUAL APPLIANCE — `ServerIcon` with a dashed outline.
 *
 * Same interior on purpose: a virtual firewall is the same function as the
 * physical one, and only its outline is provisional. Dashing the whole glyph
 * would say "we are unsure what this is", which is a different claim and belongs
 * to `UnknownIcon`.
 */
export function VirtualApplianceIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="6" y="2.5" width="12" height="19" strokeDasharray="2.5 2" />
      <path d="M8.5 7H15.5M8.5 11H15.5M8.5 15H15.5" />
      <path d="M8.5 18.5v.01" />
    </Glyph>
  );
}

/** CONTAINER — three identical stacked crates. Identical is the point: the unit
 *  is interchangeable, which is what distinguishes it from the server tower. */
export function ContainerIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="3.5" y="3" width="17" height="4" />
      <rect x="3.5" y="10" width="17" height="4" />
      <rect x="3.5" y="17" width="17" height="4" />
      <path d="M7 3V7M7 10V14M7 17V21" />
    </Glyph>
  );
}

// ── Boundaries and abstractions ────────────────────────────────────────────

/**
 * CLOUD — an OUTLINE, and it must stay one.
 *
 * This is the mark for "not our equipment, not modelled": the far side of a
 * boundary, the carrier's core, the internet lane that `TopologyLayer` calls out
 * as never a device we own. Unfilled is the convention for exactly that, and it
 * is the cheapest honest way this product has of drawing a limit — which it
 * needs constantly, because coverage is partial at every client. Fill it and the
 * cloud becomes an object we are claiming to know something about.
 */
export function CloudIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <path d="M7.5 18.2A4 4 0 1 1 7.79 10.21A5 5 0 0 1 17.43 11.04A3.6 3.6 0 0 1 16.9 18.2Z" />
    </Glyph>
  );
}

/** VLAN — the notched tag. A VLAN is a label a frame carries, not a place, and
 *  the tag shape is the convention that keeps it from being drawn as a box. */
export function VlanIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <path d="M20.5 6.5H8.5L3.5 12L8.5 17.5H20.5Z" />
      <circle cx="10" cy="12" r="1" />
    </Glyph>
  );
}

/** SUBNET — a bracketed address block, split where the prefix ends: the network
 *  part and the host part, which is the only thing a CIDR actually says. */
export function SubnetIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <path d="M6 5.5H4V18.5H6" />
      <path d="M18 5.5H20V18.5H18" />
      <rect x="7" y="8.5" width="10" height="7" />
      <path d="M13.5 8.5V15.5" />
    </Glyph>
  );
}

/** PUBLIC IP — a globe with a pin. An address that is reachable from anywhere,
 *  pinned to one place: the pair is the point. */
export function PublicIpIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <circle cx="9.5" cy="13.5" r="6" />
      <path d="M3.5 13.5H15.5" />
      <ellipse cx="9.5" cy="13.5" rx="2.6" ry="6" />
      <path d="M18 12.8C18 12.8 20.6 9.9 20.6 7.6A2.6 2.6 0 1 0 15.4 7.6C15.4 9.9 18 12.8 18 12.8Z" />
    </Glyph>
  );
}

/** WAN CIRCUIT — a span between two terminations with the carrier's segment
 *  drawn as a zigzag: the part of the path that is somebody else's. */
export function WanCircuitIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <path d="M2.5 12H8.5L11 7.5L13.5 16.5L16 12H21.5" />
      <path d="M2.5 9V15M21.5 9V15" />
    </Glyph>
  );
}

// ── The fallback ───────────────────────────────────────────────────────────

/**
 * UNKNOWN — a plain box with a question mark, and deliberately nothing else.
 *
 * This is what an unrecognised kind gets, and it is drawn to look like nothing
 * on the network on purpose. The tempting alternative — fall back to a router,
 * or to whichever glyph the kind string most resembles — is the diagram telling
 * a lie: it puts a role on screen that no console ever reported. `NetDevice`
 * carries `role_source` precisely so an underived role stays visible as one, and
 * this glyph is that field's picture.
 */
export function UnknownIcon(p: NetIconProps) {
  return (
    <Glyph {...p}>
      <rect x="3.5" y="3.5" width="17" height="17" />
      <path d="M9.5 10A2.5 2.5 0 1 1 12 12.5V14.5" />
      <path d="M12 17v.01" />
    </Glyph>
  );
}

// ── Registry ───────────────────────────────────────────────────────────────

/**
 * Keyed by the strings the backend actually emits.
 *
 * Every `DeviceRole` member in backend/src/models.py has an entry, including
 * `unknown` — a device whose role no source declared and the engine could not
 * derive is a real state, and it renders as the question-mark box rather than
 * dropping off the map.
 *
 * The remaining keys are the non-device things a topology screen has to draw:
 * `vlan`, `subnet` and `circuit` are the other infrastructure models; `internet`
 * is the `TopologyLayer` member for the boundary itself. `wan_circuit` is an
 * alias for `circuit` and `cloud` for `internet` so a caller can spell either;
 * they are synonyms for one component, never two different claims. `public_ip`
 * (entries of `Circuit.public_ips`) and `container` (a workload shape a cloud
 * console reports, which is NOT a DeviceRole and must never be mapped onto one)
 * have no model literal of their own — see README.md.
 */
export const NET_ICONS: Record<string, IconComponent> = {
  // DeviceRole
  bridge: BridgeIcon,
  firewall: FirewallIcon,
  hub: HubIcon,
  l2_switch: L2SwitchIcon,
  l3_switch: L3SwitchIcon,
  load_balancer: LoadBalancerIcon,
  modem: ModemIcon,
  router: RouterIcon,
  server: ServerIcon,
  unknown: UnknownIcon,
  virtual_appliance: VirtualApplianceIcon,
  wireless_ap: WirelessApIcon,
  workstation: WorkstationIcon,
  // Other infrastructure entities and their aliases
  circuit: WanCircuitIcon,
  wan_circuit: WanCircuitIcon,
  cloud: CloudIcon,
  internet: CloudIcon,
  subnet: SubnetIcon,
  vlan: VlanIcon,
  // Shapes with no literal of their own
  container: ContainerIcon,
  public_ip: PublicIpIcon,
};

/** Sorted, so a legend built from it is stable between renders and deploys. */
export const NET_ICON_KINDS: readonly string[] = Object.keys(NET_ICONS).sort();

/**
 * Whether a kind has a glyph of its own.
 *
 * Worth asking before rendering: `NetIcon` draws the question-mark box both for
 * `role === "unknown"` (an honest, reported state) and for a kind we simply have
 * no art for (a coverage gap in THIS file). They look the same on screen and are
 * not the same problem, so anything that reports on coverage should separate
 * them here rather than counting question marks.
 */
export function isKnownNetIconKind(kind: string): boolean {
  return Object.prototype.hasOwnProperty.call(NET_ICONS, kind);
}

/**
 * Dispatcher: `<NetIcon kind={device.role} />`.
 *
 * The lookup is exact — no lower-casing, no trimming, no prefix matching. A key
 * that nearly matches is a gap between this file and the backend's vocabulary,
 * and it has to SHOW as the question-mark box so somebody fixes it. Quietly
 * coercing "L3_Switch" into an l3 switch is how an icon set starts asserting
 * roles the data never claimed.
 *
 * It goes through `isKnownNetIconKind` rather than `NET_ICONS[kind] ?? Unknown`
 * because the index signature reaches the prototype chain: a kind of "toString"
 * or "constructor" resolves to an inherited function, which is never nullish, so
 * the fallback would be skipped and React would render whatever that returned.
 */
export function NetIcon({ kind, ...rest }: NetIconProps & { kind: string }) {
  const Icon = isKnownNetIconKind(kind) ? NET_ICONS[kind] : UnknownIcon;
  return <Icon {...rest} />;
}
