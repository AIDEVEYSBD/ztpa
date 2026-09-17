/**
 * Address parsing and the containment vocabulary the drawer shares with the
 * inventory filter.
 *
 * NOTHING HERE ANSWERS A QUESTION ABOUT THE ESTATE. This module decides only
 * whether a string is a well-formed address and whether it denotes one host or a
 * block — both facts about the *query*, never about what the snapshot contains.
 * The engine owns every claim about containment between real records; the client
 * owns the shape of the thing being asked about, because the shape changes what
 * the answer is allowed to say. A host contains nothing, so an empty CONTAINED
 * group for a host is "not applicable", while an empty CONTAINED group for a
 * /16 is "we looked inside it and found none" — two different sentences that
 * would otherwise render identically as "(0)".
 */

/** The inventory filter's containment semantics, sent verbatim as `?mode=`. */
export const IP_MODES = ["intersects", "exact", "contains", "contained_by"] as const;
export type IpMode = (typeof IP_MODES)[number];

/** The default, and the only mode that looks outward from the query — which is
 *  where COVERING rules live. Narrowing the mode narrows the answer, and the
 *  drawer says so on screen rather than letting a quiet default explain a short
 *  list. */
export const DEFAULT_IP_MODE: IpMode = "intersects";

export const IP_MODE_LABEL: Record<IpMode, string> = {
  intersects: "intersects",
  exact: "exact",
  contains: "contains",
  contained_by: "contained by",
};

/** Read strictly from the query's point of view: the query is the subject of
 *  every sentence, the record being matched is the object. */
export const IP_MODE_HINT: Record<IpMode, string> = {
  intersects:
    "Overlap in either direction. The broadest mode, and the one that surfaces rules covering this address without naming it.",
  exact: "Records naming this address exactly as written — nothing wider, nothing narrower.",
  contains: "Records that sit inside this query. Only meaningful when the query is a block.",
  contained_by: "Records wider than this query — the blocks this address sits inside.",
};

export function isIpMode(v: unknown): v is IpMode {
  return typeof v === "string" && (IP_MODES as readonly string[]).includes(v);
}

/** Coerce anything (a URL param, a caller's argument, a payload echo) to a mode
 *  without inventing one: an unrecognised value falls back to the default, and
 *  callers that need to *show* what the server actually used read the payload's
 *  own `mode` string rather than this. */
export function normaliseMode(v: unknown): IpMode {
  return isIpMode(v) ? v : DEFAULT_IP_MODE;
}

export type AddressFamily = "ipv4" | "ipv6";
/** `host` — one address. `block` — a prefix covering more than one address.
 *  A `/32` (or `/128`) is written as a block and denotes a host, and is reported
 *  as a host, because that is what governs whether CONTAINED can be non-empty. */
export type AddressShape = "host" | "block";

export interface ParsedAddress {
  /** The trimmed input, which is what gets sent. No normalisation, no
   *  compression, no case folding: the operator's spelling is what appears in
   *  the header, so the string on screen and the string on the wire are one. */
  value: string;
  family: AddressFamily;
  shape: AddressShape;
  /** Prefix length as written, or null when none was. */
  prefix: number | null;
  /** Address bits for the family — 32 or 128. */
  bits: number;
}

export type AddressParse =
  | ({ ok: true } & ParsedAddress)
  | { ok: false; value: string; reason: string };

function parseV4Octets(s: string): number[] | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    // "010" is octal to some tools and decimal to others. A security console
    // must not be the place where that ambiguity gets resolved by accident.
    if (p.length > 1 && p.startsWith("0")) return null;
    const n = Number(p);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

function looksV6(body: string): boolean {
  if (!/^[0-9A-Fa-f:]+$/.test(body)) return false;
  const doubles = body.split("::").length - 1;
  if (doubles > 1) return false;
  const groups = body.split(":").filter((g) => g !== "");
  if (groups.some((g) => g.length > 4)) return false;
  if (doubles === 1) return groups.length <= 7;
  return body.split(":").length === 8 && groups.length === 8;
}

/**
 * Validate an address or block, client-side, before a request is made.
 *
 * This exists to keep a typo out of the round trip, not to second-guess the
 * engine: anything that parses here is sent unchanged, and the API remains the
 * authority on whether it means anything. A rejection is always accompanied by
 * the reason, because "nothing happened when I pressed Enter" is the worst
 * possible answer to a well-formed question typed slightly wrong.
 */
export function parseAddress(raw: string): AddressParse {
  const value = raw.trim();
  if (!value) return { ok: false, value, reason: "Enter an address or a block." };
  if (/\s/.test(value)) return { ok: false, value, reason: "An address cannot contain spaces." };

  const slash = value.indexOf("/");
  const body = slash === -1 ? value : value.slice(0, slash);
  const prefixText = slash === -1 ? null : value.slice(slash + 1);

  const v4 = parseV4Octets(body);
  const family: AddressFamily | null = v4 ? "ipv4" : looksV6(body) ? "ipv6" : null;
  if (!family) {
    return {
      ok: false,
      value,
      reason: "Not a valid IPv4 or IPv6 address. Expected something like 10.30.7.7 or 10.30.0.0/16.",
    };
  }

  const bits = family === "ipv4" ? 32 : 128;
  let prefix: number | null = null;
  if (prefixText !== null) {
    if (!/^\d{1,3}$/.test(prefixText)) {
      return { ok: false, value, reason: `A prefix must be a number from 0 to ${bits}.` };
    }
    prefix = Number(prefixText);
    if (prefix > bits) {
      return { ok: false, value, reason: `A ${family === "ipv4" ? "/32" : "/128"} is the narrowest ${family} prefix; ${prefixText} is wider than the address is long.` };
    }
  }

  const shape: AddressShape = prefix === null || prefix === bits ? "host" : "block";
  return { ok: true, value, family, shape, prefix, bits };
}

/** How many addresses a parse covers, as a display string. Returns null when
 *  the count is not worth stating (a single host) or would be absurd (v6). */
export function blockSize(p: ParsedAddress): string | null {
  if (p.shape !== "block" || p.prefix === null) return null;
  if (p.family === "ipv6") return `2^${p.bits - p.prefix} addresses`;
  const n = 2 ** (p.bits - p.prefix);
  return `${n.toLocaleString()} addresses`;
}
