/** App role model + the AutoX SSO app-role mapping.
 *
 * Edge-safe on purpose (no DB, no node built-ins): the middleware and the
 * Auth.js `jwt` callback both resolve roles, and both run on the edge runtime.
 *
 * AutoX exposes two role claims. We deliberately use only ONE of them:
 *   autox:roles      - global directory roles, identical across every AutoX app
 *   autox:app_roles  - roles the user holds *in this application* (JWT access
 *                      token only). This is the authoritative input here.
 *
 * AutoX gives role identity, not permissions. The role -> permission mapping is
 * entirely below.
 */

export type AppRole = "admin" | "analyst" | "viewer";

export const APP_ROLES = ["admin", "analyst", "viewer"] as const;

/** Higher wins when a user holds several app roles. */
const RANK: Record<AppRole, number> = { viewer: 1, analyst: 2, admin: 3 };

/** The app-role names to create in the AutoX SSO admin for this client. */
export const SSO_APP_ROLE_NAMES: Record<AppRole, string> = {
  admin: "npr_admin",
  analyst: "npr_analyst",
  viewer: "npr_viewer",
};

/** Built-in mapping: normalized AutoX app role -> our role. Both the prefixed
 *  names we ask for and the bare names are accepted, so a rename in the SSO
 *  admin does not lock everyone out. */
const BUILTIN: Record<string, AppRole> = {
  npr_admin: "admin",
  npr_analyst: "analyst",
  npr_viewer: "viewer",
  admin: "admin",
  analyst: "analyst",
  viewer: "viewer",
  // convenience synonyms — the AutoX role form derives the identifier by
  // lowercasing the display name, so `administrator` is an easy slip to make
  administrator: "admin",
  owner: "admin",
  reviewer: "analyst",
  approver: "analyst",
  readonly: "viewer",
  read_only: "viewer",
};

/** Fold casing/separators/`autox:` prefixes so `NPR-Admin`, `npr.admin` and
 *  `autox:npr_admin` all land on the same key. */
function normalize(name: string): string {
  return String(name)
    .trim()
    .toLowerCase()
    .replace(/^autox[:_-]+/, "")
    .replace(/[\s.:\-/]+/g, "_");
}

/** `SSO_ROLE_MAP` lets an operator remap SSO role names without a deploy:
 *  SSO_ROLE_MAP='{"npr-platform-admin":"admin","npr-read":"viewer"}' */
function overrides(): Record<string, AppRole> {
  const raw = process.env.SSO_ROLE_MAP;
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as Record<string, string>;
    const out: Record<string, AppRole> = {};
    for (const [k, v] of Object.entries(parsed)) {
      const role = normalize(v) as AppRole;
      if ((APP_ROLES as readonly string[]).includes(role)) out[normalize(k)] = role;
    }
    return out;
  } catch {
    return {};
  }
}

export function roleMap(): Record<string, AppRole> {
  return { ...BUILTIN, ...overrides() };
}

/**
 * Map `autox:app_roles` onto a single effective role.
 * Returns `null` when the user holds no role we recognise — that is a real
 * "not entitled" answer, never a silent downgrade to `viewer`.
 */
export function resolveRole(ssoAppRoles: readonly string[] | null | undefined): AppRole | null {
  if (!ssoAppRoles?.length) return null;
  const map = roleMap();
  let best: AppRole | null = null;
  for (const raw of ssoAppRoles) {
    const role = map[normalize(raw)];
    if (role && (!best || RANK[role] > RANK[best])) best = role;
  }
  return best;
}

/** Roles in `autox:app_roles` that we could not map — surfaced on /no-access so
 *  a misnamed SSO role is diagnosable instead of just "access denied". */
export function unmappedRoles(ssoAppRoles: readonly string[] | null | undefined): string[] {
  const map = roleMap();
  return (ssoAppRoles ?? []).filter((r) => !map[normalize(r)]);
}

export const isAppRole = (v: unknown): v is AppRole =>
  typeof v === "string" && (APP_ROLES as readonly string[]).includes(v);

export const atLeast = (role: AppRole | null | undefined, min: AppRole): boolean =>
  !!role && RANK[role] >= RANK[min];

/** Permission helpers — the only place a role turns into a capability. */
export const isAdmin = (role: AppRole | null | undefined): boolean => role === "admin";
export const canApprove = (role: AppRole | null | undefined): boolean => atLeast(role, "analyst");
export const canRead = (role: AppRole | null | undefined): boolean => atLeast(role, "viewer");
