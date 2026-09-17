"use client";

/**
 * Per-operator table preferences — which columns are on, and how dense the rows
 * are — held in `localStorage`.
 *
 * TWO RULES, both learned the hard way:
 *
 *   1. EVERY read and write is wrapped. `localStorage` is not a plain object:
 *      it THROWS on access in a private window with site data blocked, inside a
 *      sandboxed frame, and in some embedded webviews — and an unhandled throw
 *      here would take the whole inventory screen down over a cosmetic
 *      preference. A storage that cannot be read is simply a storage with no
 *      preference in it.
 *
 *   2. The first render is always the DEFAULT, and the stored value is applied
 *      in an effect. Reading storage during render would make the server's HTML
 *      and the browser's first paint disagree, and React would throw away the
 *      tree to fix it. One frame of the default layout is cheaper than a
 *      hydration mismatch.
 *
 * Nothing in here is allowed to influence WHAT the screen claims — only how it
 * is laid out. A hidden column is a hidden column, never a dropped fact: the
 * export says how many columns it wrote, and the drawer always carries the full
 * record regardless of what the table is showing.
 */

import { useCallback, useEffect, useRef, useState } from "react";

/** Namespaced so a key can never collide with another screen's preference. */
const NS = "npr-inventory";

export const PREF_KEYS = {
  columns: `${NS}.columns`,
  density: `${NS}.density`,
} as const;

/** Read a JSON preference. Returns `undefined` for "nothing stored" AND for
 *  "storage could not be read" — the two are the same thing to a caller that
 *  has a default. */
export function readPref<T>(key: string, validate: (v: unknown) => v is T): T | undefined {
  try {
    if (typeof window === "undefined") return undefined;
    const raw = window.localStorage.getItem(key);
    if (raw === null) return undefined;
    const parsed: unknown = JSON.parse(raw);
    return validate(parsed) ? parsed : undefined;
  } catch {
    // Unreadable storage, or a value this build's validator rejects (an older
    // shape). Either way: fall back to the default rather than throw.
    return undefined;
  }
}

/** Write a JSON preference. A failure is swallowed on purpose — a quota error
 *  or a blocked store must not interrupt the interaction that caused it. */
export function writePref(key: string, value: unknown): void {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // A REVIEWED discard — the one shape of failure this codebase's no-empty-catch
    // rule is not aimed at. Nothing rendered is derived from whether this write
    // landed: the preference is COSMETIC (which columns are on), the session
    // already honours it in memory, and the table on screen is correct either
    // way. There is no fact here that could be reported as a zero, so there is
    // nothing for an ErrorState to say — only a choice that will not survive a
    // reload, and interrupting the click that caused it would be the worse
    // outcome. The explicit `return` is the reviewed decision, in code.
    return;
  }
}

/** Remove a preference, so "reset" genuinely resets rather than re-saving the
 *  defaults under the same key. */
export function clearPref(key: string): void {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.removeItem(key);
  } catch {
    // Same reviewed discard as `writePref`: a storage that cannot be removed
    // from is a storage that could not be read either, so the default the
    // caller has just restored is already what the next mount will use.
    return;
  }
}

/**
 * State that mirrors itself into `localStorage`.
 *
 * `initial` is what renders first, every time — see rule 2 above. The stored
 * value lands one effect later, and only if it passes `validate`.
 */
export function usePersistentState<T>(
  key: string,
  initial: T,
  validate: (v: unknown) => v is T,
): [T, (next: T) => void, () => void] {
  const [value, setValue] = useState<T>(initial);
  // The stored value must not be written back before it has been read, or a
  // default render would overwrite the operator's saved choice on every mount.
  const hydrated = useRef(false);

  useEffect(() => {
    const stored = readPref(key, validate);
    if (stored !== undefined) setValue(stored);
    hydrated.current = true;
    // `validate` is a module-level predicate; re-running on identity is noise.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const set = useCallback(
    (next: T) => {
      setValue(next);
      if (hydrated.current) writePref(key, next);
    },
    [key],
  );

  const reset = useCallback(() => {
    setValue(initial);
    clearPref(key);
    // `initial` is a constant per call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return [value, set, reset];
}

// ── Density ────────────────────────────────────────────────────────────────

export type Density = "comfortable" | "compact";

export function isDensity(v: unknown): v is Density {
  return v === "comfortable" || v === "compact";
}

export const DENSITY_LABEL: Record<Density, string> = {
  comfortable: "Comfortable",
  compact: "Compact",
};

export function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}
