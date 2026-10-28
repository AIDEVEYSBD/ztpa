"use client";

/**
 * Which export the Rule Review screens are looking at, and the run / package
 * this browser last associated with it.
 *
 * WHY THE PACKAGE ID IS REMEMBERED HERE. The API has no "package for this
 * export" read: a package id arrives only from a run (`run.package_id`), from a
 * draft response, or inside the 409 a second draft gets. So the id is kept per
 * export in localStorage as a per-viewer convenience. It is never a source of
 * truth — the package itself is always read back from the API, and a stale id
 * renders the API's 404, not a guess.
 */

import { useCallback, useEffect, useState } from "react";

export type FrrLink = { runId?: string; packageId?: string };

const KEY = "npr-frr.selection";

type Stored = { exportId?: string; links: Record<string, FrrLink> };

function read(): Stored {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return { links: {} };
    const v = JSON.parse(raw) as Stored;
    return { exportId: typeof v.exportId === "string" ? v.exportId : undefined, links: v.links && typeof v.links === "object" ? v.links : {} };
  } catch {
    // Unreadable storage (private window, blocked site data, corrupt JSON) is
    // the same as nothing stored: nothing here is data, only a remembered pick.
    return { links: {} };
  }
}

function write(v: Stored): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(v));
  } catch {
    // Same: losing a remembered pick costs one click, and the screen works
    // without it. Nothing fetched is being discarded here.
    return;
  }
}

export interface FrrSelection {
  exportId?: string;
  link: FrrLink;
  select: (exportId: string) => void;
  setLink: (exportId: string, patch: FrrLink) => void;
}

export function useFrrSelection(): FrrSelection {
  const [state, setState] = useState<Stored>({ links: {} });
  // Read after mount so server and first client render agree.
  useEffect(() => { setState(read()); }, []);

  const select = useCallback((exportId: string) => {
    setState((s) => { const n = { ...s, exportId }; write(n); return n; });
  }, []);
  const setLink = useCallback((exportId: string, patch: FrrLink) => {
    setState((s) => {
      const n = { ...s, links: { ...s.links, [exportId]: { ...s.links[exportId], ...patch } } };
      write(n);
      return n;
    });
  }, []);

  return {
    exportId: state.exportId,
    link: (state.exportId && state.links[state.exportId]) || {},
    select,
    setLink,
  };
}
