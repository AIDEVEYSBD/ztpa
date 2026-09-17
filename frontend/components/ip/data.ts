"use client";

/**
 * The fetches behind the drawer, and the rules about what each one is allowed
 * to claim when it fails.
 *
 * Three separate reads land on this screen and they degrade INDEPENDENTLY,
 * which is the whole reason they are three hooks rather than one:
 *
 *   /api/ip        the answer. If this fails there is no screen — every number
 *                  below it would be derived from nothing, so the drawer renders
 *                  the failure and stops.
 *   /api/findings  enrichment ONLY. The finding ids come from /api/ip and stay
 *                  on screen whether or not their titles load; a failure here
 *                  costs detail, never the fact that the address is implicated.
 *   /api/sources   provenance ONLY. Its absence means a tool's `simulated` flag
 *                  is UNKNOWN, and unknown must never render as "live" — the
 *                  badge degrades to silence plus a stated reason, because this
 *                  build's exports are all seeded and implying otherwise to a
 *                  client-facing screen is the exact failure the flag exists for.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { Finding, IpLookupResponse, SourceCard } from "@/lib/types";
import type { IpMode } from "./addr";

/** A read that is either in flight, failed, or has a value — never a value that
 *  silently stands in for a failure. */
export interface Loadable<T> {
  data?: T;
  error?: ApiError;
  loading: boolean;
}

/**
 * Run one address lookup.
 *
 * Keyed on `seq` as well as the address so re-asking the same question re-asks
 * the API. Every in-flight response is gated on a ref token, so a slow answer to
 * an abandoned query can never overwrite the answer to the current one — the
 * drawer is a rapid-typing surface and out-of-order responses are the normal
 * case, not the edge one.
 */
export function useAddressLookup(
  address: string | null,
  mode: IpMode,
  seq: number,
  snapshot?: string,
): Loadable<IpLookupResponse> & { reload: () => void } {
  const [state, setState] = useState<Loadable<IpLookupResponse>>({ loading: false });
  const [nonce, setNonce] = useState(0);
  const token = useRef(0);

  useEffect(() => {
    if (!address) {
      token.current += 1;
      setState({ loading: false });
      return;
    }
    const mine = ++token.current;
    setState({ loading: true });
    api
      .ipLookup(address, mode, snapshot)
      .then((d) => {
        if (token.current === mine) setState({ data: d, loading: false });
      })
      .catch((e) => {
        // No partial payload is kept: a stale `data` next to a fresh error is
        // how a failed lookup ends up rendering somebody else's address.
        if (token.current === mine) setState({ error: asApiError(e), loading: false });
      });
  }, [address, mode, seq, snapshot, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { ...state, reload };
}

export interface FindingIndex {
  /** finding_id -> finding, for the page that was read. */
  byId: Map<string, Finding>;
  /** True when the read did NOT cover the whole snapshot, so an id missing from
   *  `byId` means "not on this page", not "not in this snapshot". */
  partial: boolean;
  /** How many findings the page actually carried. */
  read: number;
  /** How many the snapshot holds, as the API counted them. */
  total: number;
  /** null = the API could not say whether analysis finished. Never rendered as
   *  a clean bill of health. */
  analysisComplete: boolean | null;
  /** Non-empty = findings are MISSING from the snapshot itself, so this
   *  address's involvement may be under-reported. */
  degradedAnalyzers: string[];
}

/** Enrichment for the finding ids the address lookup returned. Fetched once per
 *  snapshot and only while the drawer is open. */
export function useFindingIndex(enabled: boolean, snapshot?: string): Loadable<FindingIndex> {
  const [state, setState] = useState<Loadable<FindingIndex>>({ loading: false });
  const token = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    const mine = ++token.current;
    setState({ loading: true });
    api
      .findings(snapshot)
      .then((page) => {
        if (token.current !== mine) return;
        setState({
          loading: false,
          data: {
            byId: new Map(page.findings.map((f) => [f.finding_id, f])),
            partial: page.has_more,
            read: page.findings.length,
            total: page.total,
            analysisComplete: page.analysis_complete ?? null,
            degradedAnalyzers: page.degraded_analyzers ?? [],
          },
        });
      })
      .catch((e) => {
        if (token.current === mine) setState({ error: asApiError(e), loading: false });
      });
  }, [enabled, snapshot]);

  return state;
}

export interface SourceIndex {
  byTool: Map<string, SourceCard>;
}

/** The source cards, for `simulated` and `tier` on every tool badge. */
export function useSourceIndex(enabled: boolean, snapshot?: string): Loadable<SourceIndex> {
  const [state, setState] = useState<Loadable<SourceIndex>>({ loading: false });
  const token = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    const mine = ++token.current;
    setState({ loading: true });
    api
      .sources(snapshot)
      .then((r) => {
        if (token.current !== mine) return;
        const list = Array.isArray(r?.sources) ? r.sources : [];
        setState({ loading: false, data: { byTool: new Map(list.map((s) => [s.tool, s])) } });
      })
      .catch((e) => {
        if (token.current === mine) setState({ error: asApiError(e), loading: false });
      });
  }, [enabled, snapshot]);

  return state;
}
