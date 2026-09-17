"use client";

/**
 * ONE fetch per rule reference, shared by every place that renders one.
 *
 * A finding names up to four rules; an action groups a dozen findings; the same
 * reference (ALGO-001 shadows nearly everything in this estate) shows up on
 * twenty rows at once. Without a shared cache, opening the screen fires the
 * same GET twenty times and expanding a token fires it again.
 *
 * WHAT IS NOT CACHED: failures. A cached `ApiError` turns one bad moment into a
 * permanently broken token that never retries, and "could not load" would then
 * outlive the outage that caused it.
 */

import { useEffect, useState } from "react";
import { asApiError, riskApi, type ApiError, type RuleContext, type RuleDetail } from "@/lib/api";

const CACHE = new Map<string, RuleDetail>();
const INFLIGHT = new Map<string, Promise<RuleDetail>>();

const keyOf = (ref: string, snapshot?: string) => `${snapshot ?? "live"}|${ref}`;

function load(ref: string, snapshot?: string): Promise<RuleDetail> {
  const key = keyOf(ref, snapshot);
  const hit = CACHE.get(key);
  if (hit) return Promise.resolve(hit);
  const running = INFLIGHT.get(key);
  if (running) return running;
  const p = riskApi
    .rule(ref, snapshot)
    .then((d) => { CACHE.set(key, d); return d; })
    .finally(() => INFLIGHT.delete(key));
  INFLIGHT.set(key, p);
  return p;
}

export interface RuleState {
  detail?: RuleDetail;
  /** The engine's per-rule context, or undefined while unknown. Never defaulted
   *  to `[]`: an empty array would read as "the engine resolved this and found
   *  nothing", which is a claim a pending or failed request cannot make. */
  context?: RuleContext[] | null;
  loading: boolean;
  error?: ApiError;
  retry: () => void;
}

/** Fetch one rule reference. `enabled: false` holds the request until a token is
 *  actually expanded, so a collapsed list costs nothing. */
export function useRule(ref: string, snapshot?: string, enabled = true): RuleState {
  const key = keyOf(ref, snapshot);
  const [detail, setDetail] = useState<RuleDetail | undefined>(() => CACHE.get(key));
  const [error, setError] = useState<ApiError>();
  const [loading, setLoading] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!enabled) return;
    const cached = CACHE.get(key);
    if (cached && tick === 0) { setDetail(cached); setError(undefined); return; }
    let alive = true;
    setLoading(true); setError(undefined);
    load(ref, snapshot)
      .then((d) => { if (alive) { setDetail(d); } })
      .catch((e) => { if (alive) { setDetail(undefined); setError(asApiError(e)); } })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [key, ref, snapshot, enabled, tick]);

  return {
    detail,
    context: detail ? (detail.context ?? null) : undefined,
    loading,
    error,
    retry: () => { CACHE.delete(key); setTick((t) => t + 1); },
  };
}

/** The single context entry a compact surface (a list row) should speak for.
 *  A reference can resolve in more than one tool; the first is the one the
 *  engine ordered first, and the full card shows every one of them. */
export function primaryContext(ctx?: RuleContext[] | null): RuleContext | undefined {
  return ctx?.[0];
}
