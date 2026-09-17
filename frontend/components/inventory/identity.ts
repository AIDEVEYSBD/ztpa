"use client";

/**
 * IDENTITY — the fact that two consoles were describing the same box.
 *
 * This used to be a second screen ("Identity & merges") whose table restated the
 * inventory with fewer columns. The table is gone; what was genuinely unique
 * about it lives here and in `IdentityReview.tsx`:
 *
 *   CORRELATIONS are settled. `/api/assets` reports, per asset, the key the
 *   engine matched on (`hostname`, `context_ip`, …), how confident it was, and
 *   the evidence — which names collapsed into one, and which tools saw it. A
 *   row that carries one is a row where "app-server-07" in AlgoSec and
 *   "appsrv-07" in Wiz were proven to be one machine, and the inventory is
 *   exactly where somebody would look for that.
 *
 *   SUGGESTIONS are not settled. `/api/assets/merge-suggestions` proposes pairs
 *   for a HUMAN to confirm, and the engine never merges on its own because a
 *   wrong merge corrupts a fact permanently.
 *
 * THE TWO FAILURES ARE KEPT APART, and this is the load-bearing part carried
 * over verbatim from the old screen:
 *
 *   - An empty asset list from a FAILED read must never render as "this estate
 *     has no assets" — a statement about a client's network we are in no
 *     position to make.
 *   - An empty suggestion list from a FAILED read must never render as "all
 *     identities resolved deterministically". That is the old bug: the fallback
 *     was `[]`, and a dead endpoint printed a clean bill of health. `undefined`
 *     means "not answered yet or not answered at all"; `[]` means the API
 *     answered and proposed nothing. They are different values here on purpose.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { Asset, Correlation, MergeSuggestion } from "@/lib/types";

/**
 * `/api/assets/merge-suggestions` sends more than `MergeSuggestion` declares.
 * The extra members are all OPTIONAL here: a build of the API that predates
 * them is not a reason to render nothing, and — more importantly —
 * `similarity_available: false` is the difference between a confidence score
 * backed by an embedding model and one backed only by string overlap. A screen
 * that cannot see that field renders the second as though it were the first.
 */
export interface MergeSuggestionDetail extends MergeSuggestion {
  a_ips?: string[];
  b_ips?: string[];
  /** False when the embedding model could not be reached, so `confidence` is
   *  NOT embedding-backed. Rendered, never assumed true. */
  similarity_available?: boolean;
  similarity_unavailable_reason?: string | null;
  /** How the score was arrived at, in the engine's own words. */
  confidence_basis?: string;
  recommended_action?: string;
}

/** What one inventory row's identity looks like once the asset layer is joined
 *  to it. Absent (rather than empty) when nothing matched the row. */
export interface RowIdentity {
  asset?: Asset;
  /** The settled matches behind this identity. */
  correlations: Correlation[];
  /** Every alternative name that collapsed into this one identity. */
  aliases: string[];
  /** Every console the correlation evidence names. */
  tools: string[];
  /** Unconfirmed duplicate proposals naming this row. */
  suggestions: MergeSuggestionDetail[];
}

/** `10.30.7.7/32` and `10.30.7.7` are the same host to a join key. */
function normAddr(a: string): string {
  const v = a.trim().toLowerCase();
  const slash = v.indexOf("/");
  if (slash < 0) return v;
  const prefix = v.slice(slash + 1);
  // Only a single-host mask is dropped; /24 is a block and must not collapse
  // onto the address that starts it.
  return prefix === "32" || prefix === "128" ? v.slice(0, slash) : v;
}

const norm = (s: string) => s.trim().toLowerCase();

function evidenceNames(c: Correlation): string[] {
  const e = c.evidence ?? {};
  const out: string[] = [];
  const names = (e as { names?: unknown }).names;
  if (Array.isArray(names)) out.push(...names.filter((n): n is string => typeof n === "string"));
  const one = (e as { name?: unknown }).name;
  if (typeof one === "string") out.push(one);
  return out;
}

function evidenceTools(c: Correlation): string[] {
  const t = (c.evidence ?? {} as { tools?: unknown }).tools;
  return Array.isArray(t) ? t.filter((x): x is string => typeof x === "string") : [];
}

export interface IdentityState {
  /** The join, or `undefined` for a row the asset layer does not describe. */
  lookup: (item: { key: string; name: string; addresses: string[] }) => RowIdentity | undefined;
  /** `undefined` = not answered. `[]` = answered, and it proposed nothing. */
  suggestions?: MergeSuggestionDetail[];
  /** How many assets carry at least one settled correlation. `undefined` when
   *  the asset read failed — an estate figure is never derived from a failure. */
  correlatedAssets?: number;
  assetsError?: ApiError;
  suggestionsError?: ApiError;
  loading: boolean;
  reload: (withSpinner?: boolean) => void;
  /** Resolve a pair. Rejects with an `ApiError` the caller renders. */
  confirmMerge: (a: string, b: string) => Promise<void>;
}

/**
 * The asset layer, joined to the inventory.
 *
 * `onMerged` fires after a confirmed merge so the caller can re-read the
 * inventory too: a merge re-resolves identities and recomputes, which changes
 * the rows on screen, and a table left on the pre-merge page would be showing a
 * record the engine no longer holds.
 */
export function useIdentity(snapshot?: string, onMerged?: () => void): IdentityState {
  const [assets, setAssets] = useState<Asset[]>();
  const [correlations, setCorrelations] = useState<Correlation[]>();
  const [suggestions, setSuggestions] = useState<MergeSuggestionDetail[]>();
  const [assetsError, setAssetsError] = useState<ApiError>();
  const [suggestionsError, setSuggestionsError] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const [spin, setSpin] = useState(true);

  useEffect(() => {
    let alive = true;
    if (spin) setLoading(true);
    setAssetsError(undefined);
    setSuggestionsError(undefined);

    api
      .assets(snapshot)
      .then((r) => {
        if (!alive) return;
        setAssets((r.assets ?? []) as Asset[]);
        setCorrelations((r.correlations ?? []) as Correlation[]);
      })
      .catch((e) => {
        if (!alive) return;
        // No fallback to []: an empty asset table is a claim about the estate.
        setAssets(undefined);
        setCorrelations(undefined);
        setAssetsError(asApiError(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });

    api
      .mergeSuggestions()
      .then((r) => {
        if (alive) setSuggestions((r.suggestions ?? []) as MergeSuggestionDetail[]);
      })
      .catch((e) => {
        // `undefined`, NOT `[]` — see the header. This is the whole reason the
        // two states are distinguishable.
        if (!alive) return;
        setSuggestions(undefined);
        setSuggestionsError(asApiError(e));
      });

    return () => {
      alive = false;
    };
  }, [snapshot, nonce, spin]);

  const reload = useCallback((withSpinner = true) => {
    setSpin(withSpinner);
    setNonce((n) => n + 1);
  }, []);

  const confirmMerge = useCallback(
    async (a: string, b: string) => {
      await api.confirmMerge(a, b);
      // The suggestion set is invalidated by its own confirmation: keeping the
      // old list on screen would offer a merge that has already happened.
      setSuggestions(undefined);
      setSpin(false);
      setNonce((n) => n + 1);
      onMerged?.();
    },
    [onMerged],
  );

  /** key (lowercased name, alias, or normalised address) -> RowIdentity */
  const index = useMemo(() => {
    const byId = new Map<string, Asset>();
    for (const a of assets ?? []) byId.set(a.asset_id, a);

    const corrByAsset = new Map<string, Correlation[]>();
    for (const c of correlations ?? []) {
      const list = corrByAsset.get(c.asset_id);
      if (list) list.push(c);
      else corrByAsset.set(c.asset_id, [c]);
    }

    /** Suggestion endpoints, by the key they name. */
    const suggByKey = new Map<string, MergeSuggestionDetail[]>();
    const addSugg = (k: string, s: MergeSuggestionDetail) => {
      const key = norm(k);
      if (!key) return;
      const list = suggByKey.get(key);
      if (list) list.push(s);
      else suggByKey.set(key, [s]);
    };
    for (const s of suggestions ?? []) {
      addSugg(s.a, s);
      addSugg(s.b, s);
      for (const ip of s.a_ips ?? []) addSugg(normAddr(ip), s);
      for (const ip of s.b_ips ?? []) addSugg(normAddr(ip), s);
    }

    const out = new Map<string, RowIdentity>();
    const put = (k: string, v: RowIdentity) => {
      const key = norm(k);
      // First writer wins: the asset's own key is registered before its
      // aliases and addresses, so a collision can never demote an exact match.
      if (key && !out.has(key)) out.set(key, v);
    };

    for (const [id, asset] of byId) {
      const corr = corrByAsset.get(id) ?? [];
      const aliases = Array.from(
        new Set(corr.flatMap(evidenceNames).filter((n) => norm(n) !== norm(asset.asset_key))),
      );
      const tools = Array.from(new Set([...(asset.source_tools ?? []), ...corr.flatMap(evidenceTools)])).sort();
      const sugg = Array.from(
        new Set([asset.asset_key, ...aliases, ...(asset.ip_set ?? []).map(normAddr)].flatMap((k) => suggByKey.get(norm(k)) ?? [])),
      );
      const row: RowIdentity = { asset, correlations: corr, aliases, tools, suggestions: sugg };
      put(asset.asset_key, row);
      for (const a of aliases) put(a, row);
      for (const ip of asset.ip_set ?? []) put(normAddr(ip), row);
    }

    // A suggestion can name something the asset list does not (a rename the
    // engine has not folded in yet). It still has to reach its row, so it is
    // registered on its own.
    for (const [key, list] of suggByKey) {
      if (!out.has(key)) out.set(key, { correlations: [], aliases: [], tools: [], suggestions: list });
    }

    return out;
  }, [assets, correlations, suggestions]);

  const lookup = useCallback(
    (item: { key: string; name: string; addresses: string[] }): RowIdentity | undefined => {
      const direct = index.get(norm(item.key)) ?? index.get(norm(item.name));
      if (direct) return direct;
      for (const a of item.addresses) {
        const hit = index.get(normAddr(a));
        if (hit) return hit;
      }
      return undefined;
    },
    [index],
  );

  const correlatedAssets = useMemo(() => {
    if (!correlations) return undefined;
    return new Set(correlations.map((c) => c.asset_id)).size;
  }, [correlations]);

  return {
    lookup,
    suggestions,
    correlatedAssets,
    assetsError,
    suggestionsError,
    loading,
    reload,
    confirmMerge,
  };
}

/** The engine's match keys, spelled out. An unknown key is shown verbatim —
 *  a vocabulary this build has not caught up with is not a reason to hide how
 *  two records were joined. */
export const MATCH_KEY_MEANING: Record<string, string> = {
  hostname: "Hostname — two consoles reported the same name. Deterministic.",
  context_ip:
    "Address inside a shared context — the same IP in the same VPC/tenant, which is what makes the address unambiguous. Deterministic.",
  ip: "Address — the same IP, with nothing else distinguishing the two records.",
  serial: "Serial number — read off the hardware. The strongest join there is.",
  mac: "MAC address — the interface's burned-in address.",
};

export function matchKeyMeaning(key: string): string {
  return MATCH_KEY_MEANING[key] ?? `Match key "${key}" — not a key this build of the console knows. Shown as the engine sent it.`;
}
