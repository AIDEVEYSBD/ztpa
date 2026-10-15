"use client";

/**
 * The admin Audit screen — the reader for `ztpa.audit_log`.
 *
 * The product has recorded every agent/user action since the first commit and
 * has never shown any of it. "There is an audit trail" was a claim with no
 * surface: the only way to read it was psql. This is that surface, and it is
 * bound to `GET /api/audit` — `{items, total, limit, offset}`, admin-only,
 * newest first, with the API bounding `limit`.
 *
 * TWO RULES GOVERN EVERYTHING BELOW, both learned the hard way in this codebase:
 *
 * 1. AN EMPTY TABLE IS A CLAIM. "No actions recorded" says the governance log is
 *    empty — which, on a screen whose entire job is to prove that actions were
 *    recorded, is the single most damaging thing it could get wrong. It is
 *    printed only when the API answered 200 with `total === 0`. Every other
 *    path — a 403, a 404 from a build without the endpoint, a dead backend, a
 *    payload whose shape is not the contract — renders an explicit error panel.
 *
 * 2. A MISSING ACTOR IS NOT A GUESSED ACTOR. `actor_email` / `actor_sub` /
 *    `actor_role` are written inside `db.audit()` from the request context, but
 *    rows written before those columns existed carry null. Those render as
 *    "unattributed", never as the coarse `actor` kind ('user' / 'agent' /
 *    'system') dressed up as a person.
 */

import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { RotateCw, ScrollText, ChevronLeft, ChevronRight } from "lucide-react";
import { ApiError, api, asApiError, type AuditEntry, type AuditPage } from "@/lib/api";
import { isAdmin, type AppRole } from "@/lib/roles";
import { Chip, EmptyState, Skeleton, cn } from "../ui";
import { ErrorState } from "../ui/Feedback";

/** Page sizes offered to the reader. The API bounds `limit` itself; these stay
 *  well inside any sane cap so the screen never asks for more than it may have. */
const PAGE_SIZES = [25, 50, 100] as const;

/** The coarse actor kind from the CHECK constraint — a category, not a person. */
const ACTOR_KIND: Record<string, "info" | "accent" | "neutral"> = {
  user: "accent",
  agent: "info",
  system: "neutral",
};

const ROLE_VARIANT: Record<string, "accent" | "neutral"> = {
  admin: "accent",
  analyst: "neutral",
  viewer: "neutral",
};

/** Local time, seconds included: an audit reader correlating with a server log
 *  needs the second, and "3 minutes ago" is unusable for that. */
function when(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString(undefined, { hour12: false });
}

/**
 * Who did it. Prefers the email, falls back to the AutoX subject, and says
 * "unattributed" when the row carries neither — which is a fact about the row,
 * not a formatting default.
 */
function actorLabel(e: AuditEntry): { text: string; attributed: boolean } {
  const email = e.actor_email?.trim();
  if (email) return { text: email, attributed: true };
  const sub = e.actor_sub?.trim();
  if (sub) return { text: sub, attributed: true };
  return { text: "unattributed", attributed: false };
}

/** `detail` is free-form jsonb. Render it compactly, and never let a long blob
 *  push the columns that matter off the screen. */
function detailText(detail: AuditEntry["detail"]): string {
  if (!detail || typeof detail !== "object") return "";
  const keys = Object.keys(detail);
  if (keys.length === 0) return "";
  try {
    return JSON.stringify(detail);
  } catch {
    // A cyclic or otherwise unserializable payload is still evidence that the
    // row HAS a detail; saying so beats printing nothing and implying it does
    // not. (Not a swallowed failure: nothing was fetched here.)
    return `${keys.length} field${keys.length === 1 ? "" : "s"} (unreadable)`;
  }
}

export function AuditAdmin() {
  const { data: session } = useSession();
  const role = ((session?.user as { role?: AppRole | null } | undefined)?.role ?? null) as AppRole | null;

  const [page, setPage] = useState<AuditPage>();
  const [err, setErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    setErr(undefined);
    return api.audit(limit, offset)
      .then((p) => {
        // Contract check. A 200 whose body is not `{items: [...]}` is a build
        // mismatch, and rendering `undefined` as an empty table would report it
        // to the user as "no actions have been recorded".
        if (!p || !Array.isArray(p.items)) {
          setPage(undefined);
          setErr(new ApiError(200, "The API answered, but not with the audit page shape this screen reads ({items, total, limit, offset}). The frontend and backend are probably different builds.", "/api/audit"));
          return;
        }
        setPage(p);
      })
      // Never `setPage({items: [], ...})` here: a failed read must not be able
      // to render as a governance log with nothing in it.
      .catch((e) => { setPage(undefined); setErr(asApiError(e)); })
      .finally(() => setLoading(false));
  }, [limit, offset]);

  useEffect(() => { load(); }, [load]);

  // Role gate. The API is the real one — this screen cannot grant itself
  // anything — but the nav entry is admin-only (Sidebar's ADMIN group) and so is
  // this, so a non-admin who reaches it by any other route gets the same answer
  // the API would give, phrased as the permissions decision it is rather than as
  // an outage. Nothing is fetched.
  if (!isAdmin(role)) {
    return (
      <ErrorState
        resource="the audit trail"
        error={new ApiError(403, "The audit trail is restricted to administrators. Your session carries the role " + (role ?? "none") + ".", "/api/audit")}
      />
    );
  }

  if (err) return <ErrorState resource="the audit trail" error={err} onRetry={load} />;

  if (loading && !page) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-4 w-3/4 max-w-2xl" />
        <div className="panel divide-y divide-hair">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 p-3">
              <Skeleton className="h-3.5 w-36" /><Skeleton className="h-3.5 w-44" />
              <Skeleton className="h-3.5 w-40" /><Skeleton className="ml-auto h-3.5 w-24" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  // `page` is defined here: the error branch returned, and the loading branch
  // covers the only other way it can be undefined.
  const { items, total } = page!;
  const first = total === 0 ? 0 : offset + 1;
  const last = offset + items.length;
  const canPrev = offset > 0;
  const canNext = last < total;

  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-[13px] text-text2">
        Every action the engine, the agent and signed-in users take is appended here, with the actor
        the request carried. Newest first. Rows are never updated or deleted by the application —
        a snapshot delete only clears the row&apos;s pointer to the snapshot, not the entry.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-0.5 text-[11px] font-medium text-faint">Per page</span>
        <div className="inline-flex items-center gap-px rounded-sm border border-line bg-canvas p-px">
          {PAGE_SIZES.map((n) => (
            <button key={n} onClick={() => { setLimit(n); setOffset(0); }} aria-pressed={limit === n}
              className={cn("focusable cursor-pointer rounded-[3px] px-1.5 py-0.5 font-mono text-[10px] transition-colors duration-100",
                limit === n ? "bg-ink text-on-ink" : "text-faint hover:text-dim")}>
              {n}
            </button>
          ))}
        </div>
        <button onClick={load} className="btn-ghost !h-7 text-[11px]" disabled={loading}>
          <RotateCw size={12} /> {loading ? "Refreshing…" : "Refresh"}
        </button>
        {/* The window, and what it is a window onto. `total` comes from the API's
            COUNT, so this is the size of the log, not the size of this page. */}
        <span className="ml-auto text-[11px] text-text3">
          {total === 0 ? "0 entries" : `${first}–${last} of ${total} entries`}
        </span>
      </div>

      {items.length === 0 ? (
        // Reached only on a 200. See rule 1 in the module docstring.
        <div className="panel">
          <EmptyState icon={ScrollText}
            title={total === 0 ? "No actions recorded yet" : "No entries on this page"}
            sub={total === 0
              ? "The audit log is empty. Run an analysis, classify a change or stage one, and the entries appear here."
              : "The log moved while you were paging. Refresh to jump back to the newest entries."} />
        </div>
      ) : (
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[860px] text-[13px]">
            <thead>
              <tr className="border-b border-border text-left [&>th]:py-2 [&>th]:pl-3 [&>th]:pr-3 [&>th]:text-[11px] [&>th]:font-bold [&>th]:uppercase [&>th]:tracking-[0.08em] [&>th]:text-text3">
                <th>When</th><th>Actor</th><th>Action</th><th>Subject</th><th>Snapshot</th><th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => {
                const who = actorLabel(e);
                const detail = detailText(e.detail);
                return (
                  <tr key={e.id} className="border-b border-hair align-top transition-colors last:border-0 hover:bg-surfaceHover">
                    <td className="mono whitespace-nowrap py-2.5 pl-3 pr-3 text-[11.5px] text-text2">{when(e.ts)}</td>
                    <td className="py-2.5 pr-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={cn("break-all font-medium", who.attributed ? "" : "italic text-text3")}>{who.text}</span>
                        <Chip variant={ACTOR_KIND[e.actor] ?? "neutral"}>{e.actor}</Chip>
                        {/* Absent role stays absent — no implicit "viewer". */}
                        {e.actor_role && <Chip variant={ROLE_VARIANT[e.actor_role] ?? "neutral"}>{e.actor_role}</Chip>}
                      </div>
                    </td>
                    <td className="mono py-2.5 pr-3 text-[11.5px] font-bold">{e.action}</td>
                    <td className="mono break-all py-2.5 pr-3 text-[11.5px] text-text2">{e.subject || <span className="text-text3">—</span>}</td>
                    <td className="mono whitespace-nowrap py-2.5 pr-3 text-[11.5px] text-text3">
                      {e.snapshot_id ? `@${e.snapshot_id.replace(/^snap_/, "").slice(0, 10)}` : "—"}
                    </td>
                    <td className="py-2.5 pr-3">
                      {detail
                        ? <span className="mono block max-w-[420px] break-all text-[11px] text-text3" title={detail}>{detail.length > 160 ? `${detail.slice(0, 160)}…` : detail}</span>
                        : <span className="text-text3">—</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => setOffset(Math.max(0, offset - limit))} disabled={!canPrev || loading}
          className="btn-ghost !h-7 text-[11px] disabled:opacity-40">
          <ChevronLeft size={12} /> Newer
        </button>
        <button onClick={() => setOffset(offset + limit)} disabled={!canNext || loading}
          className="btn-ghost !h-7 text-[11px] disabled:opacity-40">
          Older <ChevronRight size={12} />
        </button>
        <span className="text-[11px] text-text3">offset {offset}</span>
      </div>
    </div>
  );
}
