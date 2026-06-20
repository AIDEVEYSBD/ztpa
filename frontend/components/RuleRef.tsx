"use client";

import { useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "./ui";

function side(v: any): string {
  if (!v) return "?";
  if (v.cidrs) return v.cidrs.join(", ");
  if (v.identity) return v.identity;
  return JSON.stringify(v);
}
function svc(r: any): string {
  if (r.protocol === "any" || !r.ports?.length) return r.protocol || "any";
  const p = r.ports[0];
  return `${p.proto}/${p.port_start}`;
}

/** A clickable rule reference. Click opens a popover with the canonical rule.
 *  Span-based (no <button>/<div>) so it can live inside clickable rows. */
export function RuleRef({ refId, snapshot }: { refId: string; snapshot?: string }) {
  const [open, setOpen] = useState(false);
  const [rule, setRule] = useState<any | null>();
  const [loading, setLoading] = useState(false);

  const toggle = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const next = !open;
    setOpen(next);
    if (next && rule === undefined) {
      setLoading(true);
      try { const r = await api.rule(refId, snapshot); setRule(r.rules?.[0] ?? null); }
      catch { setRule(null); } finally { setLoading(false); }
    }
  };

  return (
    <span className="relative inline-block">
      <span role="button" tabIndex={0} onClick={toggle}
        className="mono cursor-pointer text-[10px] text-text2 underline decoration-dotted underline-offset-2 hover:text-text">
        {refId}
      </span>
      {open && (
        <>
          <span className="fixed inset-0 z-40" onClick={(e) => { e.stopPropagation(); setOpen(false); }} />
          <span className="panel absolute right-0 z-50 mt-1 block w-[300px] p-3 text-left shadow-[0_8px_28px_rgba(0,0,0,0.25)]">
            {loading ? (
              <span className="text-[12px] text-text3">loading…</span>
            ) : rule ? (
              <span className="block space-y-1.5 text-[12px]">
                <span className="flex flex-wrap items-center gap-2">
                  <b className="mono">{rule.raw_rule_id}</b>
                  <span className="chip text-[10px]">{rule.source_tool}</span>
                  {rule.source_device && <span className="text-[11px] text-text3">{rule.source_device}</span>}
                </span>
                <span className="mono flex flex-wrap items-center gap-1.5">
                  <span className="break-all">{side(rule.src_value)}</span><ArrowRight size={11} className="shrink-0 text-text3" /><span className="break-all">{side(rule.dst_value)}</span>
                </span>
                <span className="flex flex-wrap items-center gap-1.5">
                  <span className="chip mono text-[10px]">{svc(rule)}</span>
                  <span className={cn("mono border px-1.5 text-[10px]", rule.action === "allow" ? "border-ok-line text-ok" : "border-sev-critical-line text-sev-critical")}>{rule.action}</span>
                  {rule.rule_order != null && <span className="text-[10px] text-text3">order {rule.rule_order}</span>}
                </span>
                {rule.tags?.length > 0 && <span className="block text-[10px] text-text3">tags: {rule.tags.join(", ")}</span>}
              </span>
            ) : (
              <span className="text-[12px] text-text3">Rule {refId} is not in this snapshot.</span>
            )}
          </span>
        </>
      )}
    </span>
  );
}
