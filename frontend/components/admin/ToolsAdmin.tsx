"use client";

import { useEffect, useMemo, useState } from "react";
import { ChevronRight, Wrench, Sparkles, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";
import type { ToolInfo } from "@/lib/types";
import { cn, Skeleton } from "../ui";

const fmtCost = (n: number) => (n >= 0.01 ? `$${n.toFixed(2)}` : n > 0 ? `$${n.toFixed(4)}` : "$0");
const fmtNum = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n));

export function ToolsAdmin() {
  const [tools, setTools] = useState<ToolInfo[]>();
  const [roles, setRoles] = useState<string[]>(["admin", "analyst", "viewer"]);
  const [open, setOpen] = useState<string | null>(null);
  const [saving, setSaving] = useState<string>();

  const load = () => api.adminTools().then((r) => { setTools(r.tools); setRoles(r.roles); }).catch(() => setTools([]));
  useEffect(() => { load(); }, []);

  const totals = useMemo(() => {
    const t = { uses: 0, tokens: 0, cost: 0 };
    (tools ?? []).forEach((x) => { t.uses += x.metrics.uses; t.tokens += x.metrics.total_tokens; t.cost += x.metrics.est_cost_usd; });
    return t;
  }, [tools]);

  const toggle = async (tool: ToolInfo, role: string) => {
    const next = tool.enabled_roles.includes(role)
      ? tool.enabled_roles.filter((r) => r !== role)
      : [...tool.enabled_roles, role];
    setSaving(tool.key);
    setTools((cur) => cur?.map((t) => (t.key === tool.key ? { ...t, enabled_roles: next } : t)));
    try { await api.setToolRoles(tool.key, next); } catch { load(); } finally { setSaving(undefined); }
  };

  if (tools === undefined) {
    return <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => (
      <div key={i} className="panel flex items-center gap-3 p-3"><Skeleton className="h-4 w-48" /><Skeleton className="ml-auto h-4 w-40" /></div>
    ))}</div>;
  }

  const sections: [string, ToolInfo["kind"]][] = [["Deterministic agent tools", "agent_tool"], ["AI capabilities", "ai_capability"]];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Kpi label="Tools" value={String(tools.length)} />
        <Kpi label="Total invocations" value={fmtNum(totals.uses)} />
        <Kpi label="Total tokens" value={fmtNum(totals.tokens)} />
        <Kpi label="Est. cost" value={fmtCost(totals.cost)} />
      </div>
      <p className="text-[12px] text-text3">
        Toggle which roles may use each tool. Disabling a tool for a role blocks it for that role across the app
        (the backend fails closed). Local Ollama inference is $0 — cost reflects any hosted-provider calls.
      </p>

      {sections.map(([title, kind]) => (
        <div key={kind} className="space-y-2">
          <div className="label flex items-center gap-1.5">
            {kind === "agent_tool" ? <Wrench size={13} /> : <Sparkles size={13} />} {title}
          </div>
          {tools.filter((t) => t.kind === kind).map((t) => {
            const isOpen = open === t.key;
            return (
              <div key={t.key} className="panel overflow-hidden">
                <div className="flex flex-wrap items-center gap-3 p-3">
                  <button onClick={() => setOpen(isOpen ? null : t.key)} className="flex min-w-0 flex-1 items-center gap-2 text-left">
                    <ChevronRight size={15} className={cn("shrink-0 text-text3 transition-transform", isOpen && "rotate-90")} />
                    <span className="min-w-0">
                      <span className="text-[13px] font-bold">{t.label}</span>
                      <span className="ml-2 font-mono text-[11px] text-text3">{t.key}</span>
                      <span className="block truncate text-[11px] text-text3">{t.description}</span>
                    </span>
                  </button>
                  <div className="flex items-center gap-1.5">
                    {roles.map((r) => {
                      const on = t.enabled_roles.includes(r);
                      return (
                        <button key={r} onClick={() => toggle(t, r)} disabled={saving === t.key}
                          className={cn("border px-2 py-1 text-[11px] capitalize", on ? "border-accent bg-accent-soft text-text" : "border-border text-text3 hover:bg-surfaceHover")}>
                          {r}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-hair px-3 py-2 text-[11px] text-text3">
                  <Metric label="uses" value={fmtNum(t.metrics.uses)} />
                  <Metric label="avg latency" value={`${t.metrics.avg_latency_ms} ms`} />
                  <Metric label="tokens" value={fmtNum(t.metrics.total_tokens)} />
                  <Metric label="cost" value={fmtCost(t.metrics.est_cost_usd)} />
                  {t.metrics.errors > 0 && (
                    <span className="flex items-center gap-1 text-sev-high"><AlertTriangle size={11} /> {t.metrics.errors} errors</span>
                  )}
                  {t.metrics.last_used && <span>last used {new Date(t.metrics.last_used).toLocaleString()}</span>}
                </div>
                {isOpen && (
                  <div className="border-t border-hair bg-surfaceHover px-3 py-2.5 text-[12px]">
                    <div className="mb-1 font-semibold text-text2">Example output</div>
                    <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] text-text3">{t.example_output}</pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel p-3">
      <div className="label text-[10px]">{label}</div>
      <div className="mt-0.5 text-[20px] font-bold tabular-nums">{value}</div>
    </div>
  );
}
function Metric({ label, value }: { label: string; value: string }) {
  return <span><span className="text-text2 font-medium tabular-nums">{value}</span> {label}</span>;
}
