"use client";

import { useEffect, useState } from "react";
import { Activity, Coins, Cpu, Gauge, Database, GitBranch, Rocket, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";
import type { AdminMetrics } from "@/lib/types";
import { cn, Skeleton } from "../ui";

const fmtCost = (n: number) => (n >= 0.01 ? `$${n.toFixed(2)}` : n > 0 ? `$${n.toFixed(4)}` : "$0");
const fmtNum = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(Math.round(n)));
const RANGES = [7, 30, 90];

export function MetricsAdmin() {
  const [m, setM] = useState<AdminMetrics>();
  const [days, setDays] = useState(30);
  const [err, setErr] = useState(false);

  useEffect(() => { setM(undefined); setErr(false); api.adminMetrics(days).then(setM).catch(() => setErr(true)); }, [days]);

  if (err) return <div className="panel border-sev-critical-line bg-sev-critical-bg p-3 text-[13px] text-sev-critical">Could not load metrics.</div>;
  if (!m) return <div className="space-y-3"><div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="panel p-4"><Skeleton className="h-3 w-20" /><Skeleton className="mt-2 h-6 w-24" /></div>)}</div></div>;

  const t = m.totals;
  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <span className="label">Window</span>
        {RANGES.map((d) => (
          <button key={d} onClick={() => setDays(d)} className={cn("border px-2 py-1 text-[11px]", days === d ? "border-accent bg-accent-soft text-text" : "border-border text-text2 hover:bg-surfaceHover")}>{d}d</button>
        ))}
        <span className="ml-auto text-[11px] text-text3">active snapshot @{m.active_snapshot.replace(/^snap_/, "").slice(0, 7)}</span>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi icon={Activity} label="AI calls" value={fmtNum(t.calls)} sub={`${t.errors} errors`} />
        <Kpi icon={Cpu} label="Tokens" value={fmtNum(t.tokens)} sub="prompt + completion" />
        <Kpi icon={Coins} label="Est. cost" value={fmtCost(t.cost)} sub="local Ollama = $0" />
        <Kpi icon={Gauge} label="Latency p50 / p95" value={`${t.p50_latency} / ${t.p95_latency} ms`} sub={`avg ${t.avg_latency} ms`} />
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi icon={Database} label="Snapshots" value={String(m.snapshots)} />
        <Kpi icon={AlertTriangle} label="Findings (active)" value={`${m.findings}`} sub={`${m.critical} critical`} />
        <Kpi icon={GitBranch} label="Change decisions" value={String((m.decisions.auto_approve ?? 0) + (m.decisions.escalate ?? 0))} sub={`${m.decisions.auto_approve ?? 0} approved · ${m.decisions.escalate ?? 0} escalated`} />
        <Kpi icon={Rocket} label="Staged changes" value={String(Object.values(m.staging).reduce((a, b) => a + b, 0))} sub={`${m.staging.pushed ?? 0} pushed · ${m.staging.conflict ?? 0} conflict`} />
      </div>

      <div className="panel p-4">
        <div className="eyebrow mb-2.5">Daily activity</div>
        <TimeChart data={m.timeseries} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2 3xl:grid-cols-4">
        <div className="panel p-4">
          <div className="eyebrow mb-2.5">By capability</div>
          <Bars rows={m.by_capability.map((c) => ({ label: c.capability, value: c.calls, meta: `${fmtNum(c.tokens)} tok · ${fmtCost(c.cost)} · ${c.avg_latency}ms` }))} />
        </div>
        <div className="panel p-4">
          <div className="eyebrow mb-2.5">By provider / model</div>
          <Bars rows={m.by_provider.map((p) => ({ label: `${p.provider}:${p.model}`, value: p.calls, meta: `${fmtNum(p.tokens)} tok · ${fmtCost(p.cost)}` }))} />
        </div>
        <div className="panel p-4">
          <div className="eyebrow mb-2.5">Usage by role</div>
          <Bars rows={m.by_role.map((r) => ({ label: r.role, value: r.calls, meta: `${fmtNum(r.tokens)} tok` }))} />
        </div>
        <div className="panel p-4">
          <div className="eyebrow mb-2.5">Top tools</div>
          <Bars rows={m.top_tools.map((tt) => ({ label: tt.tool_name, value: tt.uses, meta: `${fmtNum(tt.tokens)} tok` }))} />
        </div>
      </div>
    </div>
  );
}

function Kpi({ icon: Icon, label, value, sub }: { icon: any; label: string; value: string; sub?: string }) {
  return (
    <div className="panel p-4">
      <div className="label flex items-center gap-1.5 text-[10px]"><Icon size={13} /> {label}</div>
      <div className="mt-1 text-[20px] font-bold tabular-nums">{value}</div>
      {sub && <div className="text-[11px] text-text3">{sub}</div>}
    </div>
  );
}

function Bars({ rows }: { rows: { label: string; value: number; meta?: string }[] }) {
  if (!rows.length) return <div className="text-[12px] text-text3">No data yet.</div>;
  const max = Math.max(...rows.map((r) => r.value), 1);
  return (
    <div className="space-y-1.5">
      {rows.map((r, i) => (
        <div key={i} className="text-[12px]">
          <div className="flex items-baseline justify-between gap-2">
            <span className="truncate font-mono text-[11px]">{r.label}</span>
            <span className="shrink-0 tabular-nums font-semibold">{r.value}</span>
          </div>
          <div className="mt-0.5 h-1.5 w-full bg-sunk">
            <div className="h-full bg-accent" style={{ width: `${(r.value / max) * 100}%` }} />
          </div>
          {r.meta && <div className="mt-0.5 text-[10px] text-text3">{r.meta}</div>}
        </div>
      ))}
    </div>
  );
}

function TimeChart({ data }: { data: { day: string; calls: number; tokens: number; cost: number }[] }) {
  if (!data.length) return <div className="text-[12px] text-text3">No activity in this window yet.</div>;
  const max = Math.max(...data.map((d) => d.calls), 1);
  return (
    <div className="flex items-end gap-1.5 overflow-x-auto pb-1" style={{ minHeight: 120 }}>
      {data.map((d) => (
        <div key={d.day} className="group flex min-w-[14px] flex-1 flex-col items-center justify-end" title={`${d.day}: ${d.calls} calls · ${fmtNum(d.tokens)} tok · ${fmtCost(d.cost)}`}>
          <div className="w-full bg-accent transition-opacity group-hover:opacity-80" style={{ height: `${Math.max((d.calls / max) * 100, 2)}px` }} />
          <div className="mt-1 w-full truncate text-center text-[9px] text-text3">{d.day.slice(5)}</div>
        </div>
      ))}
    </div>
  );
}
