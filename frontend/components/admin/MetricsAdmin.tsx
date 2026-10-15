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

  if (err) return <div className="relative overflow-hidden rounded-lg border border-line bg-surface p-3.5 pl-4 text-[13px] elev-1"><span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-err" />Could not load metrics.</div>;
  if (!m) return <div className="space-y-3"><div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="panel p-4"><Skeleton className="h-3 w-20" /><Skeleton className="mt-2 h-6 w-24" /></div>)}</div></div>;

  const t = m.totals;
  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <span className="mr-0.5 text-[11px] font-medium text-faint">Window</span>
        <div className="inline-flex items-center gap-px rounded-sm border border-line bg-canvas p-px">
          {RANGES.map((d) => (
            <button key={d} onClick={() => setDays(d)} aria-pressed={days === d}
              className={cn("focusable cursor-pointer rounded-[3px] px-1.5 py-0.5 font-mono text-[10px] transition-colors duration-100",
                days === d ? "bg-ink text-on-ink" : "text-faint hover:text-dim")}>{d}d</button>
          ))}
        </div>
        <span className="ml-auto font-mono text-[10.5px] text-faint">active snapshot @{m.active_snapshot.replace(/^snap_/, "").slice(0, 7)}</span>
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
    <div className="flex flex-col gap-2 rounded-lg border border-line bg-surface p-4 elev-1">
      <div className="flex items-center gap-1.5 text-[11px] font-medium text-faint"><Icon size={13} /> {label}</div>
      <div className="tnum text-[28px] leading-none font-semibold tracking-[-0.025em]">{value}</div>
      {sub && <div className="text-[11.5px] text-faint">{sub}</div>}
    </div>
  );
}

function Bars({ rows }: { rows: { label: string; value: number; meta?: string }[] }) {
  if (!rows.length) return <div className="text-[12.5px] text-dim">No data yet.</div>;
  const max = Math.max(...rows.map((r) => r.value), 1);
  return (
    <div className="space-y-1.5">
      {rows.map((r, i) => (
        <div key={i} className="text-[12px]">
          <div className="flex items-baseline justify-between gap-2">
            <span className="truncate font-mono text-[11px] text-mist">{r.label}</span>
            <span className="tnum shrink-0 font-medium">{r.value}</span>
          </div>
          <div className="mt-0.5 h-1.5 w-full overflow-hidden rounded-[2px] bg-sunken">
            <div className="h-full rounded-[2px]" style={{ width: `${(r.value / max) * 100}%`, background: "var(--t-c2)" }} />
          </div>
          {r.meta && <div className="mt-0.5 text-[10px] text-ghost">{r.meta}</div>}
        </div>
      ))}
    </div>
  );
}

function TimeChart({ data }: { data: { day: string; calls: number; tokens: number; cost: number }[] }) {
  if (!data.length) return <div className="text-[12.5px] text-dim">No activity in this window yet.</div>;
  const max = Math.max(...data.map((d) => d.calls), 1);
  return (
    <div className="flex items-end gap-1.5 overflow-x-auto pb-1" style={{ minHeight: 120 }}>
      {data.map((d) => (
        <div key={d.day} className="group flex min-w-[14px] flex-1 flex-col items-center justify-end" title={`${d.day}: ${d.calls} calls · ${fmtNum(d.tokens)} tok · ${fmtCost(d.cost)}`}>
          <div className="w-full rounded-[1px] transition-opacity duration-100 group-hover:opacity-80" style={{ height: `${Math.max((d.calls / max) * 100, 2)}px`, background: "var(--t-c2)" }} />
          <div className="tnum mt-1 w-full truncate text-center font-mono text-[9.5px] text-faint">{d.day.slice(5)}</div>
        </div>
      ))}
    </div>
  );
}
