"use client";

import { useEffect, useState } from "react";
import { ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { ToolBadge, Chip, Eyebrow, Skeleton, cn } from "./ui";
import { RuleRef } from "./RuleRef";
import { useFilterSort, SearchBox, SortSelect } from "@/lib/tableTools";

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

export function IngestInspector({ snapshot }: { snapshot?: string }) {
  const [d, setD] = useState<{ active_scenario: string; sources: any[]; resolved_objects: any[]; canonical_rules: any[] }>();
  useEffect(() => { api.ingest(snapshot).then(setD).catch(() => {}); }, [snapshot]);

  const rules = d?.canonical_rules ?? [];
  const rt = useFilterSort(rules, {
    search: (r) => `${side(r.src_value)} ${side(r.dst_value)} ${svc(r)} ${r.action} ${r.source_tool} ${r.raw_rule_id} ${(r.tags ?? []).join(" ")}`,
    sorts: {
      tool: (r) => r.source_tool, action: (r) => r.action,
      service: (r) => svc(r), order: (r) => r.rule_order ?? 0, ref: (r) => r.raw_rule_id,
    },
    initialSort: "tool",
  });

  if (!d) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-4 w-3/4 max-w-xl" />
        {[3, 6, 4].map((rows, p) => (
          <div key={p} className="panel">
            <div className="panel-head"><Skeleton className="h-3.5 w-40" /></div>
            <div className="divide-y divide-hair">
              {Array.from({ length: rows }).map((_, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-2.5">
                  <Skeleton className="h-4 w-20 shrink-0" />
                  <Skeleton className="h-3 w-40" />
                  <Skeleton className="ml-auto h-3 w-16 shrink-0" />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <p className="text-[13px] text-text2">
        Exactly what the simulated connectors produced for the current snapshot
        (<span className="mono">{d.active_scenario}</span>), before any analysis. This is the canonical model the whole engine runs on.
      </p>

      <div className="panel">
        <div className="panel-head"><Eyebrow>Sources ({d.sources.length})</Eyebrow></div>
        <div className="divide-y divide-hair">
          {d.sources.map((s) => (
            <div key={s.tool} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
              <ToolBadge tool={s.tool} />
              <span className="mono text-text2">{s.device}</span>
              <span className="ml-auto text-[11px] text-text3">simulated export</span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="flex flex-wrap items-center gap-2 border-b border-hair px-4 py-2.5">
          <Eyebrow>Canonical rules ({rt.rows.length}{rt.rows.length !== rules.length ? ` of ${rules.length}` : ""})</Eyebrow>
          <span className="hidden text-[11px] text-text3 sm:inline">normalized · set-valued · provenance kept</span>
          <div className="ml-auto flex items-center gap-2">
            <SearchBox value={rt.q} onChange={rt.setQ} placeholder="Filter rules…" />
            <SortSelect options={[{ key: "tool", label: "tool" }, { key: "action", label: "action" }, { key: "service", label: "service" }, { key: "order", label: "order" }, { key: "ref", label: "rule id" }]}
              sortKey={rt.sortKey} setSortKey={rt.setSortKey} dir={rt.dir} toggleDir={rt.toggleDir} />
          </div>
        </div>
        <div className="zt-scroll max-h-[440px] divide-y divide-hair overflow-y-auto">
          {rt.rows.map((r) => (
            <div key={r.rule_uid} className="flex flex-wrap items-center gap-2 px-4 py-2 text-[12px]">
              <span className={cn("h-1.5 w-1.5 shrink-0", r.action === "allow" ? "bg-ok" : "bg-sev-critical")} />
              <span className="mono break-all">{side(r.src_value)}</span>
              <ArrowRight size={11} className="shrink-0 text-text3" />
              <span className="mono break-all">{side(r.dst_value)}</span>
              <Chip mono>{svc(r)}</Chip>
              <Chip variant={r.action === "allow" ? "ok" : "danger"} mono>{r.action}</Chip>
              <span className="ml-auto flex items-center gap-1.5"><ToolBadge tool={r.source_tool} /><RuleRef refId={r.raw_rule_id} snapshot={snapshot} /></span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><Eyebrow>Resolved objects ({d.resolved_objects.length})</Eyebrow></div>
        <div className="zt-scroll max-h-[320px] divide-y divide-hair overflow-y-auto">
          {d.resolved_objects.map((o, i) => (
            <div key={i} className="flex items-center gap-2 px-4 py-2 text-[12px]">
              <ToolBadge tool={o.source_tool} />
              <span className="mono font-bold">{o.object_name}</span>
              <span className="text-[10px] text-text3">{o.object_kind}</span>
              <span className="mono ml-auto max-w-[45%] truncate text-[11px] text-text2">{JSON.stringify(o.resolved)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
