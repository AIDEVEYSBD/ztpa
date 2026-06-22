"use client";

import { useMemo, useState } from "react";
import { ReactFlow, Background, Controls, Handle, Position, type Node, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Route, Globe, Server, Database, OctagonAlert, ArrowRight } from "lucide-react";
import type { Band, Finding, GraphData } from "@/lib/types";
import { Stat, ToolBadge, Skeleton, cn } from "./ui";
import { RuleRef } from "./RuleRef";

const SENSITIVE = ["pci", "customer-data", "crown-jewel", "phi"];
const NODE_CAP = 90; // above this, the full view caps + tells you (no silent truncation)

// Source tool is encoded as edge COLOUR (+ a legend) instead of repeated text
// labels, which overlap badly. Mid-tones chosen to read on both themes.
const TOOL_EDGE: Record<string, string> = {
  algosec: "#3b82f6", guardicore: "#8b5cf6", wiz: "#06b6d4", sd_wan: "#10b981", sd_lan: "#14b8a6",
};
const FALLBACK_EDGE = "var(--sev-low)";
function toolColor(tool: string) { return TOOL_EDGE[tool] ?? FALLBACK_EDGE; }

function isSensitive(tags: string[]) { return tags.some((t) => SENSITIVE.includes(t)); }
function tierOf(n: GraphData["nodes"][number]): number {
  if (n.node_id === "0.0.0.0/0") return 0;
  if (n.zone === "dmz") return 1;
  if (isSensitive(n.tags)) return 4;
  if (n.kind === "subnet") return 1;
  if (n.zone === "dev") return 1;
  if (n.node_id.includes("internal-app") || n.tags.includes("internal-app")) return 3;
  return 2;
}

function ZTNode({ data }: { data: any }) {
  return (
    <div style={{ opacity: data.dimmed ? 0.32 : 1 }}
      className={cn("border bg-surface px-2.5 py-2 min-w-[148px] transition-opacity",
      data.sensitive ? "border-sev-critical" : data.internet ? "border-dashed border-text3" : "border-border",
      data.onPath && "shadow-[0_0_0_2px_var(--accent)]")}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-border-strong" />
      <div className="flex items-center gap-1.5">
        {data.internet ? <Globe size={13} className="text-text2" /> : data.sensitive ? <Database size={13} className="text-sev-critical" /> : <Server size={13} className="text-text3" />}
        <span className="mono text-[12px] font-bold">{data.label}</span>
      </div>
      <div className="mono mt-1 text-[10px] text-text3 truncate">{data.sub}</div>
      {data.tool && (
        <div className="mt-1.5 inline-flex items-center gap-1 border border-border bg-sunk px-1 py-px text-[9px] text-text2">
          <span className="h-1 w-1 bg-accent" />{data.tool}
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-border-strong" />
    </div>
  );
}
const nodeTypes = { zt: ZTNode };

export function NetworkMap({ graph, findings = [], counts = {}, loading = false }:
  { graph?: GraphData; findings?: Finding[]; counts?: Record<string, number>; loading?: boolean }) {
  const [traced, setTraced] = useState(true);
  const [mode, setMode] = useState<"focus" | "full">("focus");

  const bands = useMemo(() => {
    const c: Record<Band, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => { c[f.severity_band]++; });
    return c;
  }, [findings]);

  const paths = useMemo(() => (graph?.cross_tool_paths ?? []) as any[], [graph]);
  const [sel, setSel] = useState(0);
  const selIdx = paths.length ? Math.min(sel, paths.length - 1) : 0;
  const { pathSet, pathPairs } = useMemo(() => {
    const p: string[] = paths[selIdx]?.path ?? [];
    return { pathSet: new Set(p), pathPairs: new Set(p.slice(0, -1).map((s, i) => `${s}->${p[i + 1]}`)) };
  }, [paths, selIdx]);
  const allPathNodes = useMemo(() => new Set<string>(paths.flatMap((p) => (p.path as string[]) ?? [])), [paths]);

  const { nodes, edges, shown, total } = useMemo(() => {
    if (!graph) return { nodes: [] as Node[], edges: [] as Edge[], shown: 0, total: 0 };
    const total = graph.nodes.length;
    const byId = new Map(graph.nodes.map((n) => [n.node_id, n]));
    const degree = new Map<string, number>();
    graph.edges.forEach((e) => {
      degree.set(e.src, (degree.get(e.src) ?? 0) + 1);
      degree.set(e.dst, (degree.get(e.dst) ?? 0) + 1);
    });

    // FOCUS = the risk-relevant subgraph: path + sensitive + internet + their neighbours.
    // This stays readable no matter how many total assets exist.
    let keep = new Set<string>();
    if (mode === "focus") {
      const seeds = new Set<string>([...allPathNodes, "0.0.0.0/0",
        ...graph.nodes.filter((n) => isSensitive(n.tags)).map((n) => n.node_id)]);
      seeds.forEach((s) => keep.add(s));
      graph.edges.forEach((e) => {
        if (seeds.has(e.src)) keep.add(e.dst);
        if (seeds.has(e.dst)) keep.add(e.src);
      });
    } else {
      const ranked = [...graph.nodes].sort((a, b) => (degree.get(b.node_id) ?? 0) - (degree.get(a.node_id) ?? 0));
      ranked.slice(0, NODE_CAP).forEach((n) => keep.add(n.node_id));
    }

    const tiers: Record<number, string[]> = {};
    [...keep].forEach((id) => { const n = byId.get(id); if (!n) return; (tiers[tierOf(n)] ??= []).push(id); });
    Object.values(tiers).forEach((a) => a.sort());

    const nodes: Node[] = [];
    Object.entries(tiers).forEach(([tStr, ids]) => {
      const tier = Number(tStr);
      const h = ids.length * 78;
      ids.forEach((id, i) => {
        const n = byId.get(id)!;
        nodes.push({
          id, type: "zt", position: { x: tier * 240, y: i * 78 - h / 2 + 260 },
          data: {
            label: n.label, sub: `${n.ip_set[0] ?? n.tags[0] ?? ""}${n.zone ? ` · ${n.zone}` : ""}`,
            sensitive: isSensitive(n.tags), internet: id === "0.0.0.0/0",
            onPath: traced && pathSet.has(id), dimmed: traced && !pathSet.has(id),
          },
        });
      });
    });
    const edges: Edge[] = graph.edges.filter((e) => keep.has(e.src) && keep.has(e.dst)).map((e) => {
      const hot = traced && pathPairs.has(`${e.src}->${e.dst}`);
      return {
        id: `${e.src}->${e.dst}`, source: e.src, target: e.dst, type: "smoothstep", animated: hot,
        data: { tools: e.tools.join(", "), services: e.services.join(", ") },
        style: hot
          ? { stroke: "var(--accent)", strokeWidth: 2.6, filter: "drop-shadow(0 0 5px var(--accent))" }
          : { stroke: toolColor(e.tools[0]), strokeWidth: 1.6, opacity: traced ? 0.18 : 0.85 },
      };
    });
    return { nodes, edges, shown: keep.size, total };
  }, [graph, mode, traced, pathSet, pathPairs, allPathNodes]);

  const hero = paths[selIdx];
  // Don't render data (or a definitive "nothing here") until the API has answered.
  const ready = !!graph && !loading;
  // legend reflects the tools actually present in this snapshot's edges
  const legendTools = useMemo(() => {
    const s = new Set<string>();
    (graph?.edges ?? []).forEach((e) => e.tools.forEach((t) => t && s.add(t)));
    return [...s].sort();
  }, [graph]);

  return (
    <div className="space-y-4">
      {/* severity summary */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {!ready ? (
          Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="panel space-y-2 p-4"><Skeleton className="h-7 w-12" /><Skeleton className="h-3 w-20" /><Skeleton className="h-2.5 w-28" /></div>
          ))
        ) : (
          <>
            <Stat band="critical" value={bands.critical} label="Critical" sub={`${counts.findings ?? findings.length} total findings`} />
            <Stat band="high" value={bands.high} label="High" sub="over-broad prod access" />
            <Stat band="medium" value={bands.medium} label="Medium" sub="hygiene & mgmt-plane" />
            <Stat band="low" value={bands.low} label="Low" sub="informational" />
          </>
        )}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_332px]">
        <section className="panel min-w-0">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3.5 py-2.5">
            <div className="flex items-center gap-2 text-[12.5px] font-bold"><Route size={15} className="text-text2" /> Unified reachability graph</div>
            <div className="flex items-center gap-2">
              <div className="flex border border-border text-[11px]">
                <button onClick={() => setMode("focus")} className={cn("px-2 py-1", mode === "focus" ? "bg-surfaceHover font-bold" : "text-text2")}>Focus</button>
                <button onClick={() => setMode("full")} className={cn("border-l border-border px-2 py-1", mode === "full" ? "bg-surfaceHover font-bold" : "text-text2")}>All</button>
              </div>
              <button onClick={() => setTraced((t) => !t)} className={cn(traced ? "btn-primary" : "btn-ghost", "!h-[30px]")}>
                <Route size={13} /> {traced ? "Tracing path" : "Trace path"}
              </button>
            </div>
          </div>

          {shown < total && (
            <div className="border-b border-border bg-sunk px-3.5 py-2 text-[11.5px] text-text2">
              Showing <b className="text-text">{shown}</b> of <b className="text-text">{total}</b> assets
              {mode === "focus" ? " (risk-relevant subgraph). " : ` (top ${NODE_CAP} most-connected). `}
              {mode === "focus"
                ? <button onClick={() => setMode("full")} className="text-text underline">Show more</button>
                : "At thousands of assets, scope by zone or focus on paths rather than rendering the full mesh."}
            </div>
          )}

          <div className="relative h-[420px] bg-sunk sm:h-[520px]">
            {!graph ? (
              <div className="grid h-full grid-cols-4 items-center gap-6 p-8">
                {[0, 1, 2, 3].map((col) => (
                  <div key={col} className="space-y-6" style={{ marginTop: col % 2 ? 40 : 0 }}>
                    {Array.from({ length: 3 - (col % 2) }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}
                  </div>
                ))}
              </div>
            ) : (
              <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2 }}
                proOptions={{ hideAttribution: true }} minZoom={0.1} nodesDraggable>
                <Background gap={26} size={1} color="var(--border)" />
                <Controls showInteractive={false} />
              </ReactFlow>
            )}
            {loading && graph && (
              <div className="absolute left-0 right-0 top-0 h-0.5 overflow-hidden">
                <span className="skeleton block h-full w-full" />
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-hair px-3.5 py-2.5 text-[11.5px] text-text2">
            <span className="text-text3">edge colour = source tool:</span>
            {legendTools.map((t) => (
              <span key={t} className="flex items-center gap-1.5"><span className="h-[3px] w-4" style={{ background: toolColor(t) }} />{t}</span>
            ))}
            <span className="flex items-center gap-1.5"><span className="h-[3px] w-4 bg-accent" />cross-tool path</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 border-[1.5px] border-sev-critical" />PCI / regulated</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 border border-dashed border-text3" />internet</span>
          </div>
        </section>

        {/* hop panel */}
        <section className="panel self-start">
          <div className="flex items-center justify-between border-b border-border px-3.5 py-2.5">
            <span className="text-[12.5px] font-bold">Cross-tool path{ready && paths.length > 1 ? `s · ${paths.length}` : ""}</span>
            {ready && hero && <span className="inline-flex items-center gap-1 text-[10.5px] font-bold uppercase tracking-[0.03em] text-sev-critical"><OctagonAlert size={12} /> Reachable</span>}
          </div>
          {ready && paths.length > 1 && (
            <div className="flex flex-wrap gap-1.5 border-b border-border p-2">
              {paths.map((p: any, i: number) => (
                <button key={i} onClick={() => setSel(i)}
                  className={cn("mono inline-flex items-center gap-1 border px-2 py-1 text-[11px]", i === selIdx ? "border-accent bg-accent-soft font-bold text-text" : "border-border text-text2")}>
                  <ArrowRight size={11} className="shrink-0" />{p.terminal}
                </button>
              ))}
            </div>
          )}
          {!ready ? (
            <div className="space-y-3 p-3.5">
              <Skeleton className="h-3 w-full" /><Skeleton className="h-3 w-4/5" />
              <div className="space-y-2 pt-1">
                {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
              <Skeleton className="h-14 w-full" />
            </div>
          ) : hero ? (
            <div className="p-3.5">
              <p className="mb-3.5 text-[12px] leading-relaxed text-text2">
                The internet reaches <span className="mono text-text">{hero.terminal}</span> in {(hero.hops ?? []).length} hops across <b className="text-text">{hero.tools?.length}</b> tools that no single console reveals.
              </p>
              <div className="space-y-0">
                {(hero.hops ?? []).map((h: any, i: number) => (
                  <div key={i}>
                    <div className="flex items-start gap-2.5">
                      <span className="mt-1 h-2.5 w-2.5 shrink-0 border-2 border-accent bg-accent" />
                      <span className="mono text-[12px] font-bold">{h.src_display}</span>
                    </div>
                    <div className="ml-[4px] border-l border-border py-1.5 pl-[14px]">
                      <div className="border border-border bg-surface2 px-2.5 py-1.5" style={{ borderLeft: "2px solid var(--sev-high)" }}>
                        <div className="text-[11px] text-text2">permits <span className="mono font-bold text-text">{h.service}</span></div>
                        <div className="mt-1.5 flex items-center gap-1.5"><ToolBadge tool={h.tool} /><span className="text-[10px] text-text3">rule</span><RuleRef refId={h.ref} /></div>
                      </div>
                    </div>
                    {i === (hero.hops ?? []).length - 1 && (
                      <div className="flex items-start gap-2.5">
                        <span className="mt-1 h-2.5 w-2.5 shrink-0 border-2 border-sev-critical bg-sev-critical" />
                        <span className="mono text-[12px] font-bold">{h.dst_display}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <div className="mt-2 border border-sev-critical-line bg-sev-critical-bg px-3 py-2.5">
                <div className="text-[11px] font-bold uppercase tracking-[0.04em] text-sev-critical">Verdict</div>
                <div className="mt-1 text-[12px] leading-relaxed">Cross-tool path exposes a {(hero.terminal_tags ?? []).join(", ")} host to the internet ({hero.boundary}). Break it at the cheapest hop.</div>
              </div>
            </div>
          ) : (
            <div className="p-10 text-center text-text3"><Route size={26} className="mx-auto mb-2" /><div className="text-[12.5px] text-text2">No cross-tool path in this snapshot.</div></div>
          )}
        </section>
      </div>
    </div>
  );
}
