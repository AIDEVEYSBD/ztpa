"use client";

import { useState } from "react";
import { Check, Plug, X, Wand2, ArrowRight, Sparkles, RotateCw } from "lucide-react";
import { api } from "@/lib/api";
import { cn, Spinner, Chip, Eyebrow, EmptyState } from "./ui";
import { Prose } from "./Markdown";

const SAMPLE = JSON.stringify({
  vendor: "Viptela",
  policies: [
    { policy_id: "SDW-1", src: "branch-ny", dst: "datacenter-seg", proto: "tcp", port: 443, act: "allow" },
    { policy_id: "SDW-2", src: "branch-sf", dst: "datacenter-seg", proto: "tcp", port: 8443, act: "allow" },
  ],
}, null, 2);

export function Connectors() {
  const [text, setText] = useState(SAMPLE);
  const [hint, setHint] = useState("sd_wan");
  const [res, setRes] = useState<any>();
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string>();

  const propose = async () => {
    setErr(undefined); setRes(undefined); setLoading(true);
    try { setRes(await api.propose(JSON.parse(text), hint)); }
    catch (e) { setErr(String(e)); } finally { setLoading(false); }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="panel p-4">
        <Eyebrow className="mb-3"><Plug size={13} /> Bring your own source</Eyebrow>
        <p className="mb-3 text-xs text-text2">
          Paste a sample export from any tool. The model proposes a declarative <b>SourceProfile</b> (config, not code);
          the engine validates it by actually normalizing your sample. A human approves before it&apos;s registered -
          the model authors validated config, never opaque runtime code.
        </p>
        <input value={hint} onChange={(e) => setHint(e.target.value)} placeholder="tool id (e.g. sd_wan)"
          className="field mb-2 w-full" />
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={12}
          className="field h-auto w-full p-3 font-mono text-xs leading-relaxed" />
        <button onClick={propose} disabled={loading} className="btn-primary mt-2 w-full">
          {loading ? <Spinner label="Authoring + validating…" /> : <><Wand2 size={15} /> Propose connector</>}
        </button>
        {err && <div className="mt-2 text-xs text-sev-critical">{err}</div>}
      </div>

      <div className="space-y-3">
        {!res ? (
          <div className="panel grid h-full min-h-[200px] place-items-center">
            <EmptyState icon={Sparkles} title="Proposed profile appears here" sub="Author a connector to validate it against your sample." />
          </div>
        ) : res.ok ? (
          <>
            <div className={cn("panel flex flex-wrap items-center gap-2 p-3 text-sm",
              res.validation?.valid ? "border-sev-low-line" : "border-sev-high-line")}>
              {res.validation?.valid ? <Check className="text-sev-low" size={18} /> : <X className="text-sev-high" size={18} />}
              <span className="font-semibold">{res.validation?.valid ? "Validated against your sample" : "Needs review"}</span>
              <span className="ml-auto text-xs text-text2">{res.validation?.records} rows · {res.validation?.entities} entities</span>
              {(res.validation?.unmapped ?? []).length > 0 && (
                <span className="w-full text-[11px] text-sev-high">Unmapped: {res.validation.unmapped.join(", ")} — the field name(s) mapped for these are wrong.</span>
              )}
            </div>

            <AuthoringTrace trace={res.trace} attempts={res.attempts} />

            <div className="panel p-3">
              <Eyebrow className="mb-2">Proposed SourceProfile (config)</Eyebrow>
              <pre className="sunk overflow-x-auto p-3 font-mono text-[11px]">{JSON.stringify(res.profile, null, 2)}</pre>
            </div>
            <div className="panel p-3">
              <Eyebrow className="mb-2">Normalized sample rows (deterministic)</Eyebrow>
              {(res.validation?.sample_rows ?? []).map((r: any, i: number) => (
                <div key={i} className="flex flex-wrap items-center gap-2 border-b border-hair py-1 text-xs last:border-0">
                  <span className="mono break-all">{r.source}</span><ArrowRight size={11} className="shrink-0 text-text3" />
                  <span className="mono break-all">{r.destination}</span>
                  <Chip mono className="ml-auto">{r.service}</Chip>
                </div>
              ))}
              <button className="btn-primary mt-3 w-full text-xs" disabled>Approve &amp; register connector (demo)</button>
            </div>
            <div className="text-[10px] text-text3">via {res.by}</div>
          </>
        ) : (
          <div className="panel border-sev-high-line p-3 text-sm"><Prose className="!text-sm">{res.reason ?? "Could not parse this sample."}</Prose></div>
        )}
      </div>
    </div>
  );
}

/** The self-correcting loop: each round the model proposed a profile, the engine
 *  tried to normalize the sample, and the concrete failure drove the next revision.
 *  Only shown when the agent actually iterated. */
function AuthoringTrace({ trace, attempts }: { trace?: any[]; attempts?: number }) {
  if (!trace || trace.length < 2) return null;
  const verdict = (t: any): { label: string; cls: string } => {
    if (t.error) return { label: t.error.includes("schema") ? "schema-invalid" : "error", cls: "border-sev-high-line bg-sev-high-bg text-sev-high" };
    const v = t.validation ?? {};
    if (v.valid) return { label: "validated", cls: "border-sev-low-line bg-sev-low-bg text-sev-low" };
    if (!v.records) return { label: "0 records", cls: "border-sev-high-line bg-sev-high-bg text-sev-high" };
    if ((v.unmapped ?? []).length) return { label: `unmapped: ${v.unmapped.join(", ")}`, cls: "border-sev-medium-line bg-sev-medium-bg text-sev-medium" };
    return { label: `${v.records} rows`, cls: "border-border text-text2" };
  };
  return (
    <div className="panel p-3">
      <Eyebrow className="mb-2 flex items-center gap-1.5"><RotateCw size={12} /> How the connector was derived — {attempts ?? trace.length} attempt{(attempts ?? 0) !== 1 ? "s" : ""}</Eyebrow>
      <ol className="space-y-1.5 border-l border-border pl-3">
        {trace.map((t, i) => {
          const v = verdict(t);
          const p = t.profile ?? {};
          return (
            <li key={i} className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="mono text-text3">{t.attempt}.</span>
              <span className="mono text-text2">rules_path=<b>{p.rules_path ?? "?"}</b></span>
              <span className={cn("chip ml-auto text-[10px]", v.cls)}>{v.label}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
