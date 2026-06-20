"use client";

import { useState } from "react";
import { Check, Plug, X, Wand2, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { cn, Spinner } from "./ui";
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
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><Plug size={16} className="text-text2" /> Bring your own source</div>
        <p className="mb-3 text-xs text-muted">
          Paste a sample export from any tool. The model proposes a declarative <b>SourceProfile</b> (config, not code);
          the engine validates it by actually normalizing your sample. A human approves before it&apos;s registered -
          the model authors validated config, never opaque runtime code.
        </p>
        <input value={hint} onChange={(e) => setHint(e.target.value)} placeholder="tool id (e.g. sd_wan)"
          className="field mb-2 w-full" />
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={12}
          className="w-full border border-border bg-[var(--surface-sunk)] p-3 font-mono text-xs text-text outline-none focus:border-borderStrong" />
        <button onClick={propose} disabled={loading} className="btn-primary mt-2 w-full">
          {loading ? <Spinner label="Authoring + validating…" /> : <><Wand2 size={15} /> Propose connector</>}
        </button>
        {err && <div className="mt-2 text-xs text-sev-critical">{err}</div>}
      </div>

      <div className="space-y-3">
        {!res ? (
          <div className="panel grid h-full min-h-[200px] place-items-center text-sm text-muted">Proposed profile appears here.</div>
        ) : res.ok ? (
          <>
            <div className={cn("panel flex items-center gap-2 p-3 text-sm",
              res.validation?.valid ? "border-sev-low-line" : "border-sev-high-line")}>
              {res.validation?.valid ? <Check className="text-sev-low" size={18} /> : <X className="text-sev-high" size={18} />}
              <span className="font-semibold">{res.validation?.valid ? "Validated against your sample" : "Needs review"}</span>
              <span className="ml-auto text-xs text-muted">{res.validation?.records} rows · {res.validation?.entities} entities</span>
            </div>
            <div className="panel p-3">
              <div className="mb-1 text-xs font-semibold text-muted">Proposed SourceProfile (config)</div>
              <pre className="overflow-x-auto rounded-lg bg-ink/[0.04] p-3 font-mono text-[11px]">{JSON.stringify(res.profile, null, 2)}</pre>
            </div>
            <div className="panel p-3">
              <div className="mb-2 text-xs font-semibold text-muted">Normalized sample rows (deterministic)</div>
              {(res.validation?.sample_rows ?? []).map((r: any, i: number) => (
                <div key={i} className="flex flex-wrap items-center gap-2 border-b py-1 text-xs last:border-0">
                  <span className="mono break-all">{r.source}</span><ArrowRight size={11} className="shrink-0 text-muted" />
                  <span className="mono break-all">{r.destination}</span>
                  <span className="ml-auto rounded bg-surfaceHover px-1.5 py-0.5 font-mono text-[10px]">{r.service}</span>
                </div>
              ))}
              <button className="btn-primary mt-3 w-full text-xs" disabled>Approve &amp; register connector (demo)</button>
            </div>
            <div className="text-[10px] text-muted">via {res.by}</div>
          </>
        ) : (
          <div className="panel border-sev-high-line p-3 text-sm"><Prose className="!text-sm">{res.reason ?? "Could not parse this sample."}</Prose></div>
        )}
      </div>
    </div>
  );
}
