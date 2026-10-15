"use client";

import { useState } from "react";
import { Check, Plug, X, Wand2, ArrowRight, Sparkles, RotateCw } from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import { cn, Spinner, Chip, Eyebrow, EmptyState, Button } from "./ui";
import { ErrorState } from "./ui/Feedback";
import { Prose } from "./Markdown";
import { AgentTerminal } from "@/components/agent/AgentTerminal";

/**
 * Samples that actually run.
 *
 * Three, not one, and each is a DIFFERENT mapping problem: a flat policy list
 * with short keys, a nested rule set with an object catalogue to dereference,
 * and a CSV-ish export whose action lives in a column called `permit`. A single
 * sample lets a reader watch the agent succeed once; three let them watch it
 * work, because the profile it proposes has to change.
 */
const SAMPLES: { key: string; label: string; hint: string; note: string; body: unknown }[] = [
  {
    key: "sdwan",
    label: "SD-WAN (flat list, short keys)",
    hint: "sd_wan",
    note: "Keys are abbreviated (src/dst/proto/act) and there is no object catalogue.",
    body: {
      vendor: "Viptela",
      policies: [
        { policy_id: "SDW-1", src: "branch-ny", dst: "datacenter-seg", proto: "tcp", port: 443, act: "allow" },
        { policy_id: "SDW-2", src: "branch-sf", dst: "datacenter-seg", proto: "tcp", port: 8443, act: "allow" },
        { policy_id: "SDW-3", src: "branch-ny", dst: "guest-wifi", proto: "udp", port: 53, act: "deny" },
      ],
    },
  },
  {
    key: "panorama",
    label: "Firewall with an object catalogue",
    hint: "pan_os",
    note: "Rules reference NAMED objects; the profile has to declare where the catalogue lives so the names dereference to addresses.",
    body: {
      vendor: "Acme-FW",
      address_objects: {
        "web-dmz": { kind: "subnet", cidr: "10.20.0.0/24", labels: ["dmz"] },
        "card-db": { kind: "host", cidr: "10.50.0.10/32", labels: ["pci", "customer-data"] },
      },
      security_rules: [
        { uuid: "R-100", from: "any", to: "card-db", app: "mssql", service: "tcp/1433", decision: "allow", position: 100 },
        { uuid: "R-101", from: "web-dmz", to: "card-db", app: "ssh", service: "tcp/22", decision: "allow", position: 101 },
      ],
    },
  },
  {
    key: "legacy",
    label: "Legacy export (boolean action)",
    hint: "legacy_acl",
    note: "The action is a BOOLEAN in a column called `permit`, which is the mapping a hand-written connector usually gets wrong.",
    body: {
      device: "core-acl-01",
      acl: [
        { seq: 10, source: "10.0.0.0/8", destination: "10.50.0.10", protocol: "tcp", dport: 3389, permit: true },
        { seq: 20, source: "0.0.0.0/0", destination: "10.50.0.10", protocol: "tcp", dport: 3389, permit: false },
      ],
    },
  },
];

const SAMPLE = JSON.stringify(SAMPLES[0].body, null, 2);

export function Connectors() {
  const [text, setText] = useState(SAMPLE);
  const [hint, setHint] = useState(SAMPLES[0].hint);
  const [picked, setPicked] = useState(SAMPLES[0].key);
  const [res, setRes] = useState<any>();
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<ApiError>();
  const [inputErr, setInputErr] = useState<string>();

  const propose = async () => {
    setErr(undefined); setInputErr(undefined); setRes(undefined);
    // Parse before the call so a typo in the pasted sample is reported as a
    // typo, not as an API failure — the old `String(e)` blurred the two.
    let sample: unknown;
    try { sample = JSON.parse(text); }
    catch (e) { setInputErr(e instanceof Error ? e.message : "The sample is not valid JSON."); return; }
    setLoading(true);
    try { setRes(await api.propose(sample, hint)); }
    catch (e) { setErr(asApiError(e)); }
    finally { setLoading(false); }
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
        <div className="mb-2 flex flex-wrap gap-1">
          {SAMPLES.map((sm) => (
            <button key={sm.key} type="button"
              onClick={() => {
                setPicked(sm.key);
                setHint(sm.hint);
                setText(JSON.stringify(sm.body, null, 2));
                setRes(undefined); setErr(undefined); setInputErr(undefined);
              }}
              className={cn("focusable h-7 cursor-pointer rounded-sm border px-2.5 text-[12px] font-medium transition-colors duration-100",
                picked === sm.key ? "border-transparent bg-ink text-on-ink"
                                  : "border-line bg-surface text-dim hover:bg-raise hover:text-fg")}>
              {sm.label}
            </button>
          ))}
        </div>
        <p className="mb-2 text-[11.5px] leading-[1.5] text-faint">
          {SAMPLES.find((sm) => sm.key === picked)?.note
            ?? "Edited sample. The agent reads whatever is in the box."}
        </p>
        <input value={hint} onChange={(e) => setHint(e.target.value)} placeholder="tool id (e.g. sd_wan)"
          className="field mb-2 w-full" />
        <textarea value={text}
          onChange={(e) => { setText(e.target.value); setPicked("custom"); }} rows={12}
          className="field h-auto w-full p-3 font-mono text-[12.5px] leading-[1.55]" />
        <Button variant="solid" tone="ink" onClick={propose} disabled={loading} className="mt-2 w-full">
          {loading ? <Spinner label="Authoring + validating…" /> : <><Wand2 size={15} /> Propose connector</>}
        </Button>
        {inputErr && (
          <div className="mt-2 text-[11.5px] text-err">That sample is not valid JSON: <span className="font-mono">{inputErr}</span></div>
        )}
        {err && <ErrorState resource="the proposed connector" error={err} onRetry={propose} className="mt-2" />}
      </div>

      <div className="space-y-3">
        {/* Rendered for BOTH outcomes and before either, because the trace is
            most useful when the answer is bad: it says whether a model
            answered, what it was asked, and which round the engine rejected. */}
        {res?.agent_trace ? (
          <AgentTerminal
            steps={res.agent_trace}
            usedAModel={res.used_a_model}
            what="Authoring a connector: propose a profile, normalize your sample with it, revise"
            defaultOpen
          />
        ) : null}
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
