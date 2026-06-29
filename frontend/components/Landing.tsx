"use client";

// ───────────────────────────────────────────────────────────────────────────
// Public marketing landing — implements "ZTPA Landing.dc.html" (Claude Design)
// in the AEGIS theme: electric-yellow accent on a warm near-black canvas,
// squared/flat/hairline structure, eyebrow titles, spectrum keylines. Forced to
// the dark palette (data-theme="dark") so the marketing page always reads as
// designed, regardless of the console theme. CTAs route to the real /login (or
// /console when already signed in).
// ───────────────────────────────────────────────────────────────────────────

import { useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { motion } from "framer-motion";
import {
  ArrowRight, ShieldCheck, Search, FileText, BarChart3, Code2, ClipboardCheck,
  Braces, GitMerge, Table2, Share2, Cloud, Ticket, Cpu, Sparkles, Check, X, Minus, RotateCw,
} from "lucide-react";
import { cn } from "@/lib/cn";

const EASE = [0.2, 0, 0, 1] as const;
const NAV = [
  { href: "#problem", label: "The problem" },
  { href: "#map", label: "One map" },
  { href: "#capabilities", label: "Capabilities" },
  { href: "#gate", label: "Change gate" },
];

const TOOL: Record<string, string> = { algosec: "#3b82f6", guardicore: "#8b5cf6", wiz: "#06b6d4" };

const PROBLEMS = [
  { icon: Table2, label: "AlgoSec", title: "Firewall rules", desc: "Sees the perimeter. Blind to cloud and east-west." },
  { icon: Share2, label: "Guardicore", title: "Segmentation", desc: "Sees east-west. Blind to the edge and the cloud." },
  { icon: Cloud, label: "Wiz", title: "Cloud posture", desc: "Sees the cloud. Blind to on-prem enforcement." },
  { icon: Ticket, label: "Tickets & tribal knowledge", title: "The rest", desc: "Lives in spreadsheets and people's heads." },
];

type Cap = { n: string; icon: typeof ShieldCheck; tag: string; title: string; desc: string };
const CAPS: Cap[] = [
  { n: "01", icon: ShieldCheck, tag: "agentic", title: "Change-request triage", desc: "Auto-approve vs escalate. Guardrailed and fail-closed." },
  { n: "02", icon: Search, tag: "agentic", title: "Ask your network", desc: "Plain English in, computed facts out. Tool-calling over the engine." },
  { n: "03", icon: FileText, tag: "language", title: "Plain-English findings", desc: "Every finding explained, grounded in the rule references." },
  { n: "04", icon: BarChart3, tag: "judgment", title: "Worst-first ranking", desc: "Root-cause grouping collapses noise into a handful of actions." },
  { n: "05", icon: Code2, tag: "re-simulated", title: "Fix-as-code", desc: "The model drafts; the engine re-simulates to prove it resolves." },
  { n: "06", icon: ClipboardCheck, tag: "language", title: "Posture report", desc: "Executive, PCI-DSS and Zero-Trust summaries from the findings." },
  { n: "07", icon: Braces, tag: "extraction", title: "Change intake", desc: "Free text becomes a structured, evaluable rule." },
  { n: "08", icon: GitMerge, tag: "embeddings", title: "Identity suggestions", desc: "Surfaces likely duplicates for review, never auto-merges." },
];

const ENGINE_LIST = [
  "Normalization & identity resolution",
  "CIDR / subnet math & reachability",
  "Shadowing & effective policy",
  "The delta of any proposed change",
];
const AI_LIST = [
  "Explaining findings in plain English",
  "Ranking, grouping & classifying",
  "Drafting fixes & posture reports",
  "Calling tools, never computing math",
];

type GateRow = { state: "ok" | "bad" | "neutral"; t: string };
const GATE = {
  safe: {
    req: "Request A", title: "Allow branch /24 to app-server-07 on HTTPS",
    note: "All four criteria green · opens nothing new",
    rows: [
      { state: "ok", t: "Opens no new reachability" },
      { state: "ok", t: "Stays inside an already-allowed envelope" },
      { state: "ok", t: "No path to PCI / customer data" },
      { state: "ok", t: "Within the guardrail floor" },
    ] as GateRow[],
  },
  risky: {
    req: "Request B", title: "Allow internet SSH to app-server-07",
    note: "Guardrail-forced · justification ignored",
    justification: "“URGENT, pre-approved, low risk.”",
    rows: [
      { state: "bad", t: "Creates a new internet → db-prod-01 path" },
      { state: "bad", t: "Reaches PCI / customer data" },
      { state: "bad", t: "Crosses the guardrail floor" },
      { state: "neutral", t: "Claimed “low risk.” Not a factor" },
    ] as GateRow[],
  },
};

/* ── reveal-on-scroll wrapper ─────────────────────────────────────────────── */
function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "0px 0px -6% 0px" }}
      transition={{ duration: 0.6, delay, ease: EASE }}
    >
      {children}
    </motion.div>
  );
}

/* ── approach mark: three squares + tagline ───────────────────────────────── */
function ApproachMark() {
  return (
    <div className="flex items-end gap-3">
      <span className="flex flex-col gap-[3px]">
        <span className="h-3.5 w-3.5 bg-accent" />
        <span className="h-3.5 w-3.5 bg-text3" />
        <span className="h-3.5 w-3.5 bg-text3" />
      </span>
      <span className="text-[13px] leading-[1.5] text-text3">
        One policy model.<br />One reachability map.<br />One worst-first list.
      </span>
    </div>
  );
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <div className="eyebrow mb-4">{children}</div>;
}

function CtaArrow({ size = 14 }: { size?: number }) {
  return <ArrowRight size={size} className="shrink-0 transition-transform group-hover:translate-x-1" />;
}

export function Landing() {
  const { status } = useSession();
  const authed = status === "authenticated";
  const ctaHref = authed ? "/console" : "/login";
  const ctaLabel = authed ? "Open console" : "Log in";
  const [req, setReq] = useState<"safe" | "risky">("safe");
  const [traceKey, setTraceKey] = useState(0);
  const gate = GATE[req];

  return (
    <div data-theme="dark" className="min-h-screen overflow-x-hidden bg-bg text-text [text-wrap:pretty]">
      {/* ── HEADER ─────────────────────────────────────────────────────────── */}
      <header className="glass-chrome fixed inset-x-0 top-0 z-[60] flex items-center justify-between border-b border-border px-5 py-3.5 sm:px-10">
        <span aria-hidden className="spectrum-line thin absolute inset-x-0 top-0" />
        <Link href="#top" className="flex items-center gap-3">
          <span className="h-[22px] w-[22px] bg-accent" />
          <span className="flex flex-col leading-none">
            <span className="text-[18px] font-bold tracking-[-0.02em]">ZTPA</span>
            <span className="mt-[3px] text-[11px] tracking-[0.02em] text-text3">ZeroTrust Policy Advisor</span>
          </span>
        </Link>
        <nav className="flex items-center gap-7">
          <div className="hidden items-center gap-7 md:flex">
            {NAV.map((n) => (
              <a key={n.href} href={n.href} className="text-[14px] text-text2 transition-colors hover:text-text">{n.label}</a>
            ))}
          </div>
          <Link href={ctaHref} className="btn-primary group !h-auto !px-5 !py-2.5 !text-[14px]">
            {ctaLabel}<CtaArrow />
          </Link>
        </nav>
      </header>

      {/* ── HERO ───────────────────────────────────────────────────────────── */}
      <section id="top" className="bg-aurora relative flex min-h-screen flex-col justify-center overflow-hidden px-5 pb-20 pt-36 sm:px-10">
        {/* ambient network overlay (thin yellow lines + nodes) */}
        <svg viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" aria-hidden className="pointer-events-none absolute inset-0 h-full w-full">
          <g stroke="var(--accent)" strokeWidth="1" fill="none">
            <path d="M120 200 L420 320 L760 180 L1080 360 L1340 240" style={{ animation: "ztpa-pulse 7s ease-in-out infinite" }} />
            <path d="M80 640 L380 540 L700 700 L1010 520 L1360 660" style={{ animation: "ztpa-pulse 9s ease-in-out infinite 1.5s" }} />
            <path d="M420 320 L380 540" style={{ animation: "ztpa-pulse 8s ease-in-out infinite .8s" }} />
            <path d="M760 180 L700 700" style={{ animation: "ztpa-pulse 10s ease-in-out infinite 2.2s" }} />
            <path d="M1080 360 L1010 520" style={{ animation: "ztpa-pulse 8.5s ease-in-out infinite 1.1s" }} />
          </g>
          <g fill="var(--accent)">
            {[[416, 316, 0], [756, 176, 1], [1076, 356, 2], [376, 536, 1.6], [1006, 516, 0.5]].map(([x, y, d], i) => (
              <rect key={i} x={x} y={y} width="8" height="8" style={{ animation: `ztpa-dot 5s ease-in-out infinite ${d}s` }} />
            ))}
          </g>
        </svg>
        <div className="pointer-events-none absolute inset-0" style={{ background: "linear-gradient(180deg, rgba(11,11,15,0.35) 0%, rgba(11,11,15,0.72) 60%, var(--bg) 100%)" }} />

        <div className="relative mx-auto w-full max-w-[1200px] 3xl:max-w-[1360px]">
          <Reveal className="mb-7 flex items-center gap-3.5">
            <span className="flex gap-1">
              <span className="h-[9px] w-[9px] bg-accent" />
              <span className="h-[9px] w-[9px] bg-text3" />
              <span className="h-[9px] w-[9px] bg-text3" />
            </span>
            <span className="text-[13px] uppercase tracking-[0.04em] text-text2">ZeroTrust Policy Advisor</span>
          </Reveal>
          <Reveal delay={0.05}>
            <h1 className="m-0 max-w-[1040px] text-[40px] font-bold leading-[1.04] tracking-[-0.03em] sm:text-[56px] lg:text-[72px]">
              What&apos;s the one risk that crosses every tool, the one <span className="text-accent">no single console</span> can see?
            </h1>
          </Reveal>
          <Reveal delay={0.12}>
            <p className="mt-7 max-w-[740px] text-[18px] leading-[1.5] text-text2 sm:text-[21px]">
              ZTPA unifies every network-policy tool you run (firewall, segmentation and cloud) into one policy
              model, one reachability map, and one worst-first to-do list, then explains, prioritizes and gates every
              change with an agentic advisory layer.
            </p>
          </Reveal>
          <Reveal delay={0.18} className="mt-10 flex flex-wrap items-center gap-4">
            <Link href={ctaHref} className="btn-primary group !h-auto !px-6 !py-[15px] !text-[16px]">{ctaLabel}<CtaArrow size={16} /></Link>
            <a href="#map" className="btn-ghost !h-auto !px-6 !py-[15px] !text-[16px]">Trace the cross-tool path</a>
          </Reveal>
        </div>

        <div className="absolute bottom-9 left-5 hidden sm:left-10 sm:block"><ApproachMark /></div>
        <div className="absolute bottom-10 right-6 hidden flex-col items-center gap-2 sm:flex">
          <span className="relative h-8 w-5 rounded-full border-[1.5px] border-text3/60">
            <span className="absolute left-1/2 top-[7px] h-[7px] w-[3px] -translate-x-1/2 bg-accent" style={{ animation: "ztpa-mouse 1.8s ease-in-out infinite" }} />
          </span>
        </div>
      </section>

      {/* ── PROBLEM ────────────────────────────────────────────────────────── */}
      <section id="problem" className="scroll-mt-20 px-5 py-28 sm:px-10">
        <div className="mx-auto max-w-[1200px] 3xl:max-w-[1360px]">
          <Reveal><Eyebrow>The pain</Eyebrow></Reveal>
          <Reveal delay={0.05}>
            <h2 className="m-0 max-w-[900px] text-[34px] font-bold leading-[1.06] tracking-[-0.03em] sm:text-[44px] lg:text-[52px]">
              Four consoles. Four mental models. <span className="text-accent">One blind spot.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mb-14 mt-6 max-w-[760px] text-[18px] leading-[1.5] text-text2 sm:text-[19px]">
              Every tool sees its own slice. The one risk that matters most, an attack path that crosses all of them,
              is invisible to every single tool you own.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 gap-px border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {PROBLEMS.map((p, i) => {
              const Icon = p.icon;
              return (
                <Reveal key={p.label} delay={i * 0.06} className="bg-bg p-7">
                  <Icon size={26} strokeWidth={1.6} className="text-text3" />
                  <div className="mt-4 text-[13px] uppercase tracking-[0.03em] text-text3">{p.label}</div>
                  <div className="mt-3.5 text-[22px] font-bold tracking-[-0.02em]">{p.title}</div>
                  <div className="mt-2.5 text-[14px] leading-[1.5] text-text3">{p.desc}</div>
                </Reveal>
              );
            })}
          </div>
          <Reveal delay={0.1} className="mt-9 flex items-center gap-4">
            <span className="spectrum-line warm h-px w-[60px] flex-none" />
            <span className="font-serif text-[22px] tracking-[-0.01em] text-text sm:text-[24px]">The risk lives in the gaps between them.</span>
          </Reveal>
        </div>
      </section>

      {/* ── MONEY SHOT / ONE MAP ───────────────────────────────────────────── */}
      <section id="map" className="scroll-mt-20 border-t border-border bg-surface px-5 py-28 sm:px-10">
        <div className="mx-auto max-w-[1200px] 3xl:max-w-[1360px]">
          <div className="mb-12 flex flex-wrap items-end justify-between gap-6">
            <div>
              <Reveal delay={0.05}>
                <h2 className="m-0 max-w-[820px] text-[34px] font-bold leading-[1.06] tracking-[-0.03em] sm:text-[44px] lg:text-[52px]">
                  One map. One model. <span className="text-accent">One path you couldn&apos;t see before.</span>
                </h2>
              </Reveal>
            </div>
            <button onClick={() => setTraceKey((k) => k + 1)} className="btn-ghost !h-auto !px-5 !py-3 !text-[15px]">
              <RotateCw size={15} /> Trace cross-tool path
            </button>
          </div>

          <Reveal className="grid grid-cols-1 gap-0 border border-border bg-bg p-5 sm:p-10 lg:grid-cols-[200px_1fr]">
            {/* sources + normalize */}
            <div className="flex flex-col justify-center gap-3.5 border-b border-border pb-6 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-9">
              <div className="mb-1 text-[11px] uppercase tracking-[0.05em] text-text3">Simulated exports</div>
              {([["AlgoSec", TOOL.algosec], ["Guardicore", TOOL.guardicore], ["Wiz", TOOL.wiz]] as const).map(([name, color]) => (
                <div key={name} className="flex items-center gap-2.5 border border-border px-3 py-2.5">
                  <span className="h-2 w-2 shrink-0" style={{ background: color }} />
                  <span className="text-[14px] font-bold">{name}</span>
                </div>
              ))}
              <div className="flex items-center gap-2.5 border border-dashed border-borderStrong px-3 py-2.5 text-text3">
                <span className="h-2 w-2 shrink-0 border border-text3" />
                <span className="text-[14px] font-bold">+ any source</span>
              </div>
              <div className="mt-2 border border-border px-3 py-2.5 text-[12px] leading-[1.45] text-text2">Normalize · resolve identity · build graph</div>
            </div>

            {/* graph */}
            <div className="relative pt-6 lg:pl-9 lg:pt-0">
              <div className="mb-2.5 text-[11px] uppercase tracking-[0.05em] text-text3">Unified reachability graph</div>
              <div className="relative w-full" style={{ aspectRatio: "1000 / 410" }}>
                <svg viewBox="0 0 1000 360" preserveAspectRatio="none" className="absolute inset-0 h-full w-full">
                  <motion.path
                    key={traceKey}
                    d="M70 250 L290 120 L510 250 L730 120 L940 230" fill="none"
                    stroke="var(--accent)" strokeWidth="2.5" strokeLinejoin="round"
                    initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
                    transition={{ duration: 2, ease: EASE }}
                  />
                  <path d="M70 250 L290 120 L510 250 L730 120 L940 230" fill="none" stroke="#FFFFFF" strokeWidth="2.5"
                    strokeDasharray="3 13" strokeLinejoin="round" opacity="0.85" className="animate-ztpa-flow" />
                </svg>
                {/* edge labels */}
                {([["18%", "algosec", "Wiz", TOOL.wiz], ["40%", "wiz", "Wiz", TOOL.wiz], ["62%", "gc", "Guardicore", TOOL.guardicore], ["83.5%", "as", "AlgoSec", TOOL.algosec]] as const).map(([left, k, label, color]) => (
                  <span key={k} className="absolute top-[51%] -translate-x-1/2 -translate-y-1/2 border border-border bg-bg px-1.5 py-0.5 text-[11px] font-bold" style={{ left, color }}>{label}</span>
                ))}
                {/* nodes */}
                <DiagramNode left="7%" top="69.4%" label="Internet" color="var(--text-3)" below />
                <DiagramNode left="29%" top="33.3%" label="lb-public-01" color="var(--accent)" />
                <DiagramNode left="51%" top="69.4%" label="app-server-07" color="var(--accent)" sub="= appsrv-07 · merged" below />
                <DiagramNode left="73%" top="33.3%" label="internal-app" color="var(--accent)" />
                <DiagramNode left="94%" top="63.9%" label="db-prod-01" color="var(--sev-critical)" sub="PCI · customer data" below critical />
              </div>
            </div>
          </Reveal>

          <Reveal className="mt-7 grid grid-cols-1 gap-px border border-border bg-border md:grid-cols-2">
            <div className="bg-bg p-7">
              <div className="text-[13px] font-bold uppercase tracking-[0.02em] text-sev-critical">Critical · force-flagged</div>
              <div className="mt-3 text-[16px] leading-[1.55] text-text2">
                A public load balancer reaches the customer database through a chain that crosses three tools:{" "}
                <span className="text-text">Internet → lb-public-01 → app-server-07 → internal-app → db-prod-01</span>. Nothing you own would have shown you this.
              </div>
            </div>
            <div className="bg-bg p-7">
              <div className="text-[13px] font-bold uppercase tracking-[0.02em] text-accent">Why it&apos;s even visible</div>
              <div className="mt-3 text-[16px] leading-[1.55] text-text2">
                Wiz calls that server <span className="text-text">appsrv-07</span>; the identity layer merged it with AlgoSec&apos;s{" "}
                <span className="text-text">app-server-07</span> by attribute. That deterministic merge is the only reason the path connects at all.
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── CAPABILITIES ───────────────────────────────────────────────────── */}
      <section id="capabilities" className="scroll-mt-20 px-5 py-28 sm:px-10">
        <div className="mx-auto max-w-[1200px] 3xl:max-w-[1360px]">
          <Reveal><Eyebrow>The advisory layer</Eyebrow></Reveal>
          <Reveal delay={0.05}>
            <h2 className="m-0 max-w-[880px] text-[34px] font-bold leading-[1.06] tracking-[-0.03em] sm:text-[44px] lg:text-[52px]">
              Eight ways the AI <span className="text-accent">advises</span>, never computes.
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mb-14 mt-6 max-w-[760px] text-[18px] leading-[1.5] text-text2 sm:text-[19px]">
              The engine owns every fact and every number. The model only explains, ranks, classifies and drafts,
              grounded in the engine&apos;s structured results.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 gap-px border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {CAPS.map((c, i) => {
              const Icon = c.icon;
              const strong = c.tag === "agentic" || c.tag === "re-simulated";
              return (
                <Reveal key={c.n} delay={(i % 4) * 0.05} className="flex min-h-[184px] flex-col bg-bg p-6">
                  <div className="flex items-start justify-between">
                    <span className="inline-flex items-center gap-2.5 text-accent">
                      <Icon size={22} strokeWidth={1.6} />
                      <span className="text-[13px] font-bold text-text3">{c.n}</span>
                    </span>
                    <span className={cn("border px-1.5 py-0.5 text-[11px]", strong ? "border-accent text-accent" : "border-border text-text2")}>{c.tag}</span>
                  </div>
                  <div className="mt-[18px] text-[18px] font-bold leading-[1.25] tracking-[-0.02em]">{c.title}</div>
                  <div className="mt-2.5 text-[13px] leading-[1.5] text-text3">{c.desc}</div>
                </Reveal>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── CHANGE GATE ────────────────────────────────────────────────────── */}
      <section id="gate" className="scroll-mt-20 border-t border-border bg-surface px-5 py-28 sm:px-10">
        <div className="mx-auto max-w-[1200px] 3xl:max-w-[1360px]">
          <Reveal><Eyebrow>The change gate</Eyebrow></Reveal>
          <Reveal delay={0.05}>
            <h2 className="m-0 max-w-[880px] text-[34px] font-bold leading-[1.06] tracking-[-0.03em] sm:text-[44px] lg:text-[52px]">
              It judges the <span className="text-accent">computed delta</span>, not the requester&apos;s words.
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mb-12 mt-6 max-w-[760px] text-[18px] leading-[1.5] text-text2 sm:text-[19px]">
              Pick a change request. The engine simulates it and the gate decides. The model can only auto-approve inside
              an already-safe envelope. It can never raise the risk tolerance, even under prompt injection.
            </p>
          </Reveal>

          <Reveal className="max-w-[880px]">
            <div className="flex border border-border">
              {(["safe", "risky"] as const).map((k, i) => {
                const active = req === k;
                return (
                  <button key={k} onClick={() => setReq(k)}
                    className={cn("flex-1 border-b-2 px-5 py-4 text-left transition-colors", i === 0 && "border-r border-r-border",
                      active ? "border-b-accent text-text" : "border-b-transparent text-text3 hover:text-text2")}>
                    <span className="block text-[12px] uppercase tracking-[0.03em] text-text3">{GATE[k].req}</span>
                    <span className="mt-1.5 block text-[15px] font-bold tracking-[-0.02em]">{GATE[k].title}</span>
                  </button>
                );
              })}
            </div>

            <motion.div key={req} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3, ease: EASE }}
              className="border border-t-0 border-border bg-bg p-8">
              <div className="flex flex-wrap items-center gap-3.5">
                <span className={cn("inline-flex items-center gap-2 px-4 py-2 text-[14px] font-bold tracking-[0.02em]",
                  req === "safe" ? "bg-ok text-bg" : "bg-sev-critical text-white")}>
                  {req === "safe" ? "AUTO-APPROVE" : "ESCALATE"}
                </span>
                <span className="text-[14px] text-text3">{gate.note}</span>
              </div>

              {"justification" in gate && gate.justification && (
                <div className="mt-[22px] border-l-2 border-sev-critical py-1 pl-4">
                  <div className="text-[12px] uppercase tracking-[0.03em] text-text3">Requester&apos;s justification</div>
                  <div className="mt-1.5 text-[15px] italic text-text2">{gate.justification}</div>
                </div>
              )}

              <div className="mt-6 grid grid-cols-1 gap-x-10 gap-y-3.5 sm:grid-cols-2">
                {gate.rows.map((r, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <span className={cn("mt-px shrink-0", r.state === "ok" ? "text-ok" : r.state === "bad" ? "text-sev-critical" : "text-text3")}>
                      {r.state === "ok" ? <Check size={18} strokeWidth={2.2} /> : r.state === "bad" ? <X size={18} strokeWidth={2.2} /> : <Minus size={18} strokeWidth={2.2} />}
                    </span>
                    <span className="text-[15px] text-text2">{r.t}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          </Reveal>
        </div>
      </section>

      {/* ── FACTS vs JUDGMENT ──────────────────────────────────────────────── */}
      <section className="px-5 py-28 sm:px-10">
        <div className="mx-auto max-w-[1200px] 3xl:max-w-[1360px]">
          <Reveal className="mx-auto max-w-[840px] text-center">
            <p className="m-0 font-serif text-[28px] leading-[1.25] tracking-[-0.01em] text-text sm:text-[38px]">
              <span className="text-accent">“</span>The engine owns the facts. The AI owns the words and the judgment.<span className="text-accent">”</span>
            </p>
          </Reveal>
          <div className="mt-14 grid grid-cols-1 gap-px border border-border bg-border md:grid-cols-2">
            <FactsColumn icon={Cpu} eyebrow="Deterministic engine" title="Facts & math" items={ENGINE_LIST} iconColor="text-accent" />
            <FactsColumn icon={Sparkles} eyebrow="AI advisory layer" title="Language & judgment" items={AI_LIST} iconColor="text-info" />
          </div>
          <Reveal>
            <p className="mx-auto mt-9 max-w-[760px] text-center text-[17px] leading-[1.55] text-text3">
              It advises today, and it earns the right to act gradually. Every decision logged and auditable.
            </p>
          </Reveal>
        </div>
      </section>

      {/* ── CTA ────────────────────────────────────────────────────────────── */}
      <section className="bg-accent px-5 py-24 text-accent-ink sm:px-10">
        <div className="mx-auto flex max-w-[1200px] 3xl:max-w-[1360px] flex-wrap items-center justify-between gap-10">
          <Reveal>
            <h2 className="m-0 max-w-[680px] text-[34px] font-bold leading-[1.04] tracking-[-0.03em] sm:text-[44px] lg:text-[50px]">
              See the path no console could show you.
            </h2>
            <p className="mt-5 max-w-[560px] text-[18px] leading-[1.5] text-[#2e2e38] sm:text-[19px]">
              {authed ? "Jump back into" : "Log in to walk"} the unified map, the ranked to-do list, and the change gate.
            </p>
          </Reveal>
          <Reveal delay={0.08}>
            <Link href={ctaHref}
              className="group inline-flex flex-none items-center gap-3 bg-accent-ink px-9 py-[18px] text-[18px] font-bold tracking-[-0.02em] text-accent transition-colors hover:bg-elevated">
              {ctaLabel}<CtaArrow size={16} />
            </Link>
          </Reveal>
        </div>
      </section>

      {/* ── FOOTER ─────────────────────────────────────────────────────────── */}
      <footer className="border-t border-border px-5 py-14 sm:px-10">
        <div className="mx-auto flex max-w-[1200px] 3xl:max-w-[1360px] flex-wrap items-end justify-between gap-8">
          <ApproachMark />
          <div className="flex flex-col gap-2 sm:text-right">
            <div className="flex items-center gap-2.5 sm:justify-end">
              <span className="h-[18px] w-[18px] bg-accent" />
              <span className="text-[16px] font-bold">ZTPA · ZeroTrust Policy Advisor</span>
            </div>
            <span className="text-[12px] text-text3">Private and confidential. Simulated exports representative of each tool, not a live integration.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

/* ── diagram node ─────────────────────────────────────────────────────────── */
function DiagramNode({ left, top, label, color, sub, below, critical }: {
  left: string; top: string; label: string; color: string; sub?: string; below?: boolean; critical?: boolean;
}) {
  return (
    <div className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-[7px]" style={{ left, top, flexDirection: below ? "column" : "column-reverse" }}>
      <span className={cn(critical ? "h-[18px] w-[18px]" : "h-3.5 w-3.5")} style={{ background: color, animation: critical ? "ztpa-crit 2s ease-out infinite" : undefined }} />
      <span className="whitespace-nowrap bg-bg px-1.5 py-0.5 text-[12px] font-bold" style={{ color: critical ? "var(--sev-critical)" : undefined }}>{label}</span>
      {sub && <span className="whitespace-nowrap bg-bg px-1.5 py-px text-[10px] text-text3">{sub}</span>}
    </div>
  );
}

/* ── facts-vs-judgment column ─────────────────────────────────────────────── */
function FactsColumn({ icon: Icon, eyebrow, title, items, iconColor }: {
  icon: typeof Cpu; eyebrow: string; title: string; items: string[]; iconColor: string;
}) {
  return (
    <Reveal className="bg-bg p-10">
      <div className="flex items-center gap-3">
        <span className={cn("inline-flex", iconColor)}><Icon size={20} strokeWidth={1.6} /></span>
        <span className="text-[13px] uppercase tracking-[0.05em] text-text3">{eyebrow}</span>
      </div>
      <div className="mt-[18px] text-[28px] font-bold tracking-[-0.02em]">{title}</div>
      <div className="mt-6 flex flex-col gap-3.5">
        {items.map((it) => (
          <div key={it} className="flex items-start gap-3 border-t border-hair pt-3.5">
            <ArrowRight size={13} strokeWidth={2} className="mt-1 shrink-0 text-accent" />
            <span className="text-[15px] text-text2">{it}</span>
          </div>
        ))}
      </div>
    </Reveal>
  );
}
