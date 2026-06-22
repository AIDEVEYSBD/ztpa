"use client";

import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Send, Terminal, User, Bot } from "lucide-react";
import { api } from "@/lib/api";
import type { AskResult } from "@/lib/types";
import { Spinner, SkeletonText, Skeleton, cn } from "./ui";
import { Prose } from "./Markdown";

// Fallback only if the snapshot-derived suggestions endpoint is unavailable.
const FALLBACK_SUGGESTED = [
  "What can reach our regulated data?",
  "Which findings are forced-critical, and why?",
  "Summarize the riskiest exposure in this snapshot.",
];

type Turn = { q: string; a?: AskResult; loading?: boolean };

export function Assistant() {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [suggested, setSuggested] = useState<string[]>();
  const busyRef = useRef(false);          // synchronous guard against spam-clicks
  const scrollRef = useRef<HTMLDivElement>(null);

  // Suggestions are derived from THIS snapshot's facts (assets, paths, findings).
  useEffect(() => { api.askSuggestions().then((r) => setSuggested(r.suggestions?.length ? r.suggestions : FALLBACK_SUGGESTED)).catch(() => setSuggested(FALLBACK_SUGGESTED)); }, []);

  // Auto-scroll to the newest activity whenever a turn is added or answered.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [turns]);

  const ask = async (q: string) => {
    if (busyRef.current || !q.trim()) return;   // ignore clicks while a request is in flight
    busyRef.current = true; setBusy(true);
    setInput("");
    const idx = turns.length;
    setTurns((t) => [...t, { q, loading: true }]);
    try {
      const a = await api.ask(q);
      setTurns((t) => t.map((x, i) => (i === idx ? { q, a } : x)));
    } catch {
      setTurns((t) => t.map((x, i) => (i === idx ? { q, a: { answer: "Request failed.", by: "error", trace: [] } } : x)));
    } finally {
      busyRef.current = false; setBusy(false);
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
      <div className="panel flex h-[560px] flex-col">
        <div ref={scrollRef} className="zt-scroll flex-1 space-y-4 overflow-y-auto p-4">
          {turns.length === 0 && (
            <div className="grid h-full place-items-center text-center text-sm text-muted">
              <div>
                <Bot className="mx-auto mb-2 text-text2" size={28} />
                Ask plain-English questions about your network.<br />The agent calls deterministic engine tools, so every answer is grounded in computed facts.
              </div>
            </div>
          )}
          {turns.map((t, i) => (
            <div key={i} className="space-y-2">
              <div className="flex items-start gap-2">
                <User size={16} className="mt-0.5 text-muted" />
                <div className="text-sm font-medium">{t.q}</div>
              </div>
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-start gap-2">
                <Bot size={16} className="mt-0.5 text-text2" />
                <div className="min-w-0 flex-1">
                  {t.loading ? (
                    <div className="space-y-2">
                      <Spinner label="Calling deterministic tools…" />
                      <SkeletonText lines={3} className="pt-1" />
                    </div>
                  ) : (
                    <>
                      <Prose>{t.a?.answer ?? ""}</Prose>
                      {!!t.a?.trace?.length && (
                        <div className="mt-2 rounded-lg border bg-surfaceHover p-2">
                          <div className="mb-1 flex items-center gap-1 text-[10px] font-semibold text-muted"><Terminal size={11} /> TOOL TRACE </div>
                          {t.a.trace.map((tr, j) => (
                            <div key={j} className="font-mono text-[10px] text-muted">
                              <span className="text-text2">{tr.tool}</span>({Object.values(tr.args ?? {}).join(", ")})
                            </div>
                          ))}
                        </div>
                      )}
                      {t.a?.by && <div className="mt-1 text-[10px] text-muted">via {t.a.by}</div>}
                    </>
                  )}
                </div>
              </motion.div>
            </div>
          ))}
        </div>
        <form onSubmit={(e) => { e.preventDefault(); ask(input); }} className="flex gap-2 border-t border-border p-3">
          <input value={input} onChange={(e) => setInput(e.target.value)} disabled={busy}
            placeholder={busy ? "Waiting for the current answer…" : "Ask about reachability, exposure, or a hypothetical change…"}
            className="field flex-1 disabled:opacity-60" />
          <button className="btn-primary" type="submit" disabled={busy || !input.trim()}><Send size={15} /></button>
        </form>
      </div>
      <div className="space-y-2">
        <div className="text-xs font-semibold text-muted">Try asking <span className="font-normal text-text3">· from this snapshot</span></div>
        {suggested === undefined
          ? Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)
          : suggested.map((s) => (
            <button key={s} onClick={() => ask(s)} disabled={busy}
              className={cn("panel w-full p-3 text-left text-xs", busy ? "cursor-not-allowed opacity-50" : "hover:bg-surfaceHover")}>{s}</button>
          ))}
        {busy && <div className="px-1 pt-1 text-[11px] text-text3">Answering… one question at a time so the trace stays readable.</div>}
      </div>
    </div>
  );
}
