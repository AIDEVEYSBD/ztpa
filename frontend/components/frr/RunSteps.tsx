"use client";

/**
 * The five review agents of one run, with live status.
 *
 * Polls GET /api/frr/runs/{id} every 1.5s while the run is queued or running,
 * and stops on succeeded / failed, on a read error, on unmount, and after
 * twenty minutes (with a "keep checking" control) — a run whose worker died
 * would otherwise be polled for as long as the tab stays open.
 */

import { useEffect, useRef, useState } from "react";
import { Bot, CheckCircle2, Circle, XCircle } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import { FRR_AGENTS, type FrrRun, type RunStep } from "@/lib/frrTypes";
import { Banner, Button, Chip, Panel, Skeleton, cn } from "../ui";
import { Spinner } from "../ui/Button";
import { ErrorState } from "../ui/Feedback";
import { when } from "./bits";

const POLL_MS = 1500;
const MAX_POLLS = 800; // 20 minutes

const AGENT_LABEL: Record<string, { label: string; does: string }> = {
  orchestrator: { label: "Orchestrator", does: "runs the steps in order and records each one" },
  intake_parser: { label: "Intake parser", does: "reads the parsed export" },
  policy_checker: { label: "Policy checker", does: "the deterministic rule-risk checks" },
  impact_assessor: { label: "Impact assessor", does: "availability impact per item, grounded in the knowledge base" },
  package_drafter: { label: "Package drafter", does: "drafts the change package and its summary" },
};

type AgentState = "waiting" | "running" | "done" | "failed";

function agentState(agent: string, steps: RunStep[], run: FrrRun): { state: AgentState; last?: RunStep } {
  const mine = steps.filter((s) => s.agent === agent);
  const last = mine[mine.length - 1];
  if (last) {
    if (last.status === "refused" || last.status === "failed" || last.status === "error") return { state: "failed", last };
    if (agent === "orchestrator") {
      if (last.status === "finished") return { state: "done", last };
      return { state: run.status === "failed" ? "failed" : "running", last };
    }
    return { state: "done", last };
  }
  if (run.status !== "running") return { state: "waiting" };
  // The first agent with no step yet is the one working now.
  const firstMissing = FRR_AGENTS.slice(1).find((a) => !steps.some((s) => s.agent === a));
  return { state: firstMissing === agent ? "running" : "waiting" };
}

function detailOf(step: RunStep | undefined): string {
  if (!step) return "";
  return Object.entries(step)
    .filter(([k]) => !["agent", "status", "at"].includes(k))
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

export function RunSteps({ runId, onFinished }: {
  runId: string;
  /** Called once when the run reaches a terminal state. */
  onFinished: (run: FrrRun) => void;
}) {
  const [run, setRun] = useState<FrrRun>();
  const [err, setErr] = useState<ApiError>();
  const [polls, setPolls] = useState(0);
  const reported = useRef<string | null>(null);
  const finishedRef = useRef(onFinished);
  finishedRef.current = onFinished;

  const terminal = run?.status === "succeeded" || run?.status === "failed";
  const capped = polls >= MAX_POLLS;

  useEffect(() => {
    if (terminal || err || capped) return;
    let live = true;
    const t = setTimeout(() => {
      frr.run(runId)
        .then((r) => { if (live) { setRun(r); setPolls((n) => n + 1); } })
        .catch((e) => { if (live) setErr(asApiError(e)); });
    }, polls === 0 ? 0 : POLL_MS);
    return () => { live = false; clearTimeout(t); };
  }, [runId, polls, terminal, err, capped]);

  useEffect(() => {
    if (run && (run.status === "succeeded" || run.status === "failed") && reported.current !== run.run_id) {
      reported.current = run.run_id;
      finishedRef.current(run);
    }
  }, [run]);

  if (err && !run) return <ErrorState resource="the review run" error={err} onRetry={() => setErr(undefined)} />;
  if (!run) return <Skeleton className="h-[220px] w-full rounded-lg" />;

  const refusal = run.steps.find((s) => s.status === "refused" || typeof s.reason === "string");

  return (
    <Panel title="Review agents" icon={<Bot size={13} />}
      caption={`Run ${run.run_id.slice(0, 8)} · started ${when(run.created_at)}${run.created_by ? ` by ${run.created_by}` : ""}`}
      actions={
        run.status === "succeeded" ? <Chip variant="ok" dot>succeeded</Chip>
          : run.status === "failed" ? <Chip variant="danger" dot>failed</Chip>
            : <Chip variant="info"><Spinner size={10} />{run.status}</Chip>
      }>
      <ol className="space-y-2">
        {FRR_AGENTS.map((a, i) => {
          const { state, last } = agentState(a, run.steps, run);
          const meta = AGENT_LABEL[a];
          return (
            <li key={a} className="flex gap-3">
              <span className={cn("mt-0.5 shrink-0",
                state === "done" ? "text-ok" : state === "failed" ? "text-err" : state === "running" ? "text-run" : "text-ghost")}>
                {state === "done" ? <CheckCircle2 size={15} /> : state === "failed" ? <XCircle size={15} />
                  : state === "running" ? <Spinner size={15} /> : <Circle size={15} />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-[12.5px] font-medium">{i + 1}. {meta.label}</span>
                  <span className="text-[11px] text-faint">{meta.does}</span>
                  <span className="ml-auto text-[11px] text-faint">{state}{last ? ` · ${when(last.at)}` : ""}</span>
                </div>
                {last && detailOf(last) && (
                  <div className={cn("mt-0.5 font-mono text-[10.5px] break-words", state === "failed" ? "text-err" : "text-dim")}>{detailOf(last)}</div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      {run.status === "failed" && (
        <Banner tone="err" className="mt-3" title="The run did not produce a package">
          {typeof refusal?.reason === "string" ? refusal.reason : "No step recorded a reason. The job log on the backend has the failure."}
        </Banner>
      )}
      {err && (
        <Banner tone="err" className="mt-3" title="Lost contact with the run"
          actions={<Button size="sm" variant="solid" tone="ink" onClick={() => setErr(undefined)}>Retry</Button>}>
          {err.detail}
        </Banner>
      )}
      {capped && !terminal && (
        <Banner tone="warn" className="mt-3" title="Still running after twenty minutes"
          actions={<Button size="sm" variant="solid" tone="ink" onClick={() => setPolls(1)}>Keep checking</Button>}>
          Automatic checks have stopped. If the run never finishes, the job worker may not be running.
        </Banner>
      )}
    </Panel>
  );
}
