"use client";

import { Fragment, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { FeedbackRow, RegisterEntry, RuleCoverage } from "@/lib/frrTypes";
import { Chip, SeverityPill, Table, THead, Th, Td } from "../ui";
import { EvidenceList, checkLabel, when } from "./bits";
import { CheckFeedback } from "./CheckFeedback";

/** A hit count the export did not carry is unknown — never 0, which would read
 *  as "this rule is never used" and invite its removal. */
function Hits({ n }: { n: number | null }) {
  return n == null ? <span className="text-faint italic">unknown</span> : <span className="tnum font-mono">{n.toLocaleString()}</span>;
}

function Expiry({ at }: { at: string | null }) {
  if (!at) return <span className="text-faint">none set</span>;
  const d = new Date(at);
  const past = !Number.isNaN(d.getTime()) && d.getTime() < Date.now();
  return <span className={past ? "font-medium text-err" : "text-dim"}>{when(at)}</span>;
}

function List({ xs }: { xs: string[] }) {
  if (!xs?.length) return <span className="text-faint">—</span>;
  return <span className="font-mono break-words">{xs.join(", ")}</span>;
}

function Coverage({ c }: { c: RuleCoverage }) {
  const rest = c.covered - c.covered_grants.length;
  return (
    <div className="mt-2 rounded-md border border-line px-2.5 py-2">
      <div className="text-[11px] font-medium text-dim">
        Partly covered above: {c.covered} of {c.grants} grants never match on {c.gateway}
        {c.partly_covered_on > 1 ? <span className="text-faint"> (and {c.partly_covered_on - 1} more gateways)</span> : null}
      </div>
      <ul className="mt-1 space-y-0.5 text-[11.5px]">
        {c.covered_grants.map((g, i) => (
          <li key={i} className="font-mono break-words text-fg">
            {g.source} → {g.destination} {g.service}
            <span className="text-faint"> · {g.by_action === "deny" ? "denied" : "allowed"} by rule {g.by_rule ?? "?"}</span>
          </li>
        ))}
        {rest > 0 && <li className="text-faint">+{rest} more</li>}
      </ul>
      <p className="mt-1 text-[11px] text-faint">The rest of the rule still matches traffic. Grants allowed above are redundant here; grants denied above are blocked before reaching it.</p>
    </div>
  );
}

export function RegisterTable({ items, feedback }: {
  items: RegisterEntry[];
  /** When present, the caller may review checks: rule uid -> check -> their verdict. */
  feedback?: { exportId: string; mine: Record<string, Record<string, FeedbackRow>>; onChange: (r: FeedbackRow) => void };
}) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setOpen((s) => {
    const n = new Set(s);
    if (n.has(id)) n.delete(id); else n.add(id);
    return n;
  });

  return (
    <div className="overflow-hidden rounded-lg border border-line bg-surface elev-1">
      <Table minWidth={980}>
        <THead>
          <Th className="w-8"><span className="sr-only">Expand</span></Th>
          <Th>#</Th>
          <Th>Rule</Th>
          <Th>Layer · section</Th>
          <Th>Action</Th>
          <Th>Worst band</Th>
          <Th>Checks</Th>
          <Th>Hits</Th>
          <Th>Last hit</Th>
          <Th>Expires</Th>
        </THead>
        <tbody>
          {items.map((e) => {
            const isOpen = open.has(e.rule_uid);
            return (
              <Fragment key={e.rule_uid}>
                <tr className="cursor-pointer border-b border-line hover:bg-raise/40" onClick={() => toggle(e.rule_uid)}>
                  <Td>
                    <button type="button" aria-expanded={isOpen} aria-label={`${isOpen ? "Collapse" : "Expand"} rule ${e.number ?? e.rule_uid}`}
                      onClick={(ev) => { ev.stopPropagation(); toggle(e.rule_uid); }}
                      className="focusable cursor-pointer text-faint hover:text-fg">
                      {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    </button>
                  </Td>
                  <Td className="tnum font-mono text-dim">{e.number ?? "—"}</Td>
                  <Td>
                    <div className="font-medium text-fg">{e.name || <span className="text-faint italic">unnamed</span>}</div>
                    {!e.enabled && <Chip variant="neutral" className="mt-0.5">disabled</Chip>}
                  </Td>
                  <Td className="text-dim">{e.layer}{e.section ? <span className="text-faint"> · {e.section}</span> : null}</Td>
                  <Td className="font-mono text-dim">{e.action}</Td>
                  <Td>{e.band ? <SeverityPill band={e.band} severity={e.severity ?? undefined} /> : <span className="text-faint">—</span>}</Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {e.checks.length === 0
                        ? <span className="text-faint">none</span>
                        : e.checks.map((c) => <Chip key={c.finding_id || c.check} variant={c.band === "critical" ? "danger" : c.band === "high" ? "warn" : "neutral"}>{checkLabel(c.check)}</Chip>)}
                    </div>
                  </Td>
                  <Td><Hits n={e.hit_count} /></Td>
                  <Td className="whitespace-nowrap">{e.last_hit ? when(e.last_hit) : <span className="text-faint italic">unknown</span>}</Td>
                  <Td className="whitespace-nowrap"><Expiry at={e.expires_at} /></Td>
                </tr>
                {isOpen && (
                  <tr className="border-b border-line bg-raise/25">
                    <td colSpan={10} className="px-4 py-3">
                      <div className="grid gap-3 xl:grid-cols-[1fr_1.4fr]">
                        <div className="space-y-1.5 text-[11.5px]">
                          <div><span className="text-faint">Sources </span><List xs={e.sources} /></div>
                          <div><span className="text-faint">Destinations </span><List xs={e.destinations} /></div>
                          <div><span className="text-faint">Services </span><List xs={e.services} /></div>
                          <div className="font-mono text-[10.5px] text-faint">uid {e.rule_uid}</div>
                          {e.nat && e.nat.length > 0 && (
                            <div className="mt-2 rounded-md border border-line px-2.5 py-2">
                              <div className="text-[11px] font-medium text-dim">Reaches NAT</div>
                              <ul className="mt-1 space-y-0.5 text-[11.5px]">
                                {e.nat.map((n, i) => (
                                  <li key={i} className="font-mono break-words text-fg">
                                    NAT {n.nat_rule ?? "?"} ({n.method}): {n.original_destination.join(", ")} → {n.translated_destination.join(", ")}
                                    {n.more_nat_rules ? <span className="text-faint"> · +{n.more_nat_rules} more</span> : null}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {e.coverage && <Coverage c={e.coverage} />}
                          {e.limitations.length > 0 && (
                            <div className="mt-2 rounded-md border border-warn-line bg-warn-bg px-2.5 py-2">
                              <div className="text-[11px] font-medium text-warn">Limitations for this rule</div>
                              <ul className="mt-1 space-y-0.5 text-[11.5px] text-fg">
                                {e.limitations.map((l, i) => <li key={i}>· {l}</li>)}
                              </ul>
                            </div>
                          )}
                        </div>
                        <div className="space-y-2.5">
                          {e.checks.length === 0 && <p className="text-[11.5px] text-faint">No check fired on this rule.</p>}
                          {e.checks.map((c) => (
                            <div key={c.finding_id || c.check} className="rounded-md border border-line bg-surface p-2.5">
                              <div className="mb-1.5 flex flex-wrap items-center gap-2">
                                <SeverityPill band={c.band} severity={c.severity} />
                                <span className="text-[12px] font-medium">{c.title}</span>
                                <Chip variant="neutral" mono>{c.check}</Chip>
                              </div>
                              <EvidenceList evidence={c.evidence} />
                            </div>
                          ))}
                          {feedback && (
                            <CheckFeedback exportId={feedback.exportId} entry={e}
                              mine={feedback.mine[e.rule_uid] ?? {}} onChange={feedback.onChange} />
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </Table>
    </div>
  );
}
