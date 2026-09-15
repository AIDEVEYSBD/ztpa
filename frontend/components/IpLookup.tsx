"use client";

/**
 * THE ADDRESS DRILL-DOWN — "what policies are associated with this IP".
 *
 * ────────────────────────────────────────────────────────────────────────────
 * MOUNTING. Render `<IpLookup />` ONCE, inside the console shell (it needs to
 * sit under `PanelHealthProvider` so its failure panels reach the degraded
 * banner). It renders nothing until opened. Everything else talks to it through
 * the store:
 *
 *     const ip = useIpLookup();
 *     ip.open("10.30.7.7");            // from any address chip, anywhere
 *     openIpLookup("10.30.0.0/16", "contains");   // outside React, too
 *     <AddressChip address={row.ip} /> // the ready-made chip
 *
 * and from the keyboard, ⌘K / Ctrl-K, registered globally by this component.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE FOUR STATES ARE FOUR DIFFERENT SENTENCES, and keeping them apart is most
 * of the point of this file:
 *
 *   loading      skeletons in the shape of the answer. Nothing asserted.
 *   failed       <ErrorState/> — names the resource, the status and the remedy,
 *                and registers with PanelHealth so the banner above cannot
 *                claim the panels below it are fine. No count is rendered.
 *   nothing found  a 200 that says this address is in no rule and in no
 *                inventory record. A RESULT. Worded as one.
 *   populated    the four sections, in order.
 *
 * "This address matched no rule" and "the lookup failed" never share markup,
 * never share wording, and never share a colour.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Command, Crosshair, History, Search, X } from "lucide-react";
import { Chip, Eyebrow, Overlay, ScrollArea, Skeleton, cn } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import {
  DEFAULT_IP_MODE,
  IP_MODES,
  IP_MODE_HINT,
  IP_MODE_LABEL,
  blockSize,
  parseAddress,
  type IpMode,
  type ParsedAddress,
} from "./ip/addr";
import { useIpLookup, type IpQuery } from "./ip/store";
import { useAddressLookup, useFindingIndex, useSourceIndex } from "./ip/data";
import { AddressIdentity } from "./ip/AddressIdentity";
import { PolicyMatches } from "./ip/PolicyMatches";
import { AddressFindings } from "./ip/AddressFindings";
import { EffectiveAccess } from "./ip/EffectiveAccess";
import { MonoChip } from "./ip/atoms";

export { useIpLookup, openIpLookup, closeIpLookup, setIpLookupQuery } from "./ip/store";
export type { IpLookupController, IpQuery } from "./ip/store";
export { parseAddress, type IpMode } from "./ip/addr";

// ───────────────────────────────────────────────────────────────────────────
// The chip any screen can drop next to an address.
// ───────────────────────────────────────────────────────────────────────────

/** A clickable address. Opens the drill-down on click; falls back to plain mono
 *  text when the string is not an address, because a chip that opens a drawer
 *  that immediately reports "not an address" is worse than no chip. */
export function AddressChip({
  address,
  mode,
  className,
}: {
  address: string;
  mode?: IpMode;
  className?: string;
}) {
  const ip = useIpLookup();
  const parsed = parseAddress(address);
  if (!parsed.ok) return <span className={cn("mono break-all text-[11.5px]", className)}>{address}</span>;
  return (
    <button
      type="button"
      onClick={() => ip.open(address, mode)}
      title={`Look up what policy reaches ${address}`}
      className={cn(
        "mono inline-flex items-center gap-1 border border-border bg-sunk px-1.5 py-0.5 text-[11px] leading-[1.45] text-text2",
        "transition-colors hover:border-accent hover:bg-accent-soft hover:text-accent-fg",
        className,
      )}
    >
      <Crosshair size={10} className="shrink-0" />
      <span className="break-all">{address}</span>
    </button>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// The query bar — the command-palette input, in the drawer's header.
// ───────────────────────────────────────────────────────────────────────────

function ModeSelector({ mode, onChange }: { mode: IpMode; onChange: (m: IpMode) => void }) {
  return (
    <div className="flex flex-wrap items-stretch border border-border" role="group" aria-label="Containment mode">
      {IP_MODES.map((m) => (
        <button
          key={m}
          type="button"
          onClick={() => onChange(m)}
          title={IP_MODE_HINT[m]}
          aria-pressed={m === mode}
          className={cn(
            "mono border-r border-border px-2 py-1 text-[10.5px] font-bold uppercase tracking-[0.04em] last:border-r-0",
            m === mode ? "bg-accent text-accent-ink" : "bg-surface2 text-text3 hover:text-text",
          )}
        >
          {IP_MODE_LABEL[m]}
        </button>
      ))}
    </div>
  );
}

function QueryBar({
  text,
  mode,
  onText,
  onMode,
  onSubmit,
  inputRef,
}: {
  text: string;
  mode: IpMode;
  onText: (v: string) => void;
  onMode: (m: IpMode) => void;
  onSubmit: () => void;
  inputRef: React.RefObject<HTMLInputElement>;
}) {
  return (
    <div className="shrink-0 space-y-2 border-b border-border bg-surface2 px-4 py-3">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
        className="flex items-center gap-2"
      >
        <div className="field flex h-9 min-w-0 flex-1 items-center gap-2 !px-2.5 focus-within:border-accent">
          <Search size={14} className="shrink-0 text-text3" />
          <input
            ref={inputRef}
            value={text}
            onChange={(e) => onText(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            placeholder="10.30.7.7  or  10.30.0.0/16"
            aria-label="Address or block"
            className="mono min-w-0 flex-1 bg-transparent text-[13px] text-text outline-none placeholder:text-text3"
          />
        </div>
        <button type="submit" className="btn-primary shrink-0 !h-9 text-xs">
          Look up
        </button>
      </form>
      <div className="flex flex-wrap items-center gap-2">
        <span className="label !text-[9.5px]">Containment</span>
        <ModeSelector mode={mode} onChange={onMode} />
        <span className="hidden min-w-0 flex-1 truncate text-[11px] text-text3 lg:block">{IP_MODE_HINT[mode]}</span>
      </div>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// The empty prompt — what ⌘K opens onto.
// ───────────────────────────────────────────────────────────────────────────

function Prompt({ recent, onPick }: { recent: IpQuery[]; onPick: (q: IpQuery) => void }) {
  return (
    <div className="space-y-4 p-4">
      <p className="text-[12.5px] leading-relaxed text-text2">
        Type a host or a block. The answer is grouped the way the question is actually asked:
      </p>
      <dl className="border border-border text-[12px]">
        <div className="flex gap-3 border-b border-hair px-3 py-2">
          <dt className="w-[132px] shrink-0 text-[11px] font-bold uppercase tracking-[0.08em] text-text">Exact</dt>
          <dd className="text-text2">rules that name the address</dd>
        </div>
        <div className="flex gap-3 border-b border-hair bg-sev-high-bg px-3 py-2">
          <dt className="w-[132px] shrink-0 text-[11px] font-bold uppercase tracking-[0.08em] text-sev-high">Covering</dt>
          <dd className="text-text2">
            rules that reach it <b className="text-text">without naming it</b> — the group people forget, and
            usually where the risk is
          </dd>
        </div>
        <div className="flex gap-3 px-3 py-2">
          <dt className="w-[132px] shrink-0 text-[11px] font-bold uppercase tracking-[0.08em] text-info">Contained</dt>
          <dd className="text-text2">rules inside the block, when the query is a block</dd>
        </div>
      </dl>

      {recent.length > 0 && (
        <div>
          <div className="label mb-2 flex items-center gap-1.5 !text-[9.5px]">
            <History size={11} /> This session
          </div>
          <div className="flex flex-wrap gap-1.5">
            {recent.map((q) => (
              <button
                key={`${q.address}~${q.mode}`}
                type="button"
                onClick={() => onPick(q)}
                className="mono border border-border bg-sunk px-2 py-1 text-[11px] text-text2 transition-colors hover:border-accent hover:text-accent-fg"
              >
                {q.address}
                <span className="ml-1.5 text-text3">{IP_MODE_LABEL[q.mode]}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <p className="text-[11px] leading-relaxed text-text3">
        Open this from anywhere with <span className="mono text-text2">⌘K</span> /{" "}
        <span className="mono text-text2">Ctrl-K</span>, or from any address chip in the console.
      </p>
    </div>
  );
}

function LoadingBody() {
  return (
    <div className="space-y-4 p-4" aria-busy="true">
      <Skeleton className="h-3 w-40" />
      <div className="sunk grid gap-3 p-3.5 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="space-y-1.5">
            <Skeleton className="h-2.5 w-14" />
            <Skeleton className="h-3.5 w-24" />
          </div>
        ))}
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="border border-border">
          <div className="space-y-1.5 border-b border-hair bg-surface2 px-3 py-2">
            <Skeleton className="h-3 w-44" />
            <Skeleton className="h-2.5 w-2/3" />
          </div>
          {Array.from({ length: 2 }).map((__, k) => (
            <div key={k} className="space-y-1.5 px-3 py-2">
              <Skeleton className="h-3 w-3/4" />
              <Skeleton className="h-2.5 w-1/2" />
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// The drawer.
// ───────────────────────────────────────────────────────────────────────────

function Body({ snapshot }: { snapshot?: string }) {
  const ip = useIpLookup();
  const inputRef = useRef<HTMLInputElement>(null);
  const findingsRef = useRef<HTMLDivElement>(null);

  const [text, setText] = useState(ip.query?.address ?? "");
  const [mode, setMode] = useState<IpMode>(ip.query?.mode ?? DEFAULT_IP_MODE);
  const [entryError, setEntryError] = useState<string>();

  // A query issued from elsewhere (an address chip, an agent answer) drives the
  // input, so what is typed and what is shown can never disagree.
  useEffect(() => {
    if (!ip.query) return;
    setText(ip.query.address);
    setMode(ip.query.mode);
  }, [ip.query]);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  // ⌘K while the drawer is already open puts the caret back in the field and
  // selects what is there — the palette behaviour people expect from the
  // keystroke, rather than a shortcut that appears to do nothing.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return;
      if (e.key !== "k" && e.key !== "K") return;
      e.preventDefault();
      inputRef.current?.focus();
      inputRef.current?.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // The store does not validate — a programmatic caller can hand it anything —
  // so the parse happens here, on whatever is actually queued, and a malformed
  // address is reported rather than sent.
  const queued = ip.query?.address ?? null;
  const parse = useMemo(() => (queued ? parseAddress(queued) : null), [queued]);
  const parsed: ParsedAddress | null = parse?.ok ? parse : null;

  const lookup = useAddressLookup(parsed ? parsed.value : null, ip.query?.mode ?? mode, ip.seq, snapshot);
  const data = lookup.data;
  // Enrichment reads only start once there is something to enrich, and they are
  // independent of each other and of the lookup — see ip/data.ts.
  const sources = useSourceIndex(!!data, snapshot);
  const findings = useFindingIndex(!!data, snapshot);

  const submit = useCallback(
    (raw: string, m: IpMode) => {
      const p = parseAddress(raw);
      if (!p.ok) {
        setEntryError(p.reason);
        return;
      }
      setEntryError(undefined);
      ip.run(p.value, m);
    },
    [ip],
  );

  const onMode = useCallback(
    (m: IpMode) => {
      setMode(m);
      // Changing the mode changes the question, so it re-asks immediately rather
      // than leaving a mode chip that disagrees with the rows underneath it.
      if (text.trim()) submit(text, m);
    },
    [text, submit],
  );

  const scrollToFindings = useCallback(() => {
    findingsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const ruleCount = data
    ? data.matches.exact.length + data.matches.covering.length + data.matches.contained.length
    : 0;

  const size = parsed ? blockSize(parsed) : null;
  const requestedMode = ip.query?.mode ?? mode;
  const echoedMode = data?.mode;
  const modeDisagrees = !!echoedMode && echoedMode !== requestedMode;
  const addressDisagrees = !!data && !!parsed && data.address !== parsed.value;

  return (
    <>
      <header className="shrink-0 border-b border-border px-4 py-3">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <Eyebrow accent>Address drill-down</Eyebrow>
            <div className="mono mt-1 break-all text-[17px] font-bold leading-tight">
              {ip.query ? ip.query.address : <span className="text-text3">no address yet</span>}
            </div>
            {parsed && (
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <MonoChip tone={parsed.shape === "block" ? "info" : "neutral"}>
                  {parsed.shape} · {parsed.family}
                </MonoChip>
                {size && <MonoChip>{size}</MonoChip>}
                <MonoChip tone="accent" title={IP_MODE_HINT[requestedMode]}>
                  mode {IP_MODE_LABEL[requestedMode]}
                </MonoChip>
                {snapshot && <MonoChip title="This drawer is reading a historical snapshot.">snapshot {snapshot}</MonoChip>}
              </div>
            )}
          </div>
          <button onClick={ip.close} className="btn-ghost shrink-0 !h-8 !px-2" aria-label="Close">
            <X size={14} />
          </button>
        </div>
      </header>

      <QueryBar
        text={text}
        mode={mode}
        onText={(v) => {
          setText(v);
          setEntryError(undefined);
        }}
        onMode={onMode}
        onSubmit={() => submit(text, mode)}
        inputRef={inputRef}
      />

      <ScrollArea className="flex-1">
        {entryError && (
          <p role="alert" className="border-b border-sev-high-line bg-sev-high-bg px-4 py-2 text-[12px] text-sev-high">
            {entryError}
          </p>
        )}
        {parse && !parse.ok && (
          <p role="alert" className="border-b border-sev-high-line bg-sev-high-bg px-4 py-2 text-[12px] text-sev-high">
            <b>{parse.value}</b> was handed to the drill-down but is not an address: {parse.reason}
          </p>
        )}

        {!ip.query || (parse && !parse.ok) ? (
          <Prompt recent={ip.recent} onPick={(q) => ip.open(q.address, q.mode)} />
        ) : lookup.loading ? (
          <LoadingBody />
        ) : lookup.error ? (
          <div className="p-4">
            {/* Nothing below this is rendered: every group, count and verdict on
                this screen would be derived from a payload that never arrived. */}
            <ErrorState
              resource={`the address lookup for ${ip.query.address}`}
              error={lookup.error}
              onRetry={lookup.reload}
            />
          </div>
        ) : data ? (
          <div className="space-y-6 p-4">
            {(modeDisagrees || addressDisagrees) && (
              <p className="border border-sev-medium-line bg-sev-medium-bg px-3 py-2 text-[11.5px] leading-relaxed text-sev-medium">
                The API answered about{" "}
                <span className="mono text-text">{data.address}</span> under mode{" "}
                <span className="mono text-text">{data.mode}</span> — which is not what was asked for.
                Everything below describes the query the API actually ran, not the one on this header.
              </p>
            )}

            <AddressIdentity data={data} parsed={parsed} sources={sources.data} ruleCount={ruleCount} />

            {sources.error && (
              <InlineError
                resource="source provenance (tier and the simulated flag)"
                error={sources.error}
                className="border border-border bg-sunk px-3 py-2"
              />
            )}

            <PolicyMatches
              data={data}
              shape={parsed?.shape ?? "block"}
              mode={requestedMode}
              sources={sources.data}
              snapshot={snapshot}
              onFinding={scrollToFindings}
            />

            <div ref={findingsRef} className="scroll-mt-4">
              <AddressFindings
                ids={data.finding_ids}
                index={findings}
                sources={sources.data}
                address={data.address}
              />
            </div>

            <EffectiveAccess effective={data.effective} />
          </div>
        ) : null}
      </ScrollArea>
    </>
  );
}

/**
 * Mount once. Renders nothing until opened with ⌘K, `useIpLookup().open(...)`
 * or `openIpLookup(...)`.
 *
 * `snapshot` should be whatever snapshot the console is currently viewing, so a
 * drill-down from a historical view reads that history rather than silently
 * answering about live.
 */
export function IpLookup({ snapshot }: { snapshot?: string }) {
  const ip = useIpLookup();
  const { open, isOpen } = ip;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return;
      if (e.key !== "k" && e.key !== "K") return;
      e.preventDefault();
      open();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <Overlay
      open={isOpen}
      onClose={ip.close}
      placement="right"
      widthClass="max-w-[min(96vw,880px)]"
      label="Address drill-down"
    >
      {/* Keyed on nothing: the body keeps its own input state across queries,
          which is what makes re-asking with a different mode feel like one
          screen rather than four. */}
      <Body snapshot={snapshot} />
    </Overlay>
  );
}

/** A small affordance for a toolbar: the ⌘K hint, as a button. */
export function IpLookupButton({ className }: { className?: string }) {
  const ip = useIpLookup();
  return (
    <button
      type="button"
      onClick={() => ip.open()}
      title="Look up an address (⌘K)"
      className={cn("btn-ghost !h-8 gap-1.5 text-xs", className)}
    >
      <Crosshair size={13} />
      <span className="hidden sm:inline">Address</span>
      <Chip mono className="!border-borderStrong !px-1 !py-0 !text-[9.5px]">
        <Command size={9} />K
      </Chip>
    </button>
  );
}

export default IpLookup;
