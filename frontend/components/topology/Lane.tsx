"use client";

/**
 * One horizontal band: the label on the left, and — when there is nothing to
 * draw in it — the strip that says why.
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE. An `observed: false` lane renders as a
 * NAMED ABSENCE: the reason, and the console API that would fill it. It never
 * renders a faded device glyph, never a dotted outline shaped like hardware,
 * and it is never omitted. Those three are the same mistake in three costumes —
 * putting equipment on a client's network diagram that no console ever
 * reported, or quietly closing the gap so nobody asks about it. A lane we did
 * not see is the most useful thing on this canvas, because it is the one that
 * tells an operator which connector to turn on next.
 */

import { EyeOff, ChevronsDownUp, ChevronsUpDown, CircleSlash } from "lucide-react";
import { cn } from "@/lib/cn";
import { GEOM, type PlacedLane } from "./layout";

export interface LaneProps {
  lane: PlacedLane;
  width: number;
  first: boolean;
  onToggle?: () => void;
}

export function Lane({ lane, width, first, onToggle }: LaneProps) {
  const stripLeft = GEOM.labelW;
  const stripW = Math.max(200, width - GEOM.labelW - GEOM.padRight);

  return (
    <div
      className={cn("absolute left-0 right-0", !first && "border-t border-hair")}
      style={{ top: lane.top, height: lane.height }}
    >
      {/* Label column. The count is the lane's own node count, so a collapsed
          lane still reads out how many devices are in it. */}
      <div className="absolute inset-y-0 left-0 flex flex-col justify-center gap-0.5 pl-2 pr-2" style={{ width: GEOM.labelW }}>
        <div className="text-[10px] font-bold uppercase tracking-[0.12em] text-text2">{lane.label}</div>
        <div className="mono flex items-center gap-1 text-[10px] text-text3">
          {lane.observed ? (
            <>
              <span className="tabular-nums">{lane.nodeCount}</span>
              <span>node{lane.nodeCount === 1 ? "" : "s"}</span>
            </>
          ) : (
            <span className="text-ghost">unobserved</span>
          )}
        </div>
        {lane.collapsible && onToggle ? (
          <button
            type="button"
            onClick={onToggle}
            className="focusable mt-0.5 inline-flex h-[17px] w-fit cursor-pointer items-center gap-1 rounded-[3px] border border-line bg-raise px-1 text-[9px] font-medium text-dim hover:border-line-strong hover:text-fg"
            aria-expanded={!lane.collapsed}
          >
            {lane.collapsed ? <ChevronsUpDown size={9} /> : <ChevronsDownUp size={9} />}
            {lane.collapsed ? "Expand" : "Collapse"}
          </button>
        ) : null}
      </div>

      {/* The named absence. */}
      {!lane.observed ? (
        <div
          className="absolute flex flex-col justify-center gap-1 border border-dotted border-borderStrong bg-sunk px-3 py-2"
          style={{ left: stripLeft, width: stripW, top: 10, bottom: 10 }}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-bold text-text2">
            <EyeOff size={12} className="shrink-0 text-text3" />
            Nothing observed at this layer — no device is drawn here because none was reported.
          </div>
          {lane.reason ? <div className="text-[11px] leading-snug text-text2">{lane.reason}</div> : null}
          {lane.wouldBeFilledBy ? (
            <div className="mono text-[10.5px] text-text3">
              Would be filled by <span className="text-text2">{lane.wouldBeFilledBy}</span>
            </div>
          ) : null}
          {/* A payload that marks a lane unobserved and then lists devices in it
              is contradicting itself, and the contradiction is reported rather
              than resolved: drawing the devices would put hardware on screen
              that the lane's own claim says nobody saw, and dropping them
              quietly is the silent truncation this canvas refuses elsewhere. */}
          {lane.nodeCount > 0 ? (
            <div className="text-[10.5px] leading-snug text-sev-high">
              This lane is marked unobserved and also carries {lane.nodeCount} node
              {lane.nodeCount === 1 ? "" : "s"} in the payload. They are not drawn — the lane&rsquo;s own claim is that
              nothing was observed here, and the two statements cannot both be rendered.
            </div>
          ) : null}
        </div>
      ) : null}

      {/* Observed, and genuinely holding nothing. A different sentence from the
          one above, because it is a different claim. */}
      {lane.observed && lane.nodeCount === 0 ? (
        <div
          className="absolute flex items-center gap-1.5 border border-border bg-sunk px-3 text-[11px] text-text2"
          style={{ left: stripLeft, width: stripW, top: 8, bottom: 8 }}
        >
          <CircleSlash size={12} className="shrink-0 text-text3" />
          This layer was covered by a source and carries no devices in this snapshot.
        </div>
      ) : null}

      {/* Collapsed notice, so an aggregated line is never read as one cable. */}
      {lane.collapsed ? (
        <div
          className="absolute text-[10px] text-text3"
          style={{ left: stripLeft, width: stripW, bottom: 3 }}
        >
          {lane.nodeCount} nodes grouped into {lane.cardCount} card{lane.cardCount === 1 ? "" : "s"} by role. Lines to a group card stand for every link its members have.
        </div>
      ) : null}
    </div>
  );
}
