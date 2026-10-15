"use client";

/**
 * Find a node on the canvas by anything you actually have in your hand.
 *
 * A nine-lane diagram is a map, and a map without a "where is this" is a
 * picture. The corpus is every node in every lane — including the ones inside a
 * collapsed group card, which the Explorer expands when you pick them, because
 * a search that can find something it cannot then show you is worse than one
 * that finds nothing.
 *
 * The result count is a fact and is printed as one: "3 of 38 nodes". Highlight
 * without a count leaves the reader to work out whether the two boxes they can
 * see are all of them.
 */

import { useEffect, useRef } from "react";
import { ChevronDown, ChevronUp, Search, X } from "lucide-react";
import { cn } from "@/lib/cn";
import type { SearchHit } from "./node";

export interface SearchBoxProps {
  value: string;
  onChange: (v: string) => void;
  hits: SearchHit[];
  /** Index into `hits` the canvas is currently centred on. */
  active: number;
  onActive: (i: number) => void;
  /** How many nodes were searched, so a count has a denominator. */
  corpusSize: number;
  /** Bumped by the parent to steal focus (the `/` shortcut). */
  focusNonce: number;
  className?: string;
}

export function SearchBox(p: SearchBoxProps) {
  const ref = useRef<HTMLInputElement | null>(null);
  const seen = useRef(p.focusNonce);

  useEffect(() => {
    if (p.focusNonce === seen.current) return;
    seen.current = p.focusNonce;
    ref.current?.focus();
    ref.current?.select();
  }, [p.focusNonce]);

  const has = p.value.trim().length > 0;
  const step = (d: number) => {
    if (p.hits.length === 0) return;
    p.onActive((p.active + d + p.hits.length) % p.hits.length);
  };

  return (
    <div className={cn("relative min-w-0", p.className)}>
      <div className="flex h-7 min-w-0 items-center gap-1.5 rounded-sm border border-line bg-canvas px-2 focus-within:border-fg">
        <Search size={12} className="shrink-0 text-faint" />
        <input
          ref={ref}
          value={p.value}
          onChange={(e) => p.onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") { e.preventDefault(); step(e.shiftKey ? -1 : 1); }
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              if (has) p.onChange("");
              else ref.current?.blur();
            }
          }}
          placeholder="Find a node — name, address, model, VLAN"
          aria-label="Find a node on the canvas"
          className="min-w-0 flex-1 bg-transparent font-mono text-[11.5px] text-fg outline-none placeholder:text-ghost"
        />
        {has ? (
          <>
            <span
              className="tnum shrink-0 font-mono text-[10.5px] whitespace-nowrap text-dim"
              title={`${p.hits.length} of ${p.corpusSize} nodes on this canvas match "${p.value}".`}
            >
              {p.hits.length === 0 ? "0" : `${p.active + 1}/${p.hits.length}`}
            </span>
            <button
              type="button"
              onClick={() => step(-1)}
              disabled={p.hits.length === 0}
              className="focusable shrink-0 cursor-pointer text-faint hover:text-fg disabled:opacity-40"
              aria-label="Previous match"
              title="Previous match (Shift+Enter)"
            >
              <ChevronUp size={12} />
            </button>
            <button
              type="button"
              onClick={() => step(1)}
              disabled={p.hits.length === 0}
              className="focusable shrink-0 cursor-pointer text-faint hover:text-fg disabled:opacity-40"
              aria-label="Next match"
              title="Next match (Enter)"
            >
              <ChevronDown size={12} />
            </button>
            <button
              type="button"
              onClick={() => p.onChange("")}
              className="shrink-0 text-text3 hover:text-accent-fg"
              aria-label="Clear the search"
              title="Clear (Esc)"
            >
              <X size={12} />
            </button>
          </>
        ) : (
          <span className="mono hidden shrink-0 border border-border px-1 text-[9px] text-text3 sm:inline">/</span>
        )}
      </div>

      {has ? (
        <div className="popover absolute left-0 right-0 top-[34px] z-30 max-h-64 overflow-auto">
          {p.hits.length === 0 ? (
            <div className="px-2.5 py-2 text-[11.5px] leading-snug text-text2">
              Nothing on this canvas matches <span className="mono text-text">{p.value}</span>.{" "}
              <span className="text-text3">
                {p.corpusSize} node{p.corpusSize === 1 ? "" : "s"} were searched by name, key, address, model, OS,
                serial, site, VLAN, tag, interface and role.
              </span>
            </div>
          ) : (
            <>
              <div className="border-b border-hair px-2.5 py-1 text-[10.5px] text-text3">
                <span className="mono text-text2">{p.hits.length}</span> of{" "}
                <span className="mono text-text2">{p.corpusSize}</span> nodes matched
              </div>
              <ul>
                {p.hits.map((h, i) => (
                  <li key={`${h.cardId}:${h.key}`}>
                    <button
                      type="button"
                      onClick={() => p.onActive(i)}
                      className={cn(
                        "row flex w-full items-baseline gap-2 px-2.5 py-1.5 text-left",
                        i === p.active && "bg-surfaceHover",
                      )}
                    >
                      <span className="mono min-w-0 flex-1 truncate text-[11.5px] font-bold">{h.name}</span>
                      <span className="mono shrink-0 text-[10px] text-text3">{h.layer}</span>
                    </button>
                    <div className="mono -mt-1 mb-1 truncate px-2.5 text-[10px] text-text3" title={h.why}>
                      {h.why}
                      {h.viaGroup ? " · inside a collapsed group" : ""}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      ) : null}
    </div>
  );
}
