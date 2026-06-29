"use client";

import { cn } from "@/lib/cn";

/* Skeleton loaders — shown wherever data is being fetched, so the layout never
   flashes empty. The `.skeleton` class (globals.css) carries the themed sheen. */

export function Skeleton({ className = "" }: { className?: string }) {
  return <span className={cn("skeleton block", className)} />;
}

export function SkeletonText({ lines = 3, className = "" }: { lines?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn("h-3", i === lines - 1 ? "w-2/3" : "w-full")} />
      ))}
    </div>
  );
}

/** List of card rows that mirror the Risk To-Do / table item shape. */
export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="panel flex items-center gap-3 p-4">
          <Skeleton className="h-7 w-9 shrink-0" />
          <div className="min-w-0 flex-1 space-y-2">
            <Skeleton className="h-3.5 w-1/3" />
            <Skeleton className="h-3 w-3/4" />
          </div>
          <Skeleton className="hidden h-5 w-20 shrink-0 sm:block" />
        </div>
      ))}
    </div>
  );
}

/** A panel placeholder with a header line and body text (prose / graph slots). */
export function SkeletonPanel({ className = "", lines = 4 }: { className?: string; lines?: number }) {
  return (
    <div className={cn("panel space-y-3 p-4", className)}>
      <Skeleton className="h-4 w-40" />
      <SkeletonText lines={lines} />
    </div>
  );
}
