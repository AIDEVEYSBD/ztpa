"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export interface ScrollAreaProps {
  children: ReactNode;
  className?: string;
  orientation?: "vertical" | "horizontal" | "both";
}

/** Thin instrument scroll container — consistent across panels. */
export function ScrollArea({ children, className, orientation = "vertical" }: ScrollAreaProps) {
  return (
    <div
      className={cn(
        "zt-scroll min-h-0",
        orientation === "vertical" && "overflow-y-auto overflow-x-hidden",
        orientation === "horizontal" && "overflow-x-auto overflow-y-hidden",
        orientation === "both" && "overflow-auto",
        className,
      )}
    >
      {children}
    </div>
  );
}

export default ScrollArea;
