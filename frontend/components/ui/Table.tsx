"use client";

import type { ReactNode, ThHTMLAttributes, TdHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export function Table({ children, minWidth, className }: { children: ReactNode; minWidth?: number; className?: string }) {
  return (
    <div className="overflow-x-auto zt-scroll">
      <table
        className={cn("w-full border-collapse text-[11.5px]", className)}
        style={minWidth ? { minWidth } : undefined}
      >
        {children}
      </table>
    </div>
  );
}

export function THead({ children }: { children: ReactNode }) {
  return (
    <thead className="sticky top-0 z-10 bg-surface">
      <tr className="border-b border-line text-left text-[10.5px] text-faint">{children}</tr>
    </thead>
  );
}

export function Th({ className, children, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={cn("px-3 py-2 text-left text-[10.5px] font-medium text-faint first:px-4", className)} {...rest}>
      {children}
    </th>
  );
}

export function Td({ className, children, ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={cn("px-3 py-2 align-top first:px-4", className)} {...rest}>
      {children}
    </td>
  );
}

export function Tr({
  onOpen,
  className,
  children,
}: {
  onOpen?: () => void;
  className?: string;
  children: ReactNode;
}) {
  return (
    <tr
      onClick={onOpen}
      className={cn("border-b border-line last:border-0", onOpen && "cursor-pointer hover:bg-raise/40", className)}
    >
      {children}
    </tr>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-10 text-center text-[12.5px] text-dim">
        {children}
      </td>
    </tr>
  );
}
