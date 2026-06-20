"use client";

import { useSession, signOut } from "next-auth/react";
import {
  ShieldHalf, Network, ListChecks, GitBranch, MessageSquare, FileText, Plug, Fingerprint,
  Users, LogOut, Database, History,
} from "lucide-react";
import { ThemeToggle } from "./theme";

export type ScreenId = "map" | "risks" | "change" | "ask" | "report" | "connectors" | "assets" | "ingest" | "users" | "snapshots";

const CONSOLE: { id: ScreenId; label: string; icon: any }[] = [
  { id: "map", label: "Network Map", icon: Network },
  { id: "risks", label: "Risk To-Do", icon: ListChecks },
  { id: "change", label: "Change Gate", icon: GitBranch },
  { id: "ask", label: "Ask the Network", icon: MessageSquare },
  { id: "report", label: "Posture Report", icon: FileText },
];
const REFERENCE: { id: ScreenId; label: string; icon: any }[] = [
  { id: "connectors", label: "Connectors", icon: Plug },
  { id: "assets", label: "Assets & Identity", icon: Fingerprint },
];

function initials(s?: string) {
  return (s?.split("@")[0] ?? "U").slice(0, 2).toUpperCase();
}

export function Sidebar({ active, onSelect, counts }: {
  active: ScreenId;
  onSelect: (id: ScreenId) => void;
  counts: { findings: number; critical: number };
}) {
  const { data } = useSession();
  const user = data?.user as any;
  const role = user?.role ?? "analyst";

  const navItem = (it: { id: ScreenId; label: string; icon: any }, count?: number, critical?: boolean) => {
    const Icon = it.icon;
    return (
      <button key={it.id} onClick={() => onSelect(it.id)} className="navitem" data-active={active === it.id}>
        <Icon size={16} className="shrink-0" />
        <span className="flex-1 truncate">{it.label}</span>
        {count != null && count > 0 && (
          <span className={`mono px-1.5 text-[11px] leading-5 min-w-[20px] text-center ${critical ? "bg-sev-critical-bg text-sev-critical border border-sev-critical-line" : "bg-sunk text-text2 border border-border"}`}>
            {count}
          </span>
        )}
      </button>
    );
  };

  return (
    <nav className="flex h-full w-[232px] shrink-0 flex-col border-r border-border bg-surface">
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-border px-[18px]">
        <div className="grid h-[22px] w-[22px] shrink-0 place-items-center bg-accent">
          <ShieldHalf size={14} className="text-accent-ink" />
        </div>
        <div className="flex flex-col leading-[1.15]">
          <span className="text-[13px] font-bold tracking-[-0.01em]">ZeroTrust</span>
          <span className="text-[10px] uppercase tracking-[0.02em] text-text3">Policy Advisor</span>
        </div>
      </div>

      <div className="zt-scroll flex-1 overflow-y-auto p-2.5">
        <div className="label px-2 pb-1.5 pt-2.5 text-[10px] tracking-[0.08em]">Console</div>
        {CONSOLE.map((it) =>
          navItem(it, it.id === "risks" ? counts.findings : undefined, it.id === "risks" && counts.critical > 0),
        )}

        <div className="label px-2 pb-1.5 pt-[18px] text-[10px] tracking-[0.08em]">Reference</div>
        {REFERENCE.map((it) => navItem(it))}
        {role === "admin" && (
          <>
            <button onClick={() => onSelect("ingest")} className="navitem" data-active={active === "ingest"}>
              <Database size={16} className="shrink-0" />
              <span className="flex-1 truncate">Ingested data</span>
            </button>
            <button onClick={() => onSelect("snapshots")} className="navitem" data-active={active === "snapshots"}>
              <History size={16} className="shrink-0" />
              <span className="flex-1 truncate">Snapshots</span>
            </button>
            <button onClick={() => onSelect("users")} className="navitem" data-active={active === "users"}>
              <Users size={16} className="shrink-0" />
              <span className="flex-1 truncate">Manage users</span>
            </button>
          </>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-2.5 border-t border-border p-3">
        <div className="grid h-[26px] w-[26px] shrink-0 place-items-center border border-border bg-sunk text-[11px] font-bold text-text2">
          {initials(user?.email)}
        </div>
        <div className="min-w-0 flex-1 leading-tight">
          <div className="truncate text-[12px] font-bold">{user?.email?.split("@")[0] ?? "User"}</div>
          <div className="text-[11px] capitalize text-text3">{role}</div>
        </div>
        <button onClick={() => signOut({ callbackUrl: "/login" })} title="Sign out"
          className="grid h-[30px] w-[30px] place-items-center border border-border bg-surface2 text-text2 hover:bg-surfaceHover">
          <LogOut size={15} />
        </button>
        <ThemeToggle />
      </div>
    </nav>
  );
}
