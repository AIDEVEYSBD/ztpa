"use client";

import { useSession, signOut } from "next-auth/react";
import {
  Network, ListChecks, GitBranch, MessageSquare, FileText, Plug, Fingerprint,
  Users, LogOut, Database, History, Rocket, SlidersHorizontal, BarChart3,
} from "lucide-react";
import { Brand, cn } from "./ui";
import { ThemeToggle } from "./theme";

export type ScreenId = "map" | "risks" | "change" | "staging" | "ask" | "report" | "connectors" | "assets" | "ingest" | "users" | "snapshots" | "tools" | "metrics";

type NavDef = { id: ScreenId; label: string; icon: typeof Network };

const CONSOLE: NavDef[] = [
  { id: "map", label: "Network Map", icon: Network },
  { id: "risks", label: "Risk To-Do", icon: ListChecks },
  { id: "change", label: "Change Gate", icon: GitBranch },
  { id: "staging", label: "Staging Area", icon: Rocket },
  { id: "ask", label: "Ask the Network", icon: MessageSquare },
  { id: "report", label: "Posture Report", icon: FileText },
];
const REFERENCE: NavDef[] = [
  { id: "connectors", label: "Connectors", icon: Plug },
  { id: "assets", label: "Assets & Identity", icon: Fingerprint },
];
const ADMIN: NavDef[] = [
  { id: "tools", label: "Tools & Usage", icon: SlidersHorizontal },
  { id: "metrics", label: "Metrics & Cost", icon: BarChart3 },
  { id: "ingest", label: "Ingested data", icon: Database },
  { id: "snapshots", label: "Snapshots", icon: History },
  { id: "users", label: "Manage users", icon: Users },
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
  const user = data?.user as { email?: string; role?: string } | undefined;
  const role = user?.role ?? "analyst";

  const navItem = (it: NavDef, count?: number, critical?: boolean) => {
    const Icon = it.icon;
    return (
      <button key={it.id} onClick={() => onSelect(it.id)} className="navitem" data-active={active === it.id}>
        <Icon size={16} className="shrink-0" />
        <span className="flex-1 truncate">{it.label}</span>
        {count != null && count > 0 && (
          <span className={cn(
            "mono min-w-[20px] border px-1.5 text-center text-[11px] leading-5",
            critical ? "border-sev-critical-line bg-sev-critical-bg text-sev-critical" : "border-border bg-sunk text-text2",
          )}>
            {count}
          </span>
        )}
      </button>
    );
  };

  return (
    <nav className="glass-chrome relative flex h-full w-[232px] shrink-0 flex-col border-r border-border 3xl:w-[268px]">
      <div className="flex h-14 shrink-0 items-center border-b border-border px-[18px]">
        <Brand />
      </div>

      <div className="zt-scroll flex-1 overflow-y-auto p-2.5">
        <div className="label px-2 pb-1.5 pt-2.5">Console</div>
        {CONSOLE.map((it) =>
          navItem(it, it.id === "risks" ? counts.findings : undefined, it.id === "risks" && counts.critical > 0),
        )}

        <div className="label px-2 pb-1.5 pt-[18px]">Reference</div>
        {REFERENCE.map((it) => navItem(it))}

        {role === "admin" && (
          <>
            <div className="label px-2 pb-1.5 pt-[18px]">Admin</div>
            {ADMIN.map((it) => navItem(it))}
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
          className="grid h-[30px] w-[30px] place-items-center border border-border bg-surface2 text-text2 transition-colors hover:border-accent hover:text-accent-fg">
          <LogOut size={15} />
        </button>
        <ThemeToggle />
      </div>
    </nav>
  );
}
