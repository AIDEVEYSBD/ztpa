"use client";

import { useSession } from "next-auth/react";
import {
  Network, ListChecks, GitBranch, MessageSquare, FileText, Plug,
  LogOut, Database, History, Rocket, SlidersHorizontal, BarChart3, ScrollText, Cog,
  Boxes,
} from "lucide-react";
import { Brand, cn } from "./ui";
import { ThemeToggle } from "./theme";

export type ScreenId = "explorer" | "inventory" | "sources" | "risks" | "change" | "staging" | "ask" | "report" | "connectors" | "ingest" | "snapshots" | "tools" | "metrics" | "audit" | "config";

type NavDef = { id: ScreenId; label: string; icon: typeof Network };

// Ordered as the review is actually conducted, which is also the order the
// brief asks for ("Order of tables: Sources, assets"):
//
//   Sources    what we read, and from which rung of the collection ladder
//   Inventory  what that found, and where each thing was found
//   Topology   what the network looks like, and what fails with what
//   Risk       what is wrong, then the gate, then staging
//
// The console used to open on the reachability graph -- step 3 of that process
// with the first two missing, so a reviewer was shown conclusions before the
// evidence and had no way to ask where any of it came from.
const CONSOLE: NavDef[] = [
  // ONE MAP, NOT TWO. "Topology" drew the physical estate and "Reachability"
  // drew the cross-tool policy path, and they were two views of one network
  // sitting in two nav entries — so a user had to know which one held the
  // answer before they could look for it. They are one canvas now, with the
  // policy path traced ACROSS the physical lanes, which only became possible
  // once every endpoint had a lane to be drawn in.
  { id: "explorer", label: "Explorer", icon: Network },
  // ONE INVENTORY, NOT TWO. "Assets & Identity" rendered a second, narrower
  // copy of this table; its only unique content was the duplicate-identity
  // review queue, which now lives inside this screen.
  { id: "inventory", label: "Inventory", icon: Boxes },
  { id: "sources", label: "Sources", icon: Plug },
  { id: "risks", label: "Risk To-Do", icon: ListChecks },
  { id: "change", label: "Change Gate", icon: GitBranch },
  { id: "staging", label: "Implementation Queue", icon: Rocket },
  { id: "ask", label: "Ask the Network", icon: MessageSquare },
  { id: "report", label: "Posture Report", icon: FileText },
];
const REFERENCE: NavDef[] = [
  { id: "connectors", label: "Connectors", icon: Plug },
];

const ADMIN: NavDef[] = [
  { id: "tools", label: "Tools & Usage", icon: SlidersHorizontal },
  { id: "metrics", label: "Metrics & Cost", icon: BarChart3 },
  { id: "ingest", label: "Ingested data", icon: Database },
  { id: "snapshots", label: "Snapshots", icon: History },
  //
  // There is no "Manage users" entry here any more, and there is no `users`
  // screen to point one at. Membership and roles are granted in the AutoX admin
  // (autox:app_roles), so a local invite/role screen could only ever create rows
  // nobody can sign in as. Who HAS signed in is still recorded in
  // ztpa.app_users (see lib/users.ts), and what they did is the Audit trail.
  //
  // The governance reader. Admin-only like the rest of this group: the whole
  // ADMIN block is rendered only for role === "admin" below, which is the same
  // gate every other admin screen already relies on. The API is admin-only too —
  // this hides the door, it does not replace the lock.
  { id: "audit", label: "Audit trail", icon: ScrollText },
  // Where this deployment's AI provider is chosen. Admin-only for the same
  // reason the rest of this group is, and for one more: it decides where the
  // product sends network topology, firewall rules and asset names. The API
  // behind it is admin-only too -- this hides the door, it does not replace the
  // lock.
  { id: "config", label: "Configuration", icon: Cog },
];

/** "Mehul Puri" -> "MP"; "purimehul2003@x.com" -> "PU". */
function initials(name?: string | null, email?: string | null) {
  const words = (name ?? "").trim().split(/\s+/).filter(Boolean);
  if (words.length >= 2) return (words[0][0] + words[words.length - 1][0]).toUpperCase();
  const base = words[0] || email?.split("@")[0] || "U";
  return base.slice(0, 2).toUpperCase();
}

export function Sidebar({ active, onSelect, counts }: {
  active: ScreenId;
  onSelect: (id: ScreenId) => void;
  counts: { findings: number; critical: number };
}) {
  const { data } = useSession();
  const user = data?.user as { email?: string; name?: string | null; role?: string | null } | undefined;
  // Prefer the AutoX `name` claim (falls back to preferred_username at the
  // provider), then the email local part.
  const displayName = user?.name?.trim() || user?.email?.split("@")[0] || "User";
  // No implicit role: an unentitled session is routed to /no-access by the
  // middleware, so anything rendered here already carries a real role.
  const role = user?.role ?? "viewer";

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
          {initials(user?.name, user?.email)}
        </div>
        <div className="min-w-0 flex-1 leading-tight">
          <div className="truncate text-[12px] font-bold" title={user?.email ?? undefined}>{displayName}</div>
          <div className="text-[11px] capitalize text-text3">{role}</div>
        </div>
        {/* Route through /sso/logout so the AutoX session ends too (RP-initiated
            logout with id_token_hint), not just our cookie. */}
        <button onClick={() => { window.location.href = "/sso/logout"; }} title="Sign out"
          className="grid h-[30px] w-[30px] place-items-center border border-border bg-surface2 text-text2 transition-colors hover:border-accent hover:text-accent-fg">
          <LogOut size={15} />
        </button>
        <ThemeToggle />
      </div>
    </nav>
  );
}
