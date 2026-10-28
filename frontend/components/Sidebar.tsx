"use client";

import { useSession } from "next-auth/react";
import {
  Network, ListChecks, GitBranch, MessageSquare, FileText, Plug,
  LogOut, History, Rocket, SlidersHorizontal, BarChart3, ScrollText, Cog,
  Boxes, FileJson, ClipboardCheck, FileStack, UserCheck, BookOpen,
} from "lucide-react";
import { Brand, cn, Button } from "./ui";
import { SurfaceGrain } from "./ui/Material";
import { ThemeToggle } from "./theme";

export type ScreenId = "explorer" | "inventory" | "sources" | "risks" | "change" | "staging" | "ask" | "report" | "connectors" | "snapshots" | "tools" | "metrics" | "audit" | "config"
  | "frr_exports" | "frr_review" | "frr_package" | "frr_approvers" | "frr_knowledge";

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
// Firewall rule review: an uploaded policy export, its deterministic rule-risk
// register, and the change package a network owner and a security approver
// sign off. In review order. The last two are admin-only (the matrix of who may
// sign, and the documents the impact assessor cites) and render only for admin,
// like the ADMIN group below; their APIs are admin-only too.
const RULE_REVIEW: NavDef[] = [
  { id: "frr_exports", label: "Exports", icon: FileJson },
  { id: "frr_review", label: "Rule review", icon: ClipboardCheck },
  { id: "frr_package", label: "Change package", icon: FileStack },
];
const RULE_REVIEW_ADMIN: NavDef[] = [
  { id: "frr_approvers", label: "Approvers", icon: UserCheck },
  { id: "frr_knowledge", label: "Knowledge", icon: BookOpen },
];

const REFERENCE: NavDef[] = [
  { id: "connectors", label: "Connectors", icon: Plug },
];

const ADMIN: NavDef[] = [
  { id: "tools", label: "Tools & Usage", icon: SlidersHorizontal },
  { id: "metrics", label: "Metrics & Cost", icon: BarChart3 },
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
      <button
        key={it.id}
        onClick={() => onSelect(it.id)}
        className="navitem focusable relative"
        data-active={active === it.id}
      >
        <Icon size={15} className="shrink-0" />
        <span className="flex-1 truncate text-[13px]">{it.label}</span>
        {count != null && count > 0 && (
          <span
            className={cn(
              "tnum min-w-5 rounded-sm border px-1.5 text-center font-mono text-[10.5px] leading-[18px]",
              critical ? "border-err-line bg-err-bg text-err" : "border-line bg-raise text-faint",
            )}
          >
            {count}
          </span>
        )}
      </button>
    );
  };

  return (
    <nav className="relative z-20 flex h-full w-[232px] shrink-0 flex-col border-r border-line bg-surface 3xl:w-[268px]">
      <SurfaceGrain />
      <div className="relative z-10 flex h-12 shrink-0 items-center border-b border-line px-4">
        <Brand />
      </div>

      <div className="zt-scroll relative z-10 flex-1 overflow-y-auto p-2.5">
        <div className="px-2 pt-2.5 pb-1.5 text-[11px] font-medium tracking-[0.08em] text-faint uppercase">Console</div>
        {CONSOLE.map((it) =>
          navItem(it, it.id === "risks" ? counts.findings : undefined, it.id === "risks" && counts.critical > 0),
        )}

        <div className="px-2 pt-[18px] pb-1.5 text-[11px] font-medium tracking-[0.08em] text-faint uppercase">Rule Review</div>
        {RULE_REVIEW.map((it) => navItem(it))}
        {role === "admin" && RULE_REVIEW_ADMIN.map((it) => navItem(it))}

        <div className="px-2 pt-[18px] pb-1.5 text-[11px] font-medium tracking-[0.08em] text-faint uppercase">Reference</div>
        {REFERENCE.map((it) => navItem(it))}

        {role === "admin" && (
          <>
            <div className="px-2 pt-[18px] pb-1.5 text-[11px] font-medium tracking-[0.08em] text-faint uppercase">Admin</div>
            {ADMIN.map((it) => navItem(it))}
          </>
        )}
      </div>

      <div className="relative z-10 flex shrink-0 items-center gap-2.5 border-t border-line p-3">
        <div className="grid size-6 shrink-0 place-items-center rounded-sm border border-line bg-raise text-[9.5px] font-semibold text-dim">
          {initials(user?.name, user?.email)}
        </div>
        <div className="min-w-0 flex-1 leading-tight">
          <div className="truncate text-[11.5px] font-medium" title={user?.email ?? undefined}>{displayName}</div>
          <div className="text-[9.5px] text-faint capitalize">{role}</div>
        </div>
        {/* Route through /sso/logout so the AutoX session ends too (RP-initiated
            logout with id_token_hint), not just our cookie. */}
        <Button
          size="sm"
          variant="solid"
          tone="err"
          title="Sign out"
          onClick={() => { window.location.href = "/sso/logout"; }}
        >
          <LogOut size={13} /> Sign out
        </Button>
        <ThemeToggle />
      </div>
    </nav>
  );
}
