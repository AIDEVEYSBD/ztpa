"use client";

import { useEffect, useState } from "react";
import { UserPlus, Users as UsersIcon } from "lucide-react";
import { adminCreateUser, adminListUsers } from "@/app/actions";
import type { AppUser, Role } from "@/lib/users";
import { Spinner, Skeleton, Chip, Eyebrow, EmptyState } from "../ui";
import type { ChipVariant } from "../ui";
import { DevLink } from "../auth/AuthShell";

const ROLE_VARIANT: Record<string, ChipVariant> = {
  admin: "accent",
  analyst: "neutral",
  viewer: "neutral",
};

export function UsersAdmin() {
  const [users, setUsers] = useState<AppUser[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; error?: string; devLink?: string }>();

  const refresh = () => adminListUsers().then((u) => { setUsers(u as AppUser[]); setLoaded(true); }).catch(() => setLoaded(true));
  useEffect(() => { refresh(); }, []);

  const invite = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true); setResult(undefined);
    const r = await adminCreateUser(email, name, role);
    setLoading(false); setResult(r);
    if (r.ok) { setEmail(""); setName(""); refresh(); }
  };

  return (
    <div className="space-y-5">
      <div className="panel p-5">
        <div className="mb-4 flex items-center gap-2"><Eyebrow><UserPlus size={13} /> Invite a user</Eyebrow></div>
        <form onSubmit={invite} className="flex flex-wrap items-end gap-3">
          <label className="min-w-[220px] flex-1">
            <span className="label mb-1 block">Email</span>
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="person@company.com" className="field" />
          </label>
          <label className="min-w-[160px] flex-1">
            <span className="label mb-1 block">Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="optional" className="field" />
          </label>
          <label>
            <span className="label mb-1 block">Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value as Role)} className="field">
              <option value="admin">admin</option>
              <option value="analyst">analyst</option>
              <option value="viewer">viewer</option>
            </select>
          </label>
          <button className="btn-primary" disabled={loading}>{loading ? <Spinner /> : "Send invite"}</button>
        </form>
        {result && !result.ok && <p className="mt-3 text-[12px] text-sev-critical">{result.error}</p>}
        {result?.ok && <p className="mt-3 text-[12px] text-ok">Invite created for {email || "the user"}.</p>}
        {result?.devLink && <DevLink href={result.devLink} />}
      </div>

      <div className="panel p-5">
        <div className="mb-4 flex items-center gap-2"><Eyebrow>Users</Eyebrow><span className="text-[12px] text-text3">({users.length})</span></div>
        {!loaded ? (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 border-b border-hair py-2.5 last:border-0">
                <Skeleton className="h-3.5 w-48" /><Skeleton className="h-3 w-24" /><Skeleton className="ml-auto h-5 w-16" />
              </div>
            ))}
          </div>
        ) : users.length === 0 ? (
          <EmptyState icon={UsersIcon} title="No users yet" sub="Invite someone above to get started." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] text-[13px]">
              <thead><tr className="border-b border-border text-left [&>th]:py-2 [&>th]:pr-3 [&>th]:text-[11px] [&>th]:font-bold [&>th]:uppercase [&>th]:tracking-[0.08em] [&>th]:text-text3">
                <th>Email</th><th>Name</th><th>Role</th><th>Status</th></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-hair transition-colors last:border-0 hover:bg-surfaceHover">
                    <td className="break-all py-2.5 pr-3 font-medium">{u.email}</td>
                    <td className="pr-3 text-text2">{u.name || "no name"}</td>
                    <td className="pr-3"><Chip variant={ROLE_VARIANT[u.role] ?? "neutral"}>{u.role}</Chip></td>
                    <td className="pr-3"><Chip variant={u.status === "active" ? "ok" : "info"}>{u.status}</Chip></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
