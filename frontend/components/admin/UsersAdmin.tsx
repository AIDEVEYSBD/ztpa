"use client";

import { useEffect, useState } from "react";
import { UserPlus } from "lucide-react";
import { adminCreateUser, adminListUsers } from "@/app/actions";
import type { AppUser, Role } from "@/lib/users";
import { cn, Spinner, Skeleton } from "../ui";
import { DevLink } from "../auth/AuthShell";

const ROLE_STYLE: Record<string, string> = {
  admin: "border-accent bg-accent-soft text-text",
  analyst: "border-border text-text2",
  viewer: "border-border text-text3",
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
        <div className="mb-3 flex items-center gap-2 text-[13px] font-bold"><UserPlus size={16} /> Invite a user</div>
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
        {result && !result.ok && <p className="mt-2 text-[12px] text-sev-critical">{result.error}</p>}
        {result?.ok && <p className="mt-2 text-[12px] text-ok">Invite created for {email || "the user"}.</p>}
        {result?.devLink && <DevLink href={result.devLink} />}
      </div>

      <div className="panel p-5">
        <div className="mb-3 text-[13px] font-bold">Users ({users.length})</div>
        {!loaded ? (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 border-b border-hair py-2 last:border-0">
                <Skeleton className="h-3.5 w-48" /><Skeleton className="h-3 w-24" /><Skeleton className="ml-auto h-5 w-16" />
              </div>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] text-[13px]">
              <thead className="text-left"><tr className="label border-b border-border [&>th]:py-1.5 [&>th]:font-bold">
                <th>Email</th><th>Name</th><th>Role</th><th>Status</th></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-hair last:border-0">
                    <td className="break-all py-2 pr-3 font-medium">{u.email}</td>
                    <td className="pr-3 text-text2">{u.name || "no name"}</td>
                    <td className="pr-3"><span className={cn("chip", ROLE_STYLE[u.role])}>{u.role}</span></td>
                    <td className="text-[12px] text-text2">{u.status}</td>
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
