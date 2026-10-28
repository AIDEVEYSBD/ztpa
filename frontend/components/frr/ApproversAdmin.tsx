"use client";

/**
 * Rule Review · Approvers (admin) — the approver matrix: who holds the
 * network_owner and security_approver duties, for which policy layer ('*' is
 * every layer). The API is admin-only; this screen only hides the door.
 */

import { useCallback, useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { Trash2, UserCheck } from "lucide-react";
import { ApiError, asApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { ApproverGrant, FrrDuty } from "@/lib/frrTypes";
import { isAdmin, type AppRole } from "@/lib/roles";
import { Button, Dialog, EmptyState, Field, IconButton, Input, Panel, Select, Skeleton, Table, THead, Th, Td, Tr, Chip } from "../ui";
import { ErrorState } from "../ui/Feedback";
import { ActionError, when } from "./bits";

const DUTY_LABEL: Record<FrrDuty, string> = {
  network_owner: "Network owner — decides items, validates the package",
  security_approver: "Security approver — approves or rejects a validated package",
};

export function ApproversAdmin() {
  const { data: session } = useSession();
  const role = ((session?.user as { role?: AppRole | null } | undefined)?.role ?? null) as AppRole | null;

  const [items, setItems] = useState<ApproverGrant[]>();
  const [err, setErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [principal, setPrincipal] = useState("");
  const [duty, setDuty] = useState<FrrDuty>("network_owner");
  const [scope, setScope] = useState("*");
  const [busy, setBusy] = useState(false);
  const [actErr, setActErr] = useState<{ action: string; error: ApiError }>();
  const [confirm, setConfirm] = useState<ApproverGrant>();
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    setErr(undefined);
    frr.approvers()
      .then((r) => {
        if (!r || !Array.isArray(r.items)) {
          setItems(undefined);
          setErr(new ApiError(200, "The API answered, but not with the approver list shape this screen reads ({items}).", "/api/admin/frr/approvers"));
          return;
        }
        setItems(r.items);
      })
      .catch((e) => { setItems(undefined); setErr(asApiError(e)); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { if (isAdmin(role)) load(); }, [load, role]);

  if (!isAdmin(role)) {
    return <ErrorState resource="the approver matrix" error={new ApiError(403, `The approver matrix is restricted to administrators. Your session carries the role ${role ?? "none"}.`, "/api/admin/frr/approvers")} />;
  }

  const p = principal.trim().toLowerCase();
  const validPrincipal = p.length >= 3 && p.length <= 320;

  const add = () => {
    if (!validPrincipal) return;
    setBusy(true);
    setActErr(undefined);
    frr.grant({ principal: p, duty, scope: scope.trim() || "*" })
      .then(() => { setPrincipal(""); load(); })
      .catch((e) => setActErr({ action: "grant the duty", error: asApiError(e) }))
      .finally(() => setBusy(false));
  };

  const remove = () => {
    if (!confirm) return;
    setRemoving(true);
    setActErr(undefined);
    frr.revoke({ principal: confirm.principal, duty: confirm.duty, scope: confirm.scope })
      .then(() => { setConfirm(undefined); load(); })
      .catch((e) => { setConfirm(undefined); setActErr({ action: "revoke the duty", error: asApiError(e) }); })
      .finally(() => setRemoving(false));
  };

  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-[12.5px] leading-[1.55] text-dim">
        A change package needs two different people: a network owner decides each item and validates the package, then a
        security approver approves or rejects it. The API refuses an approval from the person who validated. Principals are
        sign-in emails (or subject ids); scope is a policy layer name, or <span className="font-mono">*</span> for every layer.
      </p>

      <Panel title="Grant a duty" icon={<UserCheck size={13} />}>
        <form className="grid gap-3 md:grid-cols-[1.4fr_1.4fr_0.8fr_auto] md:items-end" onSubmit={(e) => { e.preventDefault(); add(); }}>
          <Field label="Principal" htmlFor="frr-principal" hint="Stored lower-case">
            <Input id="frr-principal" type="text" autoComplete="off" value={principal} onChange={(e) => setPrincipal(e.target.value)} placeholder="name@example.com" />
          </Field>
          <Field label="Duty" htmlFor="frr-duty">
            <Select id="frr-duty" value={duty} onChange={(e) => setDuty(e.target.value as FrrDuty)}>
              {(Object.keys(DUTY_LABEL) as FrrDuty[]).map((d) => <option key={d} value={d}>{DUTY_LABEL[d]}</option>)}
            </Select>
          </Field>
          <Field label="Scope (layer)" htmlFor="frr-scope">
            <Input id="frr-scope" mono value={scope} onChange={(e) => setScope(e.target.value)} />
          </Field>
          <Button type="submit" variant="solid" tone="ink" loading={busy} disabled={!validPrincipal}>Grant</Button>
        </form>
        {actErr && <ActionError className="mt-3" action={actErr.action} error={actErr.error} />}
      </Panel>

      {err ? (
        <ErrorState resource="the approver matrix" error={err} onRetry={load} />
      ) : loading && !items ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
      ) : items && items.length === 0 ? (
        <EmptyState icon={UserCheck} title="No duties granted"
          sub="Until someone holds network_owner and someone else holds security_approver, no change package can be validated or approved." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-line bg-surface elev-1">
          <Table minWidth={720}>
            <THead>
              <Th>Principal</Th><Th>Duty</Th><Th>Scope</Th><Th>Granted</Th><Th><span className="sr-only">Remove</span></Th>
            </THead>
            <tbody>
              {(items ?? []).map((g) => (
                <Tr key={`${g.principal}|${g.duty}|${g.scope}`}>
                  <Td className="font-medium break-all">{g.principal}</Td>
                  <Td><Chip variant={g.duty === "security_approver" ? "info" : "accent"}>{g.duty}</Chip></Td>
                  <Td className="font-mono">{g.scope}</Td>
                  <Td className="text-dim">{g.granted_at ? when(g.granted_at) : "—"}{g.granted_by ? ` by ${g.granted_by}` : ""}</Td>
                  <Td className="text-right">
                    <IconButton size="sm" tone="err" label={`Revoke ${g.duty} for ${g.principal} on ${g.scope}`} onClick={() => setConfirm(g)}>
                      <Trash2 size={13} />
                    </IconButton>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}

      {confirm && (
        <Dialog title="Revoke this duty?" confirmLabel="Revoke" confirmTone="err" busy={removing}
          onClose={() => setConfirm(undefined)} onConfirm={remove}>
          <span className="font-medium text-fg">{confirm.principal}</span> will no longer hold <span className="font-mono">{confirm.duty}</span> for
          scope <span className="font-mono">{confirm.scope}</span>. Decisions they already recorded stay on the record.
        </Dialog>
      )}
    </div>
  );
}
