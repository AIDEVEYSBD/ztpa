"""The two human gates over a change package (FRR-03):

  1. a NETWORK OWNER for the rules' layer decides each item -- accept, reject, or
     modify (supplying the sources/services a narrowing needs) -- which is where
     findings and availability impact are validated -- and then validates the
     package;
  2. a NETWORK SECURITY APPROVER, who is not the validator, approves or rejects
     the package as a whole.

Duties come from the approver matrix (`ztpa.frr_approvers`), matched on the
caller's email or SSO subject and scoped to a layer or '*'. Every transition is
conditional on the current state in its UPDATE, so two people acting at once
cannot both win, and every transition writes an audit row in its transaction.

Nothing here can reach a firewall or a ticketing system; the approved package
yields a runbook a person executes.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import psycopg
from psycopg.types.json import Jsonb

from .. import request_ctx
from ..db import audit

DUTIES = ("network_owner", "security_approver")


class WorkflowError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def principals() -> list[str]:
    a = request_ctx.current()
    return [p.lower() for p in (a.email, a.sub) if p]


def actor() -> Optional[str]:
    a = request_ctx.current()
    return (a.email or a.sub or "").lower() or None


def has_duty(cur: psycopg.Cursor, duty: str, scopes: set[str]) -> bool:
    """True when the caller holds `duty` for EVERY scope given ('*' covers all)."""
    p = principals()
    if not p:
        return False
    cur.execute("SELECT scope FROM ztpa.frr_approvers WHERE principal = ANY(%s) AND duty = %s",
                [p, duty])
    held = {r["scope"] for r in cur.fetchall()}
    return "*" in held or scopes <= held


def _package(cur: psycopg.Cursor, package_id: str, *, lock: bool = False) -> dict:
    try:
        cur.execute("SELECT * FROM ztpa.change_packages WHERE package_id = %s"
                    + (" FOR UPDATE" if lock else ""), [package_id])
    except psycopg.errors.InvalidTextRepresentation:
        cur.connection.rollback()
        raise WorkflowError(404, "no such change package")
    row = cur.fetchone()
    if row is None:
        raise WorkflowError(404, "no such change package")
    return row


def _scopes(cur: psycopg.Cursor, package_id: str) -> set[str]:
    cur.execute("SELECT DISTINCT layer FROM ztpa.change_package_items WHERE package_id = %s",
                [package_id])
    return {r["layer"] for r in cur.fetchall()}


def create(cur: psycopg.Cursor, export_id: str, drafted: dict, *, supersede: bool) -> dict:
    cur.execute("SELECT package_id, status FROM ztpa.change_packages WHERE export_id = %s "
                "AND status <> 'superseded' FOR UPDATE", [export_id])
    live = cur.fetchone()
    if live:
        if not supersede:
            raise WorkflowError(409, f"export already has a {live['status']} change package "
                                     f"{live['package_id']}; pass supersede=true to redraft")
        if live["status"] == "approved":
            raise WorkflowError(409, "the live package is approved; an approved package is not "
                                     "superseded -- upload a new export instead")
        cur.execute("UPDATE ztpa.change_packages SET status = 'superseded', updated_at = now() "
                    "WHERE package_id = %s", [live["package_id"]])
    cur.execute("""INSERT INTO ztpa.change_packages (export_id, summary, limitations, notes, created_by)
                   VALUES (%s, %s, %s, %s, %s) RETURNING *""",
                [export_id, Jsonb(drafted["summary"]), Jsonb(drafted["limitations"]),
                 Jsonb(drafted["notes"]), actor()])
    pkg = cur.fetchone()
    # COPY, not one INSERT per item: a 70,000-rule review drafts ~32,000 items.
    with cur.copy("""COPY ztpa.change_package_items
                       (package_id, item_id, rule_uid, layer, rule_number, rule_name, check_kind, band,
                        proposal, rationale, availability_impact, requires_owner_input, commands,
                        rollback, evidence) FROM STDIN""") as cp:
        for it in drafted["items"]:
            cp.write_row((pkg["package_id"], it["item_id"], it["rule_uid"], it["layer"], it["rule_number"],
                          it["rule_name"], it["check"], it["band"], it["proposal"], it["rationale"],
                          it["availability_impact"], json.dumps(it["requires_owner_input"]),
                          json.dumps(it["commands"]), json.dumps(it["rollback"]),
                          json.dumps(it["evidence"], default=str)))
    audit(cur, "frr_package_drafted", subject=str(pkg["package_id"]),
          detail={"export_id": export_id, "items": len(drafted["items"]), "superseded": bool(live)})
    return pkg


_ORDER = ("CASE band WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
          "rule_number NULLS LAST, item_id")
ITEMS_INLINE = 500           # packages up to this size return their items with the package


def get(cur: psycopg.Cursor, package_id: str, *, with_items: Optional[bool] = None) -> dict:
    """The package with its facet counts. Items are inlined for small packages;
    large ones are read through `items()` a page at a time (a 32,000-item package
    inlined was a 49 MiB response)."""
    pkg = _package(cur, package_id)
    cur.execute("SELECT count(*) AS total, count(*) FILTER (WHERE owner_decision IS NULL) AS undecided "
                "FROM ztpa.change_package_items WHERE package_id = %s", [package_id])
    f = cur.fetchone()
    facets = {"total": f["total"], "undecided": f["undecided"]}
    for col in ("band", "proposal", "availability_impact", "layer", "owner_decision"):
        cur.execute(f"SELECT coalesce({col}, 'undecided') AS k, count(*) AS n FROM ztpa.change_package_items "
                    f"WHERE package_id = %s GROUP BY 1", [package_id])
        facets[f"by_{col}"] = {r["k"]: r["n"] for r in cur.fetchall()}
    inline = facets["total"] <= ITEMS_INLINE if with_items is None else with_items
    out = {**pkg, "facets": facets, "items_inline": inline}
    if inline:
        cur.execute(f"SELECT * FROM ztpa.change_package_items WHERE package_id = %s ORDER BY {_ORDER}", [package_id])
        out["items"] = cur.fetchall()
    return out


def items(cur: psycopg.Cursor, package_id: str, *, band=None, proposal=None, impact=None, layer=None,
          decided: Optional[bool] = None, limit: int = 100, offset: int = 0) -> dict:
    _package(cur, package_id)
    where, params = ["package_id = %s"], [package_id]
    for col, val in (("band", band), ("proposal", proposal), ("availability_impact", impact), ("layer", layer)):
        if val:
            where.append(f"{col} = %s")
            params.append(val)
    if decided is not None:
        where.append("owner_decision IS NOT NULL" if decided else "owner_decision IS NULL")
    clause = " AND ".join(where)
    cur.execute(f"SELECT count(*) AS n FROM ztpa.change_package_items WHERE {clause}", params)
    total = cur.fetchone()["n"]
    cur.execute(f"SELECT * FROM ztpa.change_package_items WHERE {clause} ORDER BY {_ORDER} LIMIT %s OFFSET %s",
                params + [limit, offset])
    return {"total": total, "items": cur.fetchall(), "limit": limit, "offset": offset}


def decide_item(cur: psycopg.Cursor, package_id: str, item_id: str, decision: str,
                owner_input: Optional[dict], note: Optional[str]) -> dict:
    pkg = _package(cur, package_id, lock=True)
    if pkg["status"] != "draft":
        raise WorkflowError(409, f"package is {pkg['status']}; items can only be decided in draft")
    cur.execute("SELECT * FROM ztpa.change_package_items WHERE package_id = %s AND item_id = %s",
                [package_id, item_id])
    item = cur.fetchone()
    if item is None:
        raise WorkflowError(404, "no such item")
    if not has_duty(cur, "network_owner", {item["layer"]}):
        raise WorkflowError(403, f"deciding items needs the network_owner duty for layer "
                                 f"{item['layer']!r} in the approver matrix")
    if decision not in ("accept", "reject", "modify"):
        raise WorkflowError(422, "decision must be accept, reject or modify")
    required = item["requires_owner_input"] or []
    if decision in ("accept", "modify") and required:
        missing = [k for k in required if not (owner_input or {}).get(k)]
        if missing:
            raise WorkflowError(422, f"this change needs owner input before it can be accepted: "
                                     f"{', '.join(missing)}")
    if decision == "reject" and not (note or "").strip():
        raise WorkflowError(422, "a rejected item needs a note saying why (it is the record "
                                 "that the finding was reviewed)")
    cur.execute("""UPDATE ztpa.change_package_items SET owner_decision = %s, owner_input = %s,
                          owner_note = %s, decided_by = %s, decided_at = now()
                    WHERE package_id = %s AND item_id = %s RETURNING *""",
                [decision, Jsonb(owner_input) if owner_input else None, note, actor(),
                 package_id, item_id])
    out = cur.fetchone()
    audit(cur, "frr_item_decided", subject=f"{package_id}/{item_id}",
          detail={"decision": decision, "rule_uid": item["rule_uid"], "proposal": item["proposal"]})
    return out


def validate(cur: psycopg.Cursor, package_id: str, note: Optional[str]) -> dict:
    pkg = _package(cur, package_id, lock=True)
    if pkg["status"] != "draft":
        raise WorkflowError(409, f"package is {pkg['status']}, not draft")
    if not has_duty(cur, "network_owner", _scopes(cur, package_id)):
        raise WorkflowError(403, "validating needs the network_owner duty for every layer in the package")
    cur.execute("SELECT count(*) AS n FROM ztpa.change_package_items WHERE package_id = %s "
                "AND owner_decision IS NULL", [package_id])
    undecided = cur.fetchone()["n"]
    if undecided:
        raise WorkflowError(409, f"{undecided} item(s) have no owner decision yet")
    cur.execute("""UPDATE ztpa.change_packages SET status = 'owner_validated', validated_by = %s,
                          validated_at = now(), validation_note = %s, updated_at = now()
                    WHERE package_id = %s AND status = 'draft' RETURNING *""",
                [actor(), note, package_id])
    out = cur.fetchone()
    audit(cur, "frr_package_validated", subject=package_id, detail={"note": note})
    return out


def decide(cur: psycopg.Cursor, package_id: str, decision: str, note: Optional[str]) -> dict:
    pkg = _package(cur, package_id, lock=True)
    if pkg["status"] != "owner_validated":
        raise WorkflowError(409, f"package is {pkg['status']}; only an owner-validated package "
                                 "can be approved or rejected")
    if not has_duty(cur, "security_approver", _scopes(cur, package_id)):
        raise WorkflowError(403, "approving needs the security_approver duty in the approver matrix")
    if actor() == (pkg["validated_by"] or "").lower():
        raise WorkflowError(403, "four eyes: the person who validated the package cannot also approve it")
    if decision not in ("approve", "reject"):
        raise WorkflowError(422, "decision must be approve or reject")
    if decision == "reject" and not (note or "").strip():
        raise WorkflowError(422, "a rejection needs a note")
    status = "approved" if decision == "approve" else "rejected"
    cur.execute("""UPDATE ztpa.change_packages SET status = %s, decided_by = %s, decided_at = now(),
                          decision_note = %s, updated_at = now()
                    WHERE package_id = %s AND status = 'owner_validated' RETURNING *""",
                [status, actor(), note, package_id])
    out = cur.fetchone()
    audit(cur, f"frr_package_{status}", subject=package_id, detail={"note": note})
    return out


def runbook(cur: psycopg.Cursor, package_id: str) -> str:
    """The approved package as the text an engineer executes: accepted and
    modified items only, each with its rollback, under the approval record."""
    pkg = get(cur, package_id, with_items=True)
    if pkg["status"] != "approved":
        raise WorkflowError(409, f"package is {pkg['status']}; a runbook exists only once approved")
    lines = [f"# Firewall rule review change package {package_id}",
             f"# validated by {pkg['validated_by']} at {pkg['validated_at']:%Y-%m-%d %H:%M} UTC",
             f"# approved  by {pkg['decided_by']} at {pkg['decided_at']:%Y-%m-%d %H:%M} UTC",
             "# Nothing in this file has been applied. Run each step, verify, and use its",
             "# ROLLBACK block if the change misbehaves.", ""]
    n = 0
    for it in pkg["items"]:
        if it["owner_decision"] not in ("accept", "modify") or not it["commands"]:
            continue
        n += 1
        lines += [f"## {n}. {it['layer']} rule {it['rule_number']} ({it['rule_name']}): {it['proposal']}",
                  f"# why: {it['rationale']}", f"# availability impact: {it['availability_impact']}"]
        if it["owner_input"]:
            lines.append(f"# owner input: {json_compact(it['owner_input'])}")
        lines += it["commands"] + ["# ROLLBACK:"] + [f"#   {c}" for c in it["rollback"]] + [""]
    if n == 0:
        lines.append("# No accepted changes.")
    return "\n".join(lines) + "\n"


def json_compact(v: Any) -> str:
    import json
    return json.dumps(v, separators=(",", ":"), sort_keys=True)


def grant(cur: psycopg.Cursor, principal: str, duty: str, scope: str) -> dict:
    if duty not in DUTIES:
        raise WorkflowError(422, f"duty must be one of {DUTIES}")
    cur.execute("""INSERT INTO ztpa.frr_approvers (principal, duty, scope, granted_by)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (principal, duty, scope) DO UPDATE SET granted_by = EXCLUDED.granted_by
                   RETURNING *""", [principal.strip().lower(), duty, scope.strip() or "*", actor()])
    out = cur.fetchone()
    audit(cur, "frr_duty_granted", subject=principal.lower(), detail={"duty": duty, "scope": scope})
    return out


def revoke(cur: psycopg.Cursor, principal: str, duty: str, scope: str) -> bool:
    cur.execute("DELETE FROM ztpa.frr_approvers WHERE principal = %s AND duty = %s AND scope = %s",
                [principal.strip().lower(), duty, scope])
    done = cur.rowcount == 1
    if done:
        audit(cur, "frr_duty_revoked", subject=principal.lower(), detail={"duty": duty, "scope": scope})
    return done
