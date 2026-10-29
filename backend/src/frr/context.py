"""Context datasets: CMDB/IPAM ownership and observed flows (FRR-01.1c, 01.1d).

INPUT is CSV with a header row. Column names are matched case-insensitively
against the aliases below, so a Stealthwatch flow export or a common IPAM
export loads without a mapping file:

  cmdb   network | cidr | subnet | ip | address              (required)
         owner | owner_email | contact,  application | app | service,
         environment | env,  zone | security_zone,  criticality | tier
  flows  src | source | source_ip | subject ip address        (required)
         dst | destination | destination_ip | peer ip address (required)
         port | dst_port | peer port,  protocol | proto        (or "443/TCP" in the port column)
         last_seen | last active | end | end time            (required)
         first_seen | start active | start | start time,  flows | count

Validation fails closed: a missing required column, or more than
MAX_BAD_ROW_RATIO of rows unreadable, rejects the dataset with the reason and
the first bad lines; it never loads "whatever parsed". Accepted data is loaded
with COPY in one transaction, flows aggregated per (src, dst, proto, port).
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from psycopg.types.json import Jsonb

from .. import storage
from ..jobs import JobContext, handler

log = logging.getLogger("npr.api.context")

MAX_BAD_ROW_RATIO = float(os.environ.get("NPR_CONTEXT_MAX_BAD_ROW_RATIO", "0.01"))
FLOW_WINDOW_DAYS = int(os.environ.get("NPR_FRR_FLOW_WINDOW_DAYS", "90"))
SUGGEST_MAX = 25

ALIASES = {
    "cmdb": {
        "net": ["network", "cidr", "subnet", "ip", "address", "ip address", "range"],
        "owner": ["owner", "owner_email", "owner email", "contact", "technical owner"],
        "application": ["application", "app", "service", "system"],
        "environment": ["environment", "env"],
        "zone": ["zone", "security_zone", "security zone"],
        "criticality": ["criticality", "tier", "business criticality"],
    },
    "flows": {
        "src": ["src", "source", "source_ip", "source ip", "subject ip address", "subject ip", "client ip"],
        "dst": ["dst", "destination", "destination_ip", "destination ip", "peer ip address", "peer ip", "server ip"],
        "port": ["port", "dst_port", "destination port", "peer port", "peer port/protocol", "service port"],
        "proto": ["protocol", "proto"],
        "first_seen": ["first_seen", "first seen", "start active", "start", "start time"],
        "last_seen": ["last_seen", "last seen", "last active", "end", "end time"],
        "flows": ["flows", "count", "flow count", "connections"],
    },
}
REQUIRED = {"cmdb": ["net"], "flows": ["src", "dst", "last_seen"]}


class DatasetRejected(ValueError):
    pass


def _columns(kind: str, header: list[str]) -> dict[str, int]:
    norm = [h.strip().lower().replace("_", " ") for h in header]
    out = {}
    for field, names in ALIASES[kind].items():
        for n in names:
            n = n.replace("_", " ")
            if n in norm:
                out[field] = norm.index(n)
                break
    missing = [f for f in REQUIRED[kind] if f not in out]
    if missing:
        raise DatasetRejected(f"missing required column(s) {missing}; accepted names: "
                              + "; ".join(f"{f}: {', '.join(ALIASES[kind][f])}" for f in missing))
    return out


def _time(v: str) -> Optional[datetime]:
    v = (v or "").strip()
    if not v:
        return None
    if v.isdigit():                                   # epoch seconds or milliseconds
        n = int(v)
        return datetime.fromtimestamp(n / 1000 if n > 10**11 else n, tz=timezone.utc)
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00")) if fmt is None else datetime.strptime(v, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"unreadable time {v!r}")


def _port_proto(port: str, proto: str) -> tuple[Optional[int], str]:
    port, proto = (port or "").strip(), (proto or "").strip().lower()
    if "/" in port:                                   # Stealthwatch "443/TCP"
        p, _, pr = port.partition("/")
        port, proto = p.strip(), (proto or pr.strip().lower())
    proto = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto, proto) or "tcp"
    return (int(port) if port else None), proto


def parse(kind: str, data: bytes) -> tuple[list[tuple], dict]:
    """(rows ready for COPY, summary). Raises DatasetRejected."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DatasetRejected("the file is not UTF-8 text")
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise DatasetRejected("the file is empty")
    cols = _columns(kind, header)
    get = lambda row, f: row[cols[f]] if f in cols and cols[f] < len(row) else ""  # noqa: E731
    bad: list[str] = []          # first few unreadable lines, for the rejection message
    n = n_bad = 0
    if kind == "cmdb":
        rows = []
        for line_no, row in enumerate(reader, 2):
            if not any(c.strip() for c in row):
                continue
            n += 1
            try:
                raw = get(row, "net").strip()
                if "-" in raw:                         # a range "10.0.0.1-10.0.0.20"
                    a, _, b = raw.partition("-")
                    nets = list(ipaddress.summarize_address_range(ipaddress.ip_address(a.strip()),
                                                                  ipaddress.ip_address(b.strip())))
                else:
                    nets = [ipaddress.ip_network(raw, strict=False)]
                for net in nets:
                    rows.append((str(net), *(get(row, f).strip() or None for f in
                                             ("owner", "application", "environment", "zone", "criticality"))))
            except ValueError as e:
                n_bad += 1
                if len(bad) < 5:
                    bad.append(f"line {line_no}: {e}")
        summary = {"rows": n, "networks": len(rows)}
    else:
        agg: dict[tuple, list] = {}
        for line_no, row in enumerate(reader, 2):
            if not any(c.strip() for c in row):
                continue
            n += 1
            try:
                src = str(ipaddress.ip_address(get(row, "src").strip()))
                dst = str(ipaddress.ip_address(get(row, "dst").strip()))
                port, proto = _port_proto(get(row, "port"), get(row, "proto"))
                last = _time(get(row, "last_seen"))
                if last is None:
                    raise ValueError("no last-seen time")
                first = _time(get(row, "first_seen")) or last
                count = int(get(row, "flows") or 1)
                key = (src, dst, proto, port)
                cur = agg.get(key)
                if cur is None:
                    agg[key] = [first, last, max(1, count)]
                else:
                    cur[0], cur[1], cur[2] = min(cur[0], first), max(cur[1], last), cur[2] + max(1, count)
            except ValueError as e:
                n_bad += 1
                if len(bad) < 5:
                    bad.append(f"line {line_no}: {e}")
        rows = [(s, d, pr, po, f, l, c) for (s, d, pr, po), (f, l, c) in agg.items()]
        lasts = [r[5] for r in rows]
        summary = {"rows": n, "conversations": len(rows),
                   "from": min(lasts).isoformat() if lasts else None,
                   "to": max(lasts).isoformat() if lasts else None}
    if n == 0:
        raise DatasetRejected("the file has a header but no data rows")
    if n_bad / n > MAX_BAD_ROW_RATIO:
        raise DatasetRejected(f"{n_bad} of {n} rows are unreadable (limit {MAX_BAD_ROW_RATIO:.0%}); first: "
                              + "; ".join(bad)[:600])
    summary["skipped_rows"] = n_bad
    return rows, summary


def original_key(kind: str, sha: str) -> str:
    return f"context/{kind}/{sha}"


@handler("context.ingest")
def ingest(ctx: JobContext) -> dict:
    cur = ctx.conn.cursor()
    cur.execute("SELECT * FROM ztpa.context_datasets WHERE dataset_id = %s", [ctx.payload["dataset_id"]])
    ds = cur.fetchone()
    if ds is None:
        return {"skipped": "dataset no longer exists"}
    data = storage.store().get_bytes(ds["storage_key"])
    if hashlib.sha256(data).hexdigest() != ds["sha256"]:
        reason = "stored file does not match the checksum recorded at upload; re-upload it"
        cur.execute("UPDATE ztpa.context_datasets SET status='rejected', rejection_reason=%s WHERE dataset_id=%s",
                    [reason, ds["dataset_id"]])
        return {"status": "rejected", "reason": reason}
    try:
        rows, summary = parse(ds["kind"], data)
    except DatasetRejected as e:
        cur.execute("UPDATE ztpa.context_datasets SET status='rejected', rejection_reason=%s WHERE dataset_id=%s",
                    [str(e), ds["dataset_id"]])
        return {"status": "rejected", "reason": str(e)}
    ctx.check()
    # Idempotent on retry: clear anything a previous attempt loaded.
    table = "ztpa.cmdb_assets" if ds["kind"] == "cmdb" else "ztpa.flows"
    cur.execute(f"DELETE FROM {table} WHERE dataset_id = %s", [ds["dataset_id"]])
    cols = ("dataset_id, net, owner, application, environment, zone, criticality" if ds["kind"] == "cmdb"
            else "dataset_id, src, dst, proto, port, first_seen, last_seen, flows")
    with cur.copy(f"COPY {table} ({cols}) FROM STDIN") as cp:
        for r in rows:
            cp.write_row((ds["dataset_id"], *r))
    cur.execute("UPDATE ztpa.context_datasets SET status='accepted', summary=%s WHERE dataset_id=%s",
                [Jsonb(summary), ds["dataset_id"]])
    log.info("context dataset loaded", extra={"event": "context_loaded", "kind": ds["kind"], **summary})
    return {"status": "accepted", **summary}


# --- lookups used by the review, the drafter and the API ----------------------------
def active(cur, kind: str) -> Optional[dict]:
    cur.execute("""SELECT dataset_id, uploaded_at, summary FROM ztpa.context_datasets
                    WHERE kind = %s AND status = 'accepted' ORDER BY uploaded_at DESC LIMIT 1""", [kind])
    return cur.fetchone()


def owners_for(cur, nets: Iterable[str]) -> list[dict]:
    """CMDB rows overlapping any of `nets`, most specific first."""
    nets = [n for n in dict.fromkeys(nets) if n]
    ds = active(cur, "cmdb")
    if not ds or not nets:
        return []
    cur.execute("""SELECT DISTINCT ON (net) host(net) || '/' || masklen(net) AS net, owner, application,
                          environment, zone, criticality, masklen(net) AS plen
                     FROM ztpa.cmdb_assets
                    WHERE dataset_id = %s AND net && ANY(%s::cidr[])
                    ORDER BY net, masklen(net) DESC LIMIT 50""", [ds["dataset_id"], nets])
    rows = cur.fetchall()
    rows.sort(key=lambda r: -r["plen"])
    return [{k: v for k, v in r.items() if k != "plen"} for r in rows]


def _supernet(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 64}", strict=False))


def observed_sources(cur, dest_cidrs: list[str], proto: str, port_lo: Optional[int],
                     port_hi: Optional[int], *, now: Optional[datetime] = None) -> Optional[dict]:
    """Sources seen reaching `dest_cidrs` on the service within the window,
    grouped to /24 (IPv4) or /64 (IPv6). None when no flow dataset is loaded."""
    ds = active(cur, "flows")
    if not ds or not dest_cidrs:
        return None
    since = (now or datetime.now(timezone.utc)) - timedelta(days=FLOW_WINDOW_DAYS)
    params: list[Any] = [ds["dataset_id"], since, dest_cidrs]
    where = ""
    if proto and proto != "any":
        where += " AND proto = %s"
        params.append(proto)
    if port_lo is not None:
        where += " AND port BETWEEN %s AND %s"
        params += [port_lo, port_hi if port_hi is not None else port_lo]
    cur.execute(f"""SELECT host(src) AS src, sum(flows) AS flows, max(last_seen) AS last_seen
                      FROM ztpa.flows
                     WHERE dataset_id = %s AND last_seen >= %s AND dst <<= ANY(%s::inet[]) {where}
                     GROUP BY src ORDER BY sum(flows) DESC LIMIT 5000""", params)
    rows = cur.fetchall()
    groups: dict[str, dict] = defaultdict(lambda: {"sources": 0, "flows": 0, "last_seen": None})
    for r in rows:
        g = groups[_supernet(r["src"])]
        g["sources"] += 1
        g["flows"] += int(r["flows"])
        g["last_seen"] = max(filter(None, [g["last_seen"], r["last_seen"]]))
    ranked = sorted(groups.items(), key=lambda kv: -kv[1]["flows"])
    return {"window_days": FLOW_WINDOW_DAYS, "dataset_id": str(ds["dataset_id"]),
            "distinct_sources": len(rows), "groups": len(ranked),
            "suggested": [{"cidr": k, **{**v, "last_seen": v["last_seen"].isoformat() if v["last_seen"] else None}}
                          for k, v in ranked[:SUGGEST_MAX]],
            "truncated": len(ranked) > SUGGEST_MAX}


def _owners_batch(cur, dataset_id, nets: list[str]) -> dict[str, list[dict]]:
    """CMDB rows overlapping each of `nets`, in ONE query (the per-item version
    was 32,000 round trips -- 16.7 s -- on a 70,000-rule package)."""
    if not nets:
        return {}
    cur.execute("""SELECT q.net::text AS q, host(a.net) || '/' || masklen(a.net) AS net, a.owner, a.application,
                          a.environment, a.zone, a.criticality, masklen(a.net) AS plen
                     FROM unnest(%s::cidr[]) AS q(net)
                     JOIN ztpa.cmdb_assets a ON a.dataset_id = %s AND a.net && q.net""", [nets, dataset_id])
    out: dict[str, list[dict]] = defaultdict(list)
    for r in cur.fetchall():
        out[str(ipaddress.ip_network(r.pop("q"), strict=False))].append(r)
    return out


def _observed_batch(cur, dataset_id, probes: list[tuple[int, str, str, Optional[int], Optional[int]]],
                    since: datetime) -> dict[int, dict[str, dict]]:
    """Observed sources per probe key, grouped /24 (IPv4) or /64 (IPv6), in ONE
    query over every narrowing grant. probes = (key, dst cidr, proto, port lo, hi)."""
    if not probes:
        return {}
    k, d, p, lo, hi = (list(x) for x in zip(*probes))
    cur.execute("""SELECT q.k,
                          network(set_masklen(f.src, CASE WHEN family(f.src) = 4 THEN 24 ELSE 64 END))::text AS grp,
                          count(DISTINCT f.src) AS sources, sum(f.flows) AS flows
                     FROM unnest(%s::int[], %s::cidr[], %s::text[], %s::int[], %s::int[]) AS q(k, dst, proto, lo, hi)
                     JOIN ztpa.flows f ON f.dataset_id = %s AND f.last_seen >= %s AND f.dst <<= q.dst
                                      AND (q.proto = 'any' OR f.proto = q.proto)
                                      AND (q.lo IS NULL OR f.port BETWEEN q.lo AND coalesce(q.hi, q.lo))
                    GROUP BY q.k, grp""", [k, d, p, lo, hi, dataset_id, since])
    out: dict[int, dict[str, dict]] = defaultdict(dict)
    for r in cur.fetchall():
        g = out[r["k"]].setdefault(r["grp"], {"cidr": r["grp"], "sources": 0, "flows": 0})
        g["sources"] += int(r["sources"])
        g["flows"] += int(r["flows"])
    return out


def enrich_package(cur, drafted: dict, parsed: dict, *, now: Optional[datetime] = None) -> dict:
    """Attach context to drafted items, in place:

    * every item: `evidence.dest_owners` from the CMDB (who owns what the rule reaches);
    * narrowing items: `evidence.observed_sources` from flows, and
      `evidence.suggested_input` -- the observed source groups and the rule's
      services, as a PREFILL the network owner confirms or edits. Flows are
      evidence of use, not proof of need, so nothing is accepted on their basis.

    Two set-based queries for the whole package, whatever its size.
    Returns counts for the run log."""
    grants: dict[str, list[dict]] = defaultdict(list)
    for rec in parsed.get("records", []):
        grants[rec["raw_ref"]].append(rec)
    cmdb, flows_ds = active(cur, "cmdb"), active(cur, "flows")
    counts = {"owners": 0, "observed": 0, "no_flows": 0}

    def dests(item) -> list[str]:
        return sorted({str(ipaddress.ip_network(c, strict=False)) for r in grants.get(item["rule_uid"], [])
                       for c in r.get("dest_cidrs") or []} - {"0.0.0.0/0", "::/0"})

    if cmdb:
        all_nets = sorted({n for it in drafted["items"] for n in dests(it)})
        by_net = _owners_batch(cur, cmdb["dataset_id"], all_nets)
        for item in drafted["items"]:
            rows: dict[str, dict] = {}
            for n in dests(item):
                for r in by_net.get(n, []):
                    rows.setdefault(r["net"], r)
            if rows:
                ordered = sorted(rows.values(), key=lambda r: -r["plen"])[:10]
                item["evidence"]["dest_owners"] = [{k: v for k, v in r.items() if k != "plen"} for r in ordered]
                counts["owners"] += 1

    narrowing = [(i, it) for i, it in enumerate(drafted["items"]) if it["proposal"] == "time_bound_and_narrow"]
    if not flows_ds:
        counts["no_flows"] = len(narrowing)
        drafted.setdefault("limitations", []).append(
            "no flow data loaded: narrowing proposals carry no observed sources")
        return counts
    probes = []
    for i, it in narrowing:
        for r in grants.get(it["rule_uid"], []):
            for c in r.get("dest_cidrs") or []:
                probes.append((i, c, r.get("protocol") or "any", r.get("port"), r.get("port_end")))
    since = (now or datetime.now(timezone.utc)) - timedelta(days=FLOW_WINDOW_DAYS)
    observed = _observed_batch(cur, flows_ds["dataset_id"], probes, since)
    for i, item in narrowing:
        groups = observed.get(i, {})
        top = sorted(groups.values(), key=lambda g: -g["flows"])[:SUGGEST_MAX]
        services = sorted(dict.fromkeys(r["service"] for r in grants.get(item["rule_uid"], [])))
        item["evidence"]["observed_sources"] = {"window_days": FLOW_WINDOW_DAYS, "groups": top,
                                                "truncated": len(groups) > SUGGEST_MAX}
        if top:
            item["evidence"]["suggested_input"] = {"allowed_sources": [g["cidr"] for g in top],
                                                   "allowed_services": services}
            item["rationale"] += (f" Flows over the last {FLOW_WINDOW_DAYS} days show "
                                  f"{sum(g['sources'] for g in top)} source(s) in {len(top)} group(s) using it; "
                                  "they are offered as the narrowed sources for the owner to confirm.")
        else:
            item["rationale"] += (f" No flows matched this rule in the last {FLOW_WINDOW_DAYS} days; if that "
                                  "is accurate, the owner may prefer to remove it.")
        counts["observed"] += 1
    return counts
