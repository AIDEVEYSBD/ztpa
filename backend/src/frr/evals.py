"""FRR evaluation: a labelled test rulebase, the metrics FRR-01.5 names, and a
gate CI and releases can enforce (FRR-04.3, 04.5).

    python -m src.frr.evals --rules 2000 --gate               # synthetic labelled set
    python -m src.frr.evals --export X.json --labels L.json   # a real labelled rulebase

METRICS
  check accuracy      precision / recall / F1 per check over (rule, check) pairs,
                      against labels -- not against the engine's own output
  severity agreement  exact agreement and Cohen's kappa between the labelled
                      band and the register's worst band, over every rule
                      ("none" for an unflagged rule)
  time / 1,000 rules  parse + review wall time, scaled

WHERE THE LABELS COME FROM. The synthetic set plants each condition by
construction (a rule built to be any-any IS any-any), so its check labels are
ground truth independent of the engine. Its BAND labels follow `REVIEWER_POLICY`
below -- a written v1 policy, not the engine -- so disagreement is measured, not
assumed away. The security owner's labelled rulebase (UAT, FRR-04.1) replaces
both via --export/--labels; the labels file is
    {"<rule uid>": {"checks": ["unused", ...], "band": "medium" | "none"}, ...}

THE GATE. Check precision and recall and time per 1,000 rules are enforced.
Severity agreement is reported and enforced only when NPR_EVAL_MIN_BAND_AGREEMENT
is set: v1 band labels are a policy proposal awaiting the reviewers' own.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from ..normalizers import checkpoint
from .review import review

ANY = "97aeb369-9aea-11d5-bd16-0090272ccb30"
BANDS = ("none", "low", "medium", "high", "critical")

#: v1 reviewer severity policy for the planted categories (to be replaced by the
#: security owner's labels at UAT).
REVIEWER_POLICY = {
    "any_any": "critical", "internet_admin": "critical", "internet_data": "high",
    "internal_broad_admin": "medium", "redundant_unused": "medium", "expired": "medium",
    "disabled": "low", "unused": "medium", "stale": "medium", "clean": "none",
}

GATE = {
    "min_precision": float(os.environ.get("NPR_EVAL_MIN_PRECISION", "0.98")),
    "min_recall": float(os.environ.get("NPR_EVAL_MIN_RECALL", "0.98")),
    "min_check_recall": float(os.environ.get("NPR_EVAL_MIN_CHECK_RECALL", "0.95")),
    "max_seconds_per_1k": float(os.environ.get("NPR_EVAL_MAX_SECONDS_PER_1K", "3.0")),
    "min_band_agreement": (float(os.environ["NPR_EVAL_MIN_BAND_AGREEMENT"])
                           if os.environ.get("NPR_EVAL_MIN_BAND_AGREEMENT") else None),
}


def generate(n: int, seed: int = 1, exported_at: datetime | None = None) -> tuple[dict, dict]:
    """(export, labels) with ~n rules. Every rule gets its own destination host
    unless it is half of a planted redundant pair, so no condition is created
    by accident."""
    rnd = random.Random(seed)
    now = exported_at or datetime(2026, 10, 27, tzinfo=timezone.utc)
    recent = (now - timedelta(days=3)).isoformat()
    old = (now - timedelta(days=200)).isoformat()
    objs: list[dict] = [
        {"uid": ANY, "name": "Any", "type": "CpmiAnyObject"},
        {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
        {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
        {"uid": "t-past", "name": "ended", "type": "time", "end-never": False,
         "end": {"iso-8601": (now - timedelta(days=60)).isoformat()}},
        {"uid": "pt", "name": "Policy Targets", "type": "Global"},
    ]
    for name, port in (("ssh", 22), ("rdp", 3389), ("smb", 445), ("https", 443), ("alt-https", 8443),
                       ("mssql", 1433), ("postgres", 5432)):
        objs.append({"uid": f"s-{name}", "name": name, "type": "service-tcp", "port": str(port)})

    counter = iter(range(1, 10_000_000))

    def host() -> str:
        k = next(counter)
        uid = f"h{k}"
        objs.append({"uid": uid, "name": f"srv-{k}", "type": "host",
                     "ipv4-address": f"10.{200 + k // 65536 % 50}.{k // 256 % 256}.{k % 256}"})
        return uid

    def net(prefix: int) -> str:
        k = next(counter)
        uid = f"n{k}"
        if prefix == 16:
            addr = f"10.{(k % 90) + 100}.0.0"
        else:
            addr = f"10.{50 + k // 65536 % 40}.{k // 256 % 256}.{(k % 256) & ~((1 << (32 - prefix)) - 1) if prefix > 24 else 0}"
        objs.append({"uid": uid, "name": f"net-{k}", "type": "network", "subnet4": addr,
                     "mask-length4": prefix})
        return uid

    rules: list[dict] = []
    labels: dict[str, dict] = {}

    def add(cat: str, checks: set[str], src, dst, svc, *, action="accept", hits=(50, recent), **kw):
        num = len(rules) + 1
        uid = f"r{num}-{cat}"
        r = {"type": "access-rule", "uid": uid, "rule-number": num, "name": f"{cat}-{num}",
             "enabled": True, "source": src, "destination": dst, "service": svc, "action": action,
             "time": [ANY], "install-on": ["pt"],
             "hits": {"value": hits[0], "last-date": {"iso-8601": hits[1]} if hits[1] else None}}
        r.update(kw)
        rules.append(r)
        labels[uid] = {"checks": sorted(checks), "band": REVIEWER_POLICY[cat], "category": cat}
        return uid

    mix = ["clean"] * 50 + ["internet_admin"] * 6 + ["internal_broad_admin"] * 6 + ["internet_data"] * 4 + \
          ["redundant_unused"] * 8 + ["partly_covered"] * 4 + ["union_redundant"] * 3 + ["expired"] * 6 + ["disabled"] * 6 + ["unused"] * 8 + ["stale"] * 6
    while len(rules) < n - 2:
        cat = rnd.choice(mix)
        if cat == "clean":
            add(cat, set(), [net(24)], [host()], [rnd.choice(["s-https", "s-alt-https"])])
        elif cat == "internet_admin":
            add(cat, {"admin_port_exposed"}, [ANY], [host()], [rnd.choice(["s-ssh", "s-rdp", "s-smb"])])
        elif cat == "internal_broad_admin":
            add(cat, {"admin_port_exposed"}, [net(16)], [host()], [rnd.choice(["s-ssh", "s-rdp"])])
        elif cat == "internet_data":
            add(cat, {"broad_source"}, [ANY], [host()], [rnd.choice(["s-mssql", "s-postgres"])])
        elif cat == "redundant_unused":
            h, wide = host(), net(24)
            add("clean", set(), [wide], [h], ["s-https"])
            o = next(x for x in objs if x["uid"] == wide)
            narrow = f"{wide}-sub"
            objs.append({"uid": narrow, "name": f"{o['name']}-sub", "type": "network",
                         "subnet4": o["subnet4"], "mask-length4": 28})
            add(cat, {"shadowed", "unused"}, [narrow], [h], ["s-https"], hits=(0, None))
        elif cat == "partly_covered":
            # Only one of the second rule's two services is covered above: it
            # still carries alt-https and must NOT be reported shadowed. No
            # hits, so the counter cannot rescue it: only full-coverage logic.
            h, wide = host(), net(24)
            add("clean", set(), [wide], [h], ["s-https"])
            o = next(x for x in objs if x["uid"] == wide)
            narrow = f"{wide}-sub"
            objs.append({"uid": narrow, "name": f"{o['name']}-sub", "type": "network",
                         "subnet4": o["subnet4"], "mask-length4": 28})
            add("unused", {"unused"}, [narrow], [h], ["s-https", "s-alt-https"], hits=(0, None))
        elif cat == "union_redundant":
            # Two /25 halves above, each covering half the sources: together
            # they take all of the /24 rule's traffic, so it never matches.
            h, whole = host(), net(24)
            o = next(x for x in objs if x["uid"] == whole)
            halves = []
            for k, last in (("lo", 0), ("hi", 128)):
                uid = f"{whole}-{k}"
                base = o["subnet4"].rsplit(".", 1)[0]
                objs.append({"uid": uid, "name": f"{o['name']}-{k}", "type": "network",
                             "subnet4": f"{base}.{last}", "mask-length4": 25})
                halves.append(uid)
            add("clean", set(), [halves[0]], [h], ["s-https"])
            add("clean", set(), [halves[1]], [h], ["s-https"])
            add("redundant_unused", {"shadowed", "unused"}, [whole], [h], ["s-https"], hits=(0, None))
        elif cat == "expired":
            add(cat, {"expired"}, [net(24)], [host()], ["s-https"], time=["t-past"])
        elif cat == "disabled":
            add(cat, {"disabled"}, [net(24)], [host()], ["s-https"], enabled=False)
        elif cat == "unused":
            add(cat, {"unused"}, [net(24)], [host()], ["s-https"], hits=(0, None))
        elif cat == "stale":
            add(cat, {"unused"}, [net(24)], [host()], ["s-https"], hits=(7, old))
    add("any_any", {"any_any"}, [ANY], [ANY], [ANY])
    add("clean", set(), [ANY], [ANY], [ANY], action="drop", hits=(9000, recent))      # cleanup
    doc = {"exported_at": now.isoformat(),
           "access_layers": [{"name": "Network", "from": 1, "to": len(rules), "total": len(rules),
                              "rulebase": rules, "objects-dictionary": objs}]}
    return doc, labels


def _kappa(pairs: list[tuple[str, str]]) -> float:
    n = len(pairs)
    if not n:
        return 1.0
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def evaluate(doc: dict, labels: dict[str, dict]) -> dict[str, Any]:
    t0 = time.perf_counter()
    parsed = checkpoint.parse(doc)
    result = review(parsed)
    elapsed = time.perf_counter() - t0
    got = {e.rule_uid: e for e in result.register}

    per: dict[str, Counter] = {}
    band_pairs: list[tuple[str, str]] = []
    misses: list[dict] = []
    for uid, lab in labels.items():
        e = got.get(uid)
        found = {c.check for c in e.checks} if e else set()
        want = set(lab["checks"])
        for c in want | found:
            ctr = per.setdefault(c, Counter())
            ctr["tp" if c in want and c in found else "fn" if c in want else "fp"] += 1
        if want != found and len(misses) < 25:
            misses.append({"rule": uid, "category": lab.get("category"), "expected": sorted(want),
                           "got": sorted(found)})
        band_pairs.append((lab["band"], e.band if e and e.checks else "none"))

    def prf(c: Counter) -> dict:
        p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 1.0
        r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 1.0
        return {"precision": round(p, 4), "recall": round(r, 4),
                "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0, **{k: c[k] for k in ("tp", "fp", "fn")}}

    total = sum(per.values(), Counter())
    disagreements = Counter(f"{a}->{b}" for a, b in band_pairs if a != b)
    return {
        "rules": len(labels),
        "checks": {k: prf(v) for k, v in sorted(per.items())},
        "micro": prf(total),
        "severity": {"exact_agreement": round(sum(a == b for a, b in band_pairs) / len(band_pairs), 4),
                     "cohens_kappa": round(_kappa(band_pairs), 4),
                     "disagreements": dict(disagreements.most_common(10))},
        "seconds": round(elapsed, 3),
        "seconds_per_1k_rules": round(elapsed / max(1, len(labels)) * 1000, 3),
        "misses": misses,
    }


def gate(m: dict, g: dict = GATE) -> list[str]:
    fails = []
    if m["micro"]["precision"] < g["min_precision"]:
        fails.append(f"precision {m['micro']['precision']} < {g['min_precision']}")
    if m["micro"]["recall"] < g["min_recall"]:
        fails.append(f"recall {m['micro']['recall']} < {g['min_recall']}")
    for k, v in m["checks"].items():
        if v["tp"] + v["fn"] and v["recall"] < g["min_check_recall"]:
            fails.append(f"{k} recall {v['recall']} < {g['min_check_recall']}")
    if m["seconds_per_1k_rules"] > g["max_seconds_per_1k"]:
        fails.append(f"{m['seconds_per_1k_rules']} s per 1,000 rules > {g['max_seconds_per_1k']}")
    if g["min_band_agreement"] is not None and m["severity"]["exact_agreement"] < g["min_band_agreement"]:
        fails.append(f"band agreement {m['severity']['exact_agreement']} < {g['min_band_agreement']}")
    return fails


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rules", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--export")
    ap.add_argument("--labels")
    ap.add_argument("--gate", action="store_true")
    a = ap.parse_args(argv)
    if a.export:
        with open(a.export) as fh:
            doc = json.load(fh)
        with open(a.labels) as fh:
            labels = json.load(fh)
    else:
        doc, labels = generate(a.rules, a.seed)
    m = evaluate(doc, labels)
    m["gate"] = {"thresholds": GATE, "failures": gate(m)}
    print(json.dumps(m, indent=2))
    return 1 if a.gate and m["gate"]["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
