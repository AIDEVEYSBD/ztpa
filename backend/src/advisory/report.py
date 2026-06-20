"""Capability #6 -- executive / compliance posture report (language).

Summarizes the deterministic snapshot for leadership + auditors and maps it to
PCI-DSS / Zero-Trust maturity language. Reasons only from the computed summary."""

from __future__ import annotations

import json
from collections import Counter

from ..config import SENSITIVE_TAGS
from ..models import Asset, Finding
from .client import complete

_PROMPT = (
    "You are writing an executive network-security posture report for leadership and auditors. "
    "Given the JSON summary of deterministic findings, write Markdown with three short sections: "
    "## Executive summary (3-4 sentences), ## Top risks (priority order, terse), and "
    "## Compliance posture (a brief PCI-DSS and Zero-Trust maturity note). "
    "Reason ONLY from the provided facts; do not invent numbers. No preamble."
)


def build_summary(findings: list[Finding], assets: list[Asset]) -> dict:
    bands = Counter(f.severity_band for f in findings)
    types = Counter(f.type for f in findings)
    sensitive = sorted(a.asset_key for a in assets if set(a.tags) & SENSITIVE_TAGS)
    paths = [f for f in findings if f.type == "cross_tool_path"]
    internet_to_regulated = any(
        f.type == "cross_tool_path" and f.signals.get("reaches_sensitive") for f in paths
    ) or any(
        f.type == "over_permissive" and f.forced_critical and set(f.signals.get("dest_tags", [])) & SENSITIVE_TAGS
        for f in findings
    )
    return {
        "total_findings": len(findings),
        "by_band": dict(bands),
        "by_type": dict(types),
        "forced_critical": sum(1 for f in findings if f.forced_critical),
        "sensitive_assets": sensitive,
        "cross_tool_paths": len(paths),
        "internet_reaches_regulated_data": internet_to_regulated,
        "top_findings": [{"title": f.title, "band": f.severity_band, "severity": f.severity}
                         for f in findings[:5]],
    }


def _fallback(summary: dict) -> str:
    b = summary["by_band"]
    return (
        "## Executive summary\n"
        f"The current snapshot surfaced {summary['total_findings']} policy risks across the estate "
        f"({b.get('critical', 0)} critical, {b.get('high', 0)} high, {b.get('medium', 0)} medium, "
        f"{b.get('low', 0)} low). "
        + ("A cross-tool attack path reaches regulated data from the internet, which no single tool reveals. "
           if summary["internet_reaches_regulated_data"] else "")
        + f"{summary['forced_critical']} findings are categorically unacceptable and were force-flagged critical.\n\n"
        "## Top risks\n"
        + "".join(f"- {t['title']} ({t['band']})\n" for t in summary["top_findings"])
        + "\n## Compliance posture\n"
        f"Regulated assets in scope: {', '.join(summary['sensitive_assets']) or 'none tagged'}. "
        "Internet-exposed access to PCI/customer-data assets is a PCI-DSS segmentation gap (Req. 1) and a "
        "Zero-Trust violation; closing the flagged criticals moves the estate toward an enforced-segmentation "
        "maturity level."
    )


def generate_report(findings: list[Finding], assets: list[Asset]) -> dict:
    summary = build_summary(findings, assets)
    r = complete(system=_PROMPT, user=json.dumps(summary, indent=2), role="prose", temperature=0.3)
    text = r.text.strip() if (r.ok and r.text.strip()) else _fallback(summary)
    return {"report_markdown": text, "summary": summary,
            "by": f"{r.provider}:{r.model}" if r.ok and r.text.strip() else "engine_fallback"}
