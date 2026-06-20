"""Cross-tool path tracing: flag reachability chains that reach a sensitive
asset and span >= 2 tools. The differentiator no single tool can show."""

from __future__ import annotations

import networkx as nx

from ..config import SENSITIVE_TAGS
from ..graph.reachability import cross_tool_paths
from ..models import Finding
from .severity import band, score_cross_tool_path


def analyze(g: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []
    for p in cross_tool_paths(g, SENSITIVE_TAGS):
        sc = score_cross_tool_path(p)
        entry_display, terminal_display = p["display_path"][0], p["display_path"][-1]
        findings.append(Finding(
            id=f"cross_tool_path|{'>'.join(p['path'])}",
            type="cross_tool_path",
            title=f"Cross-tool path: {entry_display} can reach {terminal_display} "
                  f"through {len(p['tools'])} tools",
            severity=sc["severity"],
            severity_band="critical" if sc["forced_critical"] else band(sc["severity"]),
            forced_critical=sc["forced_critical"],
            signals={
                "path": p["path"], "display_path": p["display_path"], "hops": p["hops"],
                "hops_tools": p["hops_tools"], "tools": p["tools"],
                "reaches_sensitive": sc["reaches_sensitive"], "boundary": p["boundary"],
                "boundary_crossed": p["boundary_crossed"], "terminal": p["terminal"],
                "terminal_tags": p["terminal_tags"], "terminal_service": p["terminal_service"],
                "entry": p["entry"], "severity_vector": sc["vector"], "port_class": sc["port_class"],
            },
            involved=list(p["path"]),
            raw_refs=[h["ref"] for h in p["hops"]],
            source_tools=list(p["tools"]),
        ))
    return findings
