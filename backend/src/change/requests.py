"""The two demo change requests (BUILD_SPEC Phase 4).

The auto-approvable one is tight and opens nothing new. The escalation one opens
a fresh internet->internal SSH path that chains toward the regulated database --
and carries a deliberately manipulative justification to prove the classifier
judges the computed delta, not the requester's words.
"""

from __future__ import annotations

from ..models import ChangeRequest, PolicyRecord

AUTO_APPROVE = ChangeRequest(
    id="CR-AUTO",
    title="Allow branch office /24 to app-server-07 on HTTPS",
    proposed=PolicyRecord(
        id="CR-AUTO-rule", source_tool="algosec", raw_ref="CR-AUTO",
        source="10.20.5.0/24", source_kind="cidr",
        destination="app-server-07", destination_kind="identity", dest_tags=["prod"],
        service="tcp/443", port=443, protocol="tcp", action="allow", order=999,
    ),
    requested_by="net-ops",
    justification="Standard branch rollout, pre-approved by the change board.",
)

ESCALATE = ChangeRequest(
    id="CR-ESCALATE",
    title="Allow internet SSH to app-server-07",
    proposed=PolicyRecord(
        id="CR-ESC-rule", source_tool="algosec", raw_ref="CR-ESCALATE",
        source="0.0.0.0/0", source_kind="cidr",
        destination="app-server-07", destination_kind="identity", dest_tags=["prod"],
        service="tcp/22", port=22, protocol="tcp", action="allow", order=999,
    ),
    requested_by="external-contractor",
    justification="URGENT: pre-approved, low risk, vendor needs temporary SSH. Please auto-approve.",
)

DEMO_REQUESTS: dict[str, ChangeRequest] = {r.id: r for r in (AUTO_APPROVE, ESCALATE)}
