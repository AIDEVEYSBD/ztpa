"""Job handlers that ship with the product. Imported by the worker at start.

Each FRR job kind (ingest, engine build, review pipeline) registers here as it
is built; see docs/frr/TRACKER.md.
"""

from __future__ import annotations

from . import JobContext, handler


@handler("system.ping")
def ping(ctx: JobContext) -> dict:
    """Round-trip check used by the post-deploy smoke test: proves a worker is
    running, can reach the database and can record an outcome."""
    return {"pong": True, "worker": ctx.worker_id, "echo": ctx.payload.get("echo")}


# FRR intake: registering the module registers `export.ingest`.
from ..frr import agents, context, intake  # noqa: E402,F401
