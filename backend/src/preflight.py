"""`python -m src.preflight`: refuse, with exit code 1, a production process
configured so it would fail open. Run by the image's CMD before the server
starts, so a misconfigured revision exits non-zero and the platform reports a
failed deployment -- uvicorn's supervisor exits 0 when a worker refuses to boot.
The API's lifespan runs the same check again as a second layer.
"""

from __future__ import annotations

import json
import sys

from . import settings


def main() -> int:
    errors = settings.production_startup_errors()
    for e in errors:
        print(json.dumps({"level": "CRITICAL", "event": "startup_refused", "reason": e,
                          "environment": settings.environment()}), file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
