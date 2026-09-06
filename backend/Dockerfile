# syntax=docker/dockerfile:1

# =============================================================================
# Network Policy Reviewer — backend image
#
# THE BUILD CONTEXT IS THE REPO ROOT, not backend/:
#
#     docker build --platform linux/amd64 -f backend/Dockerfile -t npr-backend .
#
# because one image has to carry both halves of the deploy. The same image runs
# the API and the schema migration, so `db/` ships alongside `backend/`:
#
#     the API          uvicorn app.main:app --host 0.0.0.0 --port 8000   (CMD)
#     the migration    python /app/db/migrate.py
#     first-run seed   python /app/backend/scripts/seed_demo.py
#                      python /app/backend/scripts/precompute.py
#
# The layout inside the image mirrors the repo exactly — /app IS the repo root —
# because three separate pieces of code locate their neighbours by walking up
# from their own __file__, and a flattened layout silently breaks all three:
#
#     backend/src/settings.py   REPO_ROOT = parents[2]      must be /app
#     backend/app/main.py       puts parents[1] on sys.path  -> /app/backend
#     db/migrate.py             reads schema.sql + migrations/ beside itself
#
# Nothing secret is baked in at any stage. DATABASE_URL, NPR_PROXY_SECRET and
# any model-provider key arrive from the platform at run time, never from a
# build arg (a build arg is recoverable from `docker history`).
# =============================================================================


# --------------------------------------------------------------------------
# Stage 1 — build the dependency tree
# --------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Install into a virtualenv rather than the system site-packages. The point is
# not isolation — the container is already isolated — it is that the entire
# dependency tree becomes ONE directory to copy forward. Anything pip needed on
# the way (wheel caches, a build toolchain a source distribution might have
# pulled in, scratch under /tmp) stays in this stage and cannot reach the image
# that actually gets published.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Only the requirements file, so this layer is cached across every source edit:
# the dependency install is by far the slowest step, and application code
# changes far more often than the 15 lines of requirements.txt.
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /tmp/requirements.txt


# --------------------------------------------------------------------------
# Stage 2 — the runtime image
# --------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv

# A fixed, high, system uid/gid rather than whatever the next free number
# happens to be, so file ownership is the same in every build and on any volume
# this image is ever handed.
RUN groupadd --system --gid 10001 npr \
 && useradd --system --uid 10001 --gid 10001 --home-dir /app --no-create-home npr

WORKDIR /app

# Source stays owned by root and is not writable by the user the service runs
# as: a process that is compromised at run time should not be able to rewrite
# the code it will execute after the next restart.
COPY --chown=root:root backend/app     /app/backend/app
COPY --chown=root:root backend/src     /app/backend/src
COPY --chown=root:root backend/scripts /app/backend/scripts
COPY --chown=root:root backend/data    /app/backend/data
COPY --chown=root:root db              /app/db

# ...with exactly one exception. POST /api/scenario regenerates the three
# simulated tool exports in place (src/scenarios.py::_write writes a sibling
# .tmp and os.replace()s it, which requires write on the DIRECTORY, not just on
# the files). backend/data is the only path the service writes, so it is the
# only path the service owns.
RUN chown -R npr:npr /app/backend/data

# cwd=/app/backend is what makes `uvicorn app.main:app` resolve `app.main` and
# then `from src...` exactly as it does in development. This is the working
# directory the CMD below inherits, and the reason it is set here rather than
# passed per-command.
WORKDIR /app/backend

USER npr

EXPOSE 8000

# LIVENESS — deliberately /api/live and never /api/health.
#
# /api/health is the READINESS and honesty endpoint: it answers 503 whenever the
# database is unreachable, the active snapshot is missing, or the engine came
# back degraded. Pointing a restart-triggering probe at it means that every time
# Postgres is briefly away — a failover, a maintenance window, a sleeping
# sandbox server — the platform kills and restarts a process that is working
# perfectly, in a loop, and the restart cannot fix the thing that is broken.
# /api/live touches nothing but the process itself, which is the actual question
# a liveness probe is asking.
#
# Implemented with the interpreter that is already here instead of curl, which
# python:3.12-slim does not ship: adding it would mean an apt layer and another
# package to keep patched, to make one HTTP request.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/live', timeout=4).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
