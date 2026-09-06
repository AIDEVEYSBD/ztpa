#!/bin/sh
# Substitute the real backend URL into the frozen rewrite destination, then hand
# PID 1 to the server.
#
# WHY THIS EXISTS. `next.config.mjs` builds its `/api/*` rewrite destination from
# `process.env.BACKEND_URL`. With `output: "standalone"` that config is evaluated
# during `next build`, and the result is FROZEN into `.next/routes-manifest.json`
# -- so unlike a normal `next start`, the variable is a BUILD-time input, not a
# runtime one. Baking a real backend URL into the image would make the image
# environment-specific (and one built for staging would silently proxy to staging
# from production), so the build uses a sentinel and this script swaps it at boot.
#
# A missing sentinel is a HARD ERROR rather than a warning: starting anyway would
# leave every /api call resolving a placeholder host, surfacing much later as a
# confusing DNS failure inside a request rather than as a startup failure.
#
# Kept as a committed file, not a Dockerfile heredoc: `COPY <<EOF` is BuildKit
# syntax. Local `docker build` enables BuildKit by default so it looked fine,
# but `az acr build` runs the classic builder and rejects it -- which would have
# failed the deploy at image-build time.
set -eu

: "${BACKEND_URL:=http://127.0.0.1:8000}"
export BACKEND_URL

# Always rebuild the live manifest from the pristine template, so a restarted or
# re-configured container converges rather than compounding an earlier edit.
node -e '
  const fs = require("fs");
  const template = "/app/.next/routes-manifest.template.json";
  const live = "/app/.next/routes-manifest.json";
  const sentinel = process.env.NPR_BACKEND_SENTINEL;
  const backend = process.env.BACKEND_URL.replace(/\/+$/, "");
  const before = fs.readFileSync(template, "utf8");
  if (!before.includes(sentinel)) {
    console.error("[entrypoint] FATAL: sentinel " + sentinel + " not found in " + template +
      " — the /api proxy destination cannot be set. Refusing to start.");
    process.exit(1);
  }
  fs.writeFileSync(live, before.split(sentinel).join(backend));
  console.log("[entrypoint] /api/* proxies to " + backend);
'

exec "$@"
