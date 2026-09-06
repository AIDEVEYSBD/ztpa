# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Network Policy Reviewer — frontend (Next.js 14 App Router).
#
# This image is not just a UI: frontend/middleware.ts is the AUTHORIZATION
# PROXY in front of FastAPI. It strips every client-supplied x-npr-* header,
# then sets x-npr-role / x-npr-email / x-npr-sub and signs them with
# x-npr-proxy-secret. Everything below is arranged so that no part of that
# trust chain is baked into the image.
#
# Build:  docker build --platform linux/amd64 -t npr-frontend:test .   (context = frontend/)
# Run:    docker run -p 3000:3000 -e AUTH_SECRET=... -e NPR_PROXY_SECRET=... \
#                    -e BACKEND_URL=http://npr-backend/ npr-frontend:test
#
# ===========================================================================
# ENVIRONMENT: WHAT IS NEEDED WHEN
# ===========================================================================
# Verified against this codebase, not assumed. Next 14 inlines only NEXT_PUBLIC_*
# and NODE_ENV into bundles; this app defines NO NEXT_PUBLIC_* variables, so no
# secret can reach client JavaScript. Confirmed by inspecting the compiled edge
# bundle: .next/server/middleware.js still contains the literal text
# `process.env.NPR_PROXY_SECRET?.trim()` and `process.env.AUTH_SECRET`, i.e. a
# real runtime lookup, not a substituted value.
#
#   BUILD TIME (`next build`)
#     NODE_ENV=production ....... set by next build itself.
#     BACKEND_URL ............... STRUCTURALLY build-time, and NOT a secret.
#                                 next.config.mjs's rewrites() is evaluated during
#                                 the build and its destination is frozen into
#                                 .next/routes-manifest.json; the production
#                                 server reads that manifest and never re-runs
#                                 rewrites(). We therefore build with a SENTINEL
#                                 host and substitute the real value at container
#                                 start (see the entrypoint below), which keeps
#                                 BACKEND_URL runtime-configurable as the shared
#                                 contract requires. One image, any environment.
#     (nothing else) ............ the build runs with an otherwise EMPTY
#                                 environment — no .env is copied in (see
#                                 .dockerignore) and none is needed.
#
#   RUN TIME — required
#     AUTH_SECRET ............... SECRET. Encrypts/signs the Auth.js JWT session
#                                 cookie. The cookie is what middleware.ts turns
#                                 into x-npr-role, so forging it is forging an
#                                 admin. 32+ random bytes, per environment.
#     NPR_PROXY_SECRET .......... SECRET. Must be byte-identical to the backend's
#                                 NPR_PROXY_SECRET. This is the value that stops
#                                 anyone who can reach the backend URL from
#                                 sending `x-npr-role: admin`. Both sides .strip()
#                                 it, so a trailing newline is tolerated — but set
#                                 it on BOTH containers or the check is disabled.
#     BACKEND_URL ............... e.g. http://npr-backend  (internal ingress).
#                                 Read at container start by the entrypoint.
#     DATABASE_URL .............. SECRET. Auth.js user store + SSO provisioning.
#
#   RUN TIME — required once SSO is on
#     SSO_CLIENT_ID ............. not secret; its presence is what ENABLES SSO
#                                 and DISABLES the legacy password/magic-link
#                                 providers (lib/sso.ts: ssoEnabled()).
#     SSO_CLIENT_SECRET ......... SECRET (omit for a public/PKCE client).
#     SSO_ISSUER, SSO_RESOURCE, SSO_SCOPE, SSO_SESSION_MAX_AGE,
#     SSO_POST_LOGOUT_REDIRECT_URI, SSO_ROLE_MAP, SSO_TOKEN_AUTH_METHOD
#                                 all optional overrides, all read at runtime.
#
#   RUN TIME — optional
#     APP_URL ................... canonical origin for magic-link/invite URLs.
#                                 Leave unset to derive from the request host.
#     AUTH_TRUST_HOST ........... REDUNDANT here: auth.config.ts hardcodes
#                                 `trustHost: true`, so Auth.js already trusts the
#                                 X-Forwarded-* headers Container Apps' ingress
#                                 sets. Harmless to set; not required.
#     AUTH_LOCAL_LOGIN, RESEND_API_KEY, EMAIL_FROM
#                                 legacy local-login paths only.
#
# NO SECRET IS BAKED. Nothing above is an ARG or an ENV in the final stage;
# every secret arrives from the platform at run time.
# ===========================================================================

# ---------------------------------------------------------------------------
# Stage 1 — deps: install node_modules from the committed lockfile only.
# Separated so a source-only edit does not re-run npm ci.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS deps
# Next's SWC binary is glibc-linked; libc6-compat is the musl shim it needs.
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---------------------------------------------------------------------------
# Stage 2 — builder: compile the app.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS builder
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# The sentinel discussed at the top. It must parse as a URL for the build to
# accept it as a rewrite destination; `.invalid` is the RFC 2606 reserved TLD, so
# if the runtime substitution ever fails to happen the proxy fails loudly with
# DNS NXDOMAIN instead of quietly reaching some real host.
ARG BACKEND_URL_SENTINEL=http://npr-backend.invalid
ENV BACKEND_URL=${BACKEND_URL_SENTINEL}

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# public/ does not exist in this repo today. Create it so the runtime COPY below
# is unconditional and keeps working if one is added later.
RUN mkdir -p public && npm run build

# ---------------------------------------------------------------------------
# Stage 3 — runner: the traced standalone server and nothing else.
# No npm, no lockfile, no source, no dev dependencies.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
# The standalone server binds HOSTNAME; without 0.0.0.0 it listens on localhost
# only and the container answers nothing from outside.
ENV HOSTNAME=0.0.0.0
# Not a secret — the sentinel baked into routes-manifest.json, kept here so the
# entrypoint knows what to replace.
ENV NPR_BACKEND_SENTINEL=http://npr-backend.invalid

RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 --ingroup nodejs nextjs

# Copied as root and left root-owned: the runtime user can execute the app but
# cannot modify it. Only the two paths that genuinely need writing are chowned
# below.
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# routes-manifest.json is REGENERATED from an immutable template on every start,
# so the entrypoint is idempotent: a restart that reuses the container's writable
# layer (docker restart, and anything that does not start from a fresh layer)
# would otherwise find the sentinel already replaced and refuse to boot.
# The template stays root-owned and read-only; only the live manifest and Next's
# runtime cache are writable by the app user.
RUN cp .next/routes-manifest.json .next/routes-manifest.template.json \
 && chown nextjs:nodejs .next/routes-manifest.json \
 && mkdir -p .next/cache \
 && chown -R nextjs:nodejs .next/cache

# Substitute the real backend URL into the frozen rewrite destination, then hand
# PID 1 to the server. Written as a file rather than a long CMD so the failure
# modes can be explicit: a missing sentinel is a hard error, because silently
# starting with http://npr-backend.invalid would make every API call fail with a
# confusing DNS error much later.
# The entrypoint is a COMMITTED FILE, not a Dockerfile heredoc. `COPY <<EOF` is
# BuildKit-only syntax: local `docker build` enables BuildKit by default so it
# builds fine on a laptop, but `az acr build` uses the classic builder and
# rejects it -- so the heredoc form would have failed the deploy at image-build
# time, on a machine nobody was watching. See frontend/docker-entrypoint.sh for
# why the substitution is needed at all.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh

USER nextjs
EXPOSE 3000

# "/" is a public route (auth.config.ts isPublicPath), so this probes the real
# request path without needing a session. Container Apps uses its own probes;
# this is for docker/compose parity.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "server.js"]
