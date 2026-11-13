# Network Policy Reviewer

## Start here (current state, November 2026)

This repository now holds two products on one codebase:

1. **Firewall Rule Review (FRR)** — the active work. A network owner uploads a firewall policy
   export (Check Point today); a deterministic engine reconstructs the effective policy per
   gateway and builds a rule-risk register (any-any, admin ports exposed, broad sources, unused,
   expired, disabled, shadowed — including by several rules together — and partly covered);
   agents draft a change package with exact `mgmt_cli` commands and rollback; the network owner
   validates it and a security approver decides (four eyes, server-enforced). Nothing is ever
   written to a firewall. Production-ready on **GCP** (Cloud Run, Cloud SQL, GCS, Vertex AI) and
   **Azure** (Container Apps, Flexible Server, Blob, AI Foundry), one cloud per deployment,
   bring-your-own-key supported.
2. **The original cross-tool console** (AlgoSec / Guardicore / Wiz, described from *What it does*
   below). Kept working; FRR deployments set `NPR_FRR_MODE=1`, which removes auto-approval and
   device push from it.

The rule that governs both: **the engine owns facts and math, the model owns language.** Model
output is schema-validated, may only cite what it was given, and falls back to labelled engine
text when the model is unavailable.

### Where things are

| You want to… | Read |
|---|---|
| Know what is done, partial, or waiting on a decision | [docs/frr/TRACKER.md](docs/frr/TRACKER.md) (status per backlog item, changelog, **Open decisions**) |
| Know what still has to be tested, and what unblocks it | [docs/frr/TEST-BACKLOG.md](docs/frr/TEST-BACKLOG.md) |
| Understand the system | [docs/frr/ARCHITECTURE.md](docs/frr/ARCHITECTURE.md); engine math in [docs/ENGINE.md](docs/ENGINE.md) |
| Deploy | [docs/frr/DEPLOY-GCP.md](docs/frr/DEPLOY-GCP.md), [docs/frr/DEPLOY-AZURE.md](docs/frr/DEPLOY-AZURE.md), [docs/frr/PRODUCTION-CHECKLIST.md](docs/frr/PRODUCTION-CHECKLIST.md) |
| Operate it (incidents, rotation, restore, scaling, pausing staging) | [docs/frr/RUNBOOK.md](docs/frr/RUNBOOK.md) |
| Run acceptance with users | [docs/frr/UAT.md](docs/frr/UAT.md) |
| See what went wrong before and how it was fixed | [docs/REMEDIATION-LOG.md](docs/REMEDIATION-LOG.md) |
| Sign-in (SSO, break-glass) | [docs/SSO.md](docs/SSO.md), [docs/BREAKGLASS.md](docs/BREAKGLASS.md) |

`docs/DEPLOY.md` (Render/Vercel/Neon) and `docs/DEPLOY-AZURE.md` (the older single-script
Azure demo) deploy the original console demo, not FRR.

### Run FRR locally

```bash
python tasks.py setup                                   # venv, backend + frontend deps, .env from .env.example

# Postgres 16 (pgvector image, as CI uses)
docker run -d --name npr-pg -p 55433:5432 -e POSTGRES_USER=npr -e POSTGRES_PASSWORD=nprdev \
  -e POSTGRES_DB=npr pgvector/pgvector:pg16

# Schema + least-privilege runtime role, exactly as the deploy's migrate job does
DATABASE_URL=postgresql://npr:nprdev@localhost:55433/npr NPR_APP_DB_PASSWORD=<choose one> \
  backend/.venv/bin/python db/migrate.py --bootstrap --ensure-app-role

# .env: DATABASE_URL=postgresql://npr:nprdev@localhost:55433/npr?sslmode=disable, NPR_FRR_MODE=1
python tasks.py dev                                     # API :8000 (runs the job worker inline) + UI :3000
```

Sign in locally with break-glass (`AUTH_LOCAL_LOGIN=true`, `BREAKGLASS_EMAIL`,
`BREAKGLASS_PASSWORD`; see docs/BREAKGLASS.md), grant yourself the `network_owner` and
`security_approver` duties under **Approvers**, then **Exports → upload**. A synthetic,
labelled Check Point export, dated now (exports older than 30 days are refused):

```bash
cd backend && .venv/bin/python -c "import json; from datetime import datetime, timezone; \
from src.frr.evals import generate; \
print(json.dumps(generate(400, exported_at=datetime.now(timezone.utc))[0]))" > ../sample-export.json
```

### Checks (all run in CI; run them before you push)

```bash
cd backend
.venv/bin/python -m pytest                                          # offline suite
NPR_TEST_DATABASE_URL=postgresql://npr_app:<password>@localhost:55433/npr \
  .venv/bin/python -m pytest                                        # + real-Postgres tests, as the runtime role
.venv/bin/python -m src.frr.evals --rules 2000 --gate               # precision/recall gate on the labelled rulebase
NPR_PROMPT_GATE_MIN_MODELS=2 .venv/bin/python -m src.frr.prompt_gate  # prompts/retrieval changes need a recorded eval
cd ../frontend && npm run typecheck && npm run lint && npm test && npm run build
```

Changing a prompt, retrieval or sampling setting changes the agent's fingerprint; record a
passing live evaluation on both clouds (`python -m src.frr.narrative_eval --items 20 --gate
--record`) or CI fails — see RUNBOOK "Change a prompt". `scripts/ui_walkthrough.py` drives every
FRR screen in headless Chromium and saves screenshots; `loadtest/run.py` is the load generator.

### Conventions

- Additive: features are built alongside, never removed; behaviour that conflicts goes behind a
  switch (`NPR_FRR_MODE`).
- Every FRR change updates `docs/frr/TRACKER.md` (and `TEST-BACKLOG.md` when it adds something
  to verify); remediation phases are logged in `docs/REMEDIATION-LOG.md`.
- Production-grade bar: measured at scale (the largest tested export is 110,000 rules) and under
  load before it is called done.
- The client is never named in code, docs, commits or resource names.

---


One unified, cross-tool view of network-policy risk — assembled from **AlgoSec**, **Guardicore**, and **Wiz**, then **explained**, **prioritized**, and **gated** by a local-first AI advisory layer. It surfaces attack paths that cross all three tools and that no single console can show — **within a stated scope**, set out under *What it does* below and in full in [docs/ENGINE.md §10](docs/ENGINE.md).

> **The one rule that governs the whole codebase:** the deterministic engine owns all **facts and math** (normalization, entity resolution, CIDR/subnet math, reachability, shadowing, effective policy, the delta of a proposed change). The AI/agent owns only **language and judgment** (explaining, ranking, classifying, drafting). **The model never computes reachability or subnet math — it calls deterministic tools and reasons over their structured results.**

---

## What it does

- **Consolidates** three tools into one canonical policy model + one reachability graph (the defensible IP).
- **Resolves identities** deterministically — IP is an attribute, not a key — so `appsrv-07` (Wiz) and `app-server-07` (AlgoSec/Guardicore) become one asset. *That merge is what lets a cross-tool path connect at all.* ⚠️ On the bundled fixture the engine **withholds** exactly that merge: none of the three exports declares a VPC / account / VRF, so `10.30.7.7` is an unscoped IP collision and it files a `manual_review` row rather than fusing two hosts on an ambiguous address. Refusing is the right answer — see [ENGINE.md §2](docs/ENGINE.md) — and it is a *second*, independent reason the demo shows no cross-tool path.
- **Finds risk deterministically**: over-permissive rules, CIDR overlap/redundancy, rule shadowing, and **cross-tool reachability paths** — each with an exact severity vector and a guardrail floor.
- **The shape of the headline finding:** `Internet → lb-public-01 → app-server-07 → internal-app → db-prod-01` — a path across **3 tools** into PCI/customer data, force-flagged critical. ⚠️ **That chain does not currently render on the bundled fixture** — the engine reports zero `cross_tool_path` findings there, deliberately, and the first bullet of the scope note below says why.

> **What the cross-tool path claim does — and does not — cover.** A differentiator is worth
> exactly what its scope is, so the scope is here rather than three documents away. The full
> list of engine simplifications is [ENGINE.md §10](docs/ENGINE.md).
>
> - **A chain that pivots *through* a subnet or group object is not reported — and on the
>   bundled demo that is every chain there is.** An abstract node may start or end a path but
>   never sit in the middle: reaching hosts inside a range does not let you originate as that
>   range, and CIDR-membership expansion — which would put the concrete hosts inside the range
>   in as the real pivots — is not built (ENGINE.md §10.2, Phase-3 scope). The rule is still in
>   force and still bites: the demo's `internal-app` (`10.40.0.0/16`) is refused as a pivot, and
>   `0.0.0.0/0 → 10.0.0.0/8 → app-segment → db-prod-01` is a complete internet-to-PCI chain of
>   real edges that the engine declines in full because every hop of it is a range. What the
>   fixture supplies instead is CONCRETE hosts inside those segments that a second tool
>   independently observes, so the two reported paths pivot through machines — **2** cross-tool
>   paths, walked hop by hop by `scripts/verify_engine.py` (`P5`), with the counterfactual that
>   deletes them asserted alongside. Data, not a relaxed rule. `docs/DEMO.md` beat 6 presents
>   them; the under-counting above is still the honest caveat to state beside the number.
> - **However the export spells the internet.** The search starts from *every* node the graph
>   classifies as internet — `0.0.0.0/0`, `any`, `ANY-EXTERNAL`, a named group that
>   dereferences to public space — because the entry set is derived from **resolved address
>   space** (`reachability.internet_entries`), not looked up by string. Four spellings of one
>   policy produce one finding, and the change gate reads the same definition.
> - **Deny rules do not subtract.** Effective policy is the union of allow edges; a
>   non-shadowed deny that ought to cut a path is invisible to reachability (§10.1).
> - **It does not yet hold at the size on the box.** On a realistic 5,000-rule multi-tool
>   export — the scale this product is sold on — path tracing took **~21 minutes**,
>   synchronously on the request path. The measured table and the shape that produced it are
>   in ENGINE.md §10; the bundled 27-rule demo and the generated scale fixture are both far
>   below the cliff, so a green `verify_engine.py` is not evidence about scale.

### The AI / agentic layer (local-first on Ollama)

> **[docs/FEATURES.md §1.5](docs/FEATURES.md) is the single source of truth for the capability list and count** — it is derived from `backend/src/tools_registry.py`, which is what the app actually gates per role. The table below mirrors it; if the two ever disagree, FEATURES.md is right.

| # | Capability | Type |
|---|---|---|
| 1 | Change-request triage (auto-approve vs escalate) | **agentic**, guardrailed, fail-closed |
| 2 | "Ask your network" assistant | **agentic** (tool-calling over the engine — see the provider caveat in [docs/AGENTS.md](docs/AGENTS.md)) |
| 3 | Remediation **fix-as-code**, re-simulated by the engine (§ below) | **agentic** (propose → re-simulate → revise) |
| 4 | Remediation **campaign** — worst-first, cumulative, drives criticals toward zero | **agentic** (composes #3) |
| 5 | Connector-authoring assist (design-time preview) | **agentic** (propose → normalize sample → revise) |
| 6 | Plain-English explanation of every finding | language |
| 7 | Root-cause grouping + worst-first ranking | judgment |
| 8 | Executive / PCI-DSS / Zero-Trust posture report | language |
| 9 | Change-intake extraction (free text → structured rule) | language → structure |
| 10 | Entity-resolution **suggestions** for human review (never auto-merge) | embeddings |

**On #3, precisely.** "Re-simulated by the engine" means the full analyzer suite is re-run on the modified record set (`run_all.reanalyze`) and the fix is accepted only if the target finding disappears **and no new *critical* appears**. New high/medium/low findings are not checked, the proof is against the snapshot as it stood when the fix was drafted and is **not re-run at push time**, and the deterministic fallback used when the model is unavailable is **conservative (removal-based)**, not scoped — it deletes the offending rule.

**On #5, precisely.** Paste a sample of an unknown tool's export → the model proposes a declarative `SourceProfile` (config, not code) → the engine checks it by actually normalizing that sample → a human reviews the result. This is a **design-time preview**: registering an approved profile and ingesting live data through it **is not implemented** in this build.

---

## Why local-first AI (Ollama)

Network topology + policy is the literal attack map of the company — the most sensitive data it owns. Running inference **locally on Ollama** means the topology **never leaves your infrastructure in that configuration**: a sales unlock for security-conscious clients, zero per-call cost on high-volume explanations, and a **rate-limit-free demo** (fully offline too, if you also point `DATABASE_URL` at a local Postgres — see the note below). The advisory layer is **provider-pluggable** — set `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (and `ADVISORY_PROVIDER`) to route the highest-stakes judgment to a hosted model instead. Same contracts, same fail-closed parsing, same guardrails.

> **Read the residency chip before you repeat that claim.** Two code paths make "data never leaves the host" false as a blanket statement, so the header carries a live **AI residency chip** (`Topbar.tsx`, bound to `/api/health` → `ai.active_provider`) that reads *"Local — stays on this host"*, *"Local — model unreachable"* or *"Hosted — data leaves this host"*. Check it, don't assume it.
>
> 1. **`ADVISORY_PROVIDER=auto` (the default) silently falls back to a hosted provider** when no local Ollama model is reachable (`settings.active_provider`). The shipped **Render blueprint pins `ADVISORY_PROVIDER=openai`** outright, because there is no Ollama on Render — so *the deployed demo sends finding text, rule text and asset names to OpenAI*.
> 2. **The system of record is Neon — cloud Postgres.** Rules, assets, findings and the audit log leave the host regardless of which model provider is active. Only the *inference* is local-first; the *storage* is not.

Model routing (default): **`qwen3-coder:30b` for both structured judgment and prose** — `settings.py` sets `OLLAMA_JUDGE_MODEL` and `OLLAMA_PROSE_MODEL` to the same tag — and `nomic-embed-text` for embeddings.

---

## Architecture

```
 Simulated exports          Deterministic engine (Python)            AI advisory (local Ollama)        Dashboard
 AlgoSec  ─┐                 normalize → resolve identity                explain · rank · classify         Next.js
 Guardicore ├─▶ normalizers ─▶ → graph → analyzers → severity ─▶ findings ─▶ remediate · report · ask ─▶  (EY-branded,
 Wiz      ─┘   (+ profiles)     reachability · change-delta              agent = tools, never math          React Flow)
                                        │                                          │
                                        ▼                                          ▼
                               Postgres (Neon, ztpa schema) ◀── system of record ──┘   audit_log
```

- **Backend** (`backend/`): FastAPI + the deterministic engine (`ipaddress`, `networkx`) + the provider-pluggable advisory/agent layer.
- **Database** (`db/schema.sql`): Neon Postgres, `ztpa` schema. Deterministic TEXT ids → re-running a snapshot UPSERTs identical rows.
- **Frontend** (`frontend/`): Next.js + Tailwind + Framer Motion + React Flow, EY brand (dark + light).

What's **real**: normalizer + canonical model, identity layer, graph, the **5** analyzers + severity + guardrails, change simulation + delta, the AI advisory/agent layer (live), persistence, the dashboard. What's **simulated**: the three tool connectors — there is **no upload path and no live API client**; the engine reads three fixed mock exports from `backend/data/mock/`, and `tasks.py demo` regenerates those files from `seed_demo.py` on every cold build. The staging *push* is simulated too (the conflict math it runs is real engine math).

> For the exact severity formula, sub-score lookup tables, reachability math, change-delta logic, determinism/ids, and the known simplifications, see **[docs/ENGINE.md](docs/ENGINE.md)**.

---

## Quickstart

All orchestration goes through `tasks.py` — a single cross-platform runner (Windows, macOS, Linux, WSL) that needs only a system **Python on PATH**; no `make`, no bash, no `psql`.

```bash
# 0. Prereqs: Python 3.11+, Node 18+, and Ollama running with these EXACT tags:
#      ollama pull qwen3-coder:30b      # judgment, prose and tool-calling
#      ollama pull nomic-embed-text     # embeddings (entity-merge suggestions)
#    The tag matters. The availability probe (settings.ollama_available) only checks
#    that Ollama is up and serving SOME model -- it never checks that these two are
#    the ones present. Pull a different tag and every call 404s at request time, so
#    the whole AI layer degrades to its deterministic fallback with nothing on screen
#    saying so. `ollama list` should show both names verbatim.
python tasks.py setup           # venv + backend deps + frontend deps; copies .env.example -> .env

# 1. Configure .env  (DATABASE_URL required; ANTHROPIC_API_KEY optional)
#    DATABASE_URL="postgresql://...neon.tech/neondb?sslmode=require&channel_binding=require"

# 2. Build the database + the demo snapshot
python tasks.py db              # apply ztpa schema + auth schema to Neon (via psycopg)
python tasks.py demo            # seed exports -> deterministic engine -> Postgres -> cache AI artifacts

# 3. Run (two terminals, or `python tasks.py dev` for both)
python tasks.py backend         # FastAPI  on http://127.0.0.1:8000
python tasks.py frontend        # dashboard on http://127.0.0.1:3000

# Regression-check the seeded demo dataset (golden acceptance checks)
python tasks.py verify

# Run the unit test suite (fully offline -- no database, no model)
python tasks.py test

# Run `python tasks.py help` to list every command.
```

> **What `verify` actually proves.** `backend/scripts/verify_engine.py` asserts the existence and exact values of specific expected findings **against the one 27-rule seeded demo fixture**, plus a byte-identical re-run. It is a golden regression check on that dataset — it is **not** a correctness proof on arbitrary input. `python tasks.py test` is the unit suite (`pytest`, driven by `pyproject.toml`'s `[tool.pytest.ini_options]`, the same invocation CI uses); that is where behaviour on inputs other than the demo is pinned.

A **cold run reproduces the demo identically** (deterministic ids → byte-identical rows; the dashboard reads the precomputed snapshot from Postgres; only the AI calls run live, and they fail closed).

---

## Repo layout

```
backend/
  src/
    models.py config.py settings.py ids.py db.py persist.py identity.py netaddr.py
    normalizers/   algosec.py guardicore.py wiz.py profile.py   # adapters + declarative engine
    graph/         build.py zones.py reachability.py
    analyzers/     over_permissive.py cidr_overlap.py shadowing.py path_trace.py
                   transport_exposure.py severity.py run_all.py
    advisory/      client.py explain.py rank.py classify_change.py remediation.py campaign.py
                   report.py intake.py entity_suggest.py authoring.py orchestrator.py prompts/
    change/        simulate.py requests.py
    agent/         tools.py assistant.py            # resolve/reachable/effective_policy/find_paths/...
  app/main.py                                       # FastAPI
  scripts/         seed_demo.py precompute.py precompute_ai.py verify_engine.py
frontend/          Next.js dashboard (app/, components/, lib/)
db/                schema.sql auth_schema.sql migrate.py
docs/              ENGINE.md       # core logic, calculations & math (the deterministic engine)
                   FEATURES.md     # the capability catalog -- source of truth for the list + count
                   AGENTS.md       # what each agent does, and which provider can actually run it
                   SSO.md          # AutoX OIDC integration + the app-role model
                   DEPLOY.md       # Render + Vercel + Neon deployment
                   REMEDIATION-LOG.md        # audit findings and how each was fixed
                   DEMO.md         # the ten-minute demo script, beat by beat
tasks.py  README.md                # tasks.py = cross-platform runner (no make required)
```

Added for FRR and production:

```
backend/src/frr/        rulebase review, NAT, change package, workflow (owner/approver), agents,
                        knowledge base, context data (CMDB/flows), intake, evals, prompt gate,
                        prompts/ (versioned prompts + eval-ledger.json)
backend/src/jobs/       Postgres job queue (SKIP LOCKED, leases, retries) and the worker
backend/src/            storage.py (file/gs/az), snapshot_artifacts.py, ratelimit.py, telemetry.py,
                        preflight.py, smoke.py
backend/app/            exports_api, uploads_api, register_api, packages_api, frr_api,
                        feedback_api, context_api, jobs_api, limits
db/migrations/          numbered migrations (0008 onwards are the production platform and FRR)
infra/gcp, infra/azure  Terraform per cloud (+ .github/workflows/deploy-*.yml)
scripts/azure/          start-job.sh / wait-job.sh for Container Apps jobs
scripts/ui_walkthrough.py, loadtest/run.py
docs/frr/               tracker, test backlog, architecture, deploy guides, runbook, UAT
```

---

## Security note

If a `DATABASE_URL` was ever shared in plaintext (chat, ticket), **treat it as compromised** and rotate the credential in the Neon console, then update `.env`. Secrets live only in the local, git-ignored `.env` — never in `.env.example`, never committed.
