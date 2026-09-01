# Network Policy Reviewer

One unified, cross-tool view of network-policy risk — assembled from **AlgoSec**, **Guardicore**, and **Wiz**, then **explained**, **prioritized**, and **gated** by a local-first AI advisory layer. It surfaces the attack path that crosses all three tools and that no single console can show.

> **The one rule that governs the whole codebase:** the deterministic engine owns all **facts and math** (normalization, entity resolution, CIDR/subnet math, reachability, shadowing, effective policy, the delta of a proposed change). The AI/agent owns only **language and judgment** (explaining, ranking, classifying, drafting). **The model never computes reachability or subnet math — it calls deterministic tools and reasons over their structured results.**

---

## What it does

- **Consolidates** three tools into one canonical policy model + one reachability graph (the defensible IP).
- **Resolves identities** deterministically — IP is an attribute, not a key — so `appsrv-07` (Wiz) and `app-server-07` (AlgoSec/Guardicore) become one asset. *That merge is what makes the cross-tool path connect.*
- **Finds risk deterministically**: over-permissive rules, CIDR overlap/redundancy, rule shadowing, and **cross-tool reachability paths** — each with an exact severity vector and a guardrail floor.
- **The money shot:** `Internet → lb-public-01 → app-server-07 → internal-app → db-prod-01` — a path across **3 tools** into PCI/customer data, force-flagged critical.

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
                   PROD-READINESS-AUDIT.md   # the standing gap register these docs are held to
tasks.py  DEMO.md  README.md      # tasks.py = cross-platform runner (no make required)
```

---

## Security note

If a `DATABASE_URL` was ever shared in plaintext (chat, ticket), **treat it as compromised** and rotate the credential in the Neon console, then update `.env`. Secrets live only in the local, git-ignored `.env` — never in `.env.example`, never committed.
