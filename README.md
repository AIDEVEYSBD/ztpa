# ZeroTrust Policy Advisor

One unified, cross-tool view of network-policy risk — assembled from **AlgoSec**, **Guardicore**, and **Wiz**, then **explained**, **prioritized**, and **gated** by a local-first AI advisory layer. It surfaces the attack path that crosses all three tools and that no single console can show.

> **The one rule that governs the whole codebase:** the deterministic engine owns all **facts and math** (normalization, entity resolution, CIDR/subnet math, reachability, shadowing, effective policy, the delta of a proposed change). The AI/agent owns only **language and judgment** (explaining, ranking, classifying, drafting). **The model never computes reachability or subnet math — it calls deterministic tools and reasons over their structured results.**

---

## What it does

- **Consolidates** three tools into one canonical policy model + one reachability graph (the defensible IP).
- **Resolves identities** deterministically — IP is an attribute, not a key — so `appsrv-07` (Wiz) and `app-server-07` (AlgoSec/Guardicore) become one asset. *That merge is what makes the cross-tool path connect.*
- **Finds risk deterministically**: over-permissive rules, CIDR overlap/redundancy, rule shadowing, and **cross-tool reachability paths** — each with an exact severity vector and a guardrail floor.
- **The money shot:** `Internet → lb-public-01 → app-server-07 → internal-app → db-prod-01` — a path across **3 tools** into PCI/customer data, force-flagged critical.

### The AI / agentic layer (8 capabilities, local-first on Ollama)

| # | Capability | Type |
|---|---|---|
| 1 | Change-request triage (auto-approve vs escalate) | agentic, guardrailed, fail-closed |
| 2 | "Ask your network" assistant | agentic (tool-calling over the engine) |
| 3 | Plain-English explanation of every finding | language |
| 4 | Root-cause grouping + worst-first ranking | judgment |
| 5 | Remediation **fix-as-code**, re-simulated by the engine to *prove* it resolves | language + judgment |
| 6 | Executive / PCI-DSS / Zero-Trust posture report | language |
| 7 | Change-intake extraction (free text → structured rule) | language → structure |
| 8 | Entity-resolution **suggestions** for human review (never auto-merge) | embeddings |

Plus a **dynamic connector authoring** assist: paste a sample of any tool's export → the model proposes a declarative `SourceProfile` (config, not code) → the engine validates it by actually normalizing the sample → a human approves. *Bring-your-own source without writing a normalizer.*

---

## Why local-first AI (Ollama)

Network topology + policy is the literal attack map of the company — the most sensitive data it owns. Running inference **locally on Ollama** means that data **never leaves the host**: a sales unlock for security-conscious clients, zero per-call cost on high-volume explanations, and a fully **offline, rate-limit-free demo**. The advisory layer is **provider-pluggable** — set `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (and `ADVISORY_PROVIDER`) to route the highest-stakes judgment to a hosted model instead. Same contracts, same fail-closed parsing, same guardrails.

Model routing (default): `qwen3-coder:30b` for structured judgment + tool-calling, `gemma4:26b` for prose, `nomic-embed-text` for embeddings.

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

What's **real**: normalizer + canonical model, identity layer, graph, the 4 analyzers + severity + guardrails, change simulation + delta, the AI advisory/agent layer (live), persistence, the dashboard. What's **simulated**: the three tool connectors (we ingest realistic mock exports representative of each tool — never live integration).

> For the exact severity formula, sub-score lookup tables, reachability math, change-delta logic, determinism/ids, and the known simplifications, see **[docs/ENGINE.md](docs/ENGINE.md)**.

---

## Quickstart

All orchestration goes through `tasks.py` — a single cross-platform runner (Windows, macOS, Linux, WSL) that needs only a system **Python on PATH**; no `make`, no bash, no `psql`.

```bash
# 0. Prereqs: Python 3.11+, Node 18+, Ollama running with qwen3-coder + gemma4 + nomic-embed-text.
python tasks.py setup           # venv + backend deps + frontend deps; copies .env.example -> .env

# 1. Configure .env  (DATABASE_URL required; ANTHROPIC_API_KEY optional)
#    DATABASE_URL="postgresql://...neon.tech/neondb?sslmode=require&channel_binding=require"

# 2. Build the database + the demo snapshot
python tasks.py db              # apply ztpa schema + auth schema to Neon (via psycopg)
python tasks.py demo            # seed exports -> deterministic engine -> Postgres -> cache AI artifacts

# 3. Run (two terminals, or `python tasks.py dev` for both)
python tasks.py backend         # FastAPI  on http://127.0.0.1:8000
python tasks.py frontend        # dashboard on http://127.0.0.1:3000

# Optional: prove the engine meets every acceptance criterion
python tasks.py verify

# Run `python tasks.py help` to list every command.
```

A **cold run reproduces the demo identically** (deterministic ids → byte-identical rows; the dashboard reads the precomputed snapshot from Postgres; only the AI calls run live, and they fail closed).

---

## Repo layout

```
backend/
  src/
    models.py config.py settings.py ids.py db.py persist.py identity.py
    normalizers/   algosec.py guardicore.py wiz.py profile.py   # adapters + declarative engine
    graph/         build.py zones.py reachability.py
    analyzers/     over_permissive.py cidr_overlap.py shadowing.py path_trace.py severity.py run_all.py
    advisory/      client.py explain.py rank.py classify_change.py remediation.py report.py intake.py
                   entity_suggest.py authoring.py prompts/
    change/        simulate.py requests.py
    agent/         tools.py assistant.py            # resolve/reachable/effective_policy/find_paths/...
  app/main.py                                       # FastAPI
  scripts/         seed_demo.py precompute.py precompute_ai.py verify_engine.py
frontend/          Next.js dashboard (app/, components/, lib/)
db/                schema.sql auth_schema.sql migrate.py
docs/              ENGINE.md       # core logic, calculations & math (the deterministic engine)
tasks.py  DEMO.md  README.md      # tasks.py = cross-platform runner (no make required)
```

---

## Security note

If a `DATABASE_URL` was ever shared in plaintext (chat, ticket), **treat it as compromised** and rotate the credential in the Neon console, then update `.env`. Secrets live only in the local, git-ignored `.env` — never in `.env.example`, never committed.
