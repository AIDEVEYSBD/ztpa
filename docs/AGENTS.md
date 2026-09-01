# The AI / Agentic layer — what the agents do and how they work

This document explains the agentic capabilities of the Network Policy Reviewer: what
each one does, how it works technically, and — the question that usually comes first —
**which model runs them and whether they need an OpenAI key.**

> The one rule that governs everything below: the **deterministic engine owns all facts
> and math** (normalization, reachability, subnet math, which findings exist, the delta
> of a change). The **model owns only language and judgment**. An *agent* is the model
> **driving** the engine in a loop — proposing, calling a deterministic tool, observing
> the engine's answer, and revising — but the engine is always the judge. The model
> never computes reachability; it asks the engine and reasons over the structured result.

---

## Which model runs the agents? (OpenAI key or not)

Every agent talks to one **provider-pluggable client** (`advisory/client.py`). The
provider is resolved per call by `settings.active_provider()`:

| `ADVISORY_PROVIDER` | What runs the agents |
|---|---|
| `auto` (default) | A **local Ollama** model if one is reachable and has a model pulled; **otherwise the OpenAI API** (if `OPENAI_API_KEY` is set); otherwise Anthropic (if `ANTHROPIC_API_KEY` is set). |
| `ollama` | Always the local model. |
| `openai` | Always the OpenAI API (`OPENAI_MODEL`, default `gpt-4o`). |
| `anthropic` | Always the Anthropic API (`ANTHROPIC_MODEL`). |

So, to answer the question directly:

- **If you run a local model (Ollama), the agents use that** — no key, no per-call cost, and
  the topology and policy text stay on the host *for the inference step*. This is the default
  when Ollama is up. (The **system of record is still cloud Postgres (Neon)** unless you point
  `DATABASE_URL` at a local one, so "nothing leaves the host" is a claim about inference, not
  about the whole system.)
- **If there is no local model, the agents use the OpenAI API key** (under `auto`, OpenAI
  is preferred over Anthropic). Set `ADVISORY_PROVIDER=openai` + `OPENAI_API_KEY` to force it.
- ⚠️ **The fallback under `auto` is silent, and the shipped Render blueprint pins
  `ADVISORY_PROVIDER=openai`.** Nothing in the flow asks before sending finding text, rule
  text and asset names to a hosted provider. The header's **AI residency chip** (bound to
  `/api/health` → `ai.active_provider` / `ai.data_residency`) is how you tell which one is
  live; check it before repeating a residency claim to a client.
- ⚠️ **The availability probe checks that Ollama serves *some* model, not the right one.**
  `settings.ollama_available()` is `bool(models)` over `/api/tags`. Pull `qwen3-coder:7b`
  instead of `qwen3-coder:30b` and `auto` still routes to Ollama, every call 404s at request
  time, and every capability degrades to its deterministic fallback with nothing on screen
  saying why. The tags must match `OLLAMA_JUDGE_MODEL` / `OLLAMA_PROSE_MODEL` /
  `OLLAMA_EMBED_MODEL` exactly.
- Otherwise, **the same code, the same guardrails, the same fail-closed parsing** run —
  with the two documented provider asymmetries under *Design guarantees* below.

Two things **never** need any key, because they are pure deterministic Python:

- the **engine tools** the agents call (`resolve`, `reachable`, `find_paths`,
  `effective_policy`, `risk_findings`, `simulate_change`, re-simulation/`reanalyze`), and
- the **fallbacks**. If the model is unreachable, slow, or returns garbage, every agent
  degrades to a deterministic result instead of failing — see *Fail-closed* below.

**Cost & observability.** Every model and tool call is recorded to `ztpa.ai_metrics`
(`metrics.py`) with provider, model, tokens, latency, and an estimated USD cost
(`config.est_cost_usd`; local Ollama = $0). The admin **Metrics & Cost** screen reads this.

**Timeouts.** Model calls are bounded (`client.py` uses a 60s hosted timeout + 1 retry;
the local path passes an explicit per-call timeout, e.g. 120s for remediation) so a cold
local model degrades to the fallback rather than hanging the HTTP request.

---

## The five agentic capabilities

> These five are the *agentic* subset — the ones that drive the engine in a loop.
> **[FEATURES.md §1.5](FEATURES.md) is the source of truth for the full AI capability list
> and count**; this document does not restate it. (The other five are single-shot language
> or judgment jobs: `explain`, `rank`, `report`, `intake`, `entity_suggest`.)

| # | Agent | Kind of loop | Endpoint |
|---|---|---|---|
| 1 | **Remediation loop** | propose → re-simulate → revise → certify | `POST /api/findings/{id}/remediate` |
| 2 | **Remediation campaign** | worst-first, cumulative, over all findings | `GET/POST /api/campaign/plan`, `POST /api/campaign/submit` |
| 3 | **Triage investigator** | ReAct tool-calling → guardrailed decision | `POST /api/change/classify` |
| 4 | **Connector-authoring loop** | propose → normalize sample → revise | `POST /api/connectors/propose` |
| — | **Ask the network** (pre-existing) | tool-calling Q&A over the engine | `POST /api/agent/ask` |

All four new agents share the same shape: a **bounded loop**, the **engine as judge**,
a **deterministic fallback**, and a **trace** returned to the UI so a human can see
exactly how the agent reached its answer.

---

### 1. Remediation loop — `advisory/remediation.py`

**What it does.** Given one finding, it produces a concrete fix (human text + a structured
rule change) that the engine has *proven* resolves the finding without opening a new critical.

**How it works.**
1. The model proposes a `change` (`remove` / `scope_source` / `restrict_service` / `reorder_before`)
   against a rule ref from the finding's facts.
2. The engine applies it to a copy of the records and **re-runs all analyzers** (`reanalyze`)
   — this is the deterministic proof: does the target finding disappear, and are any new
   criticals introduced?
3. The model **sees that verdict** and, if the fix didn't hold (still reachable) or was
   dirty (opened a new critical), **revises** — up to `MAX_ATTEMPTS` (3) rounds.
4. A fix is accepted only when the engine certifies it is **clean** (resolves + no new
   critical). If no clean model fix is found, a **deterministic conservative fallback**
   (which exists for every finding type) is used and re-validated.

**What "the engine has proven it" does and does not mean.** `_validate` re-runs the whole
analyzer suite on the modified record set and compares against the pre-fix findings. It
asserts exactly two things: the target finding is gone, and the set of **critical**-band
findings gained no new member. Three limits follow, and they are worth stating before a
client finds them:
- **Only the critical band is checked.** A fix that resolves a critical while opening three
  new *high* findings still certifies clean (`remediation.py:_is_clean`).
- **The proof is against the snapshot at draft time.** It is not re-run when the change is
  later staged or pushed, so a proof can be stale by the time it is acted on.
- **The fallback is conservative, not surgical.** Every branch of
  `remediation.py:_fallback_change` is `remove` — delete the offending rule — except a
  shadowed rule, which is `reorder_before`. It never narrows a source or a service. That is
  the safe direction to fail in, but it is a blunt instrument, and describing it as
  "surgical" overstates it. (The *model* may propose `scope_source` / `restrict_service`; the
  deterministic safety net may not.)

**Output.** `fix_text`, `change`, `validation`, `by`, and `trace` (every attempt with its
engine verdict). The UI (`RiskTodo.tsx`) shows the trace: *"scope R-14 → still reachable →
remove R-14 → resolved."* The `refine` endpoint feeds a reviewer's comment in as the first
round's feedback, so the same loop powers human iteration.

---

### 2. Remediation campaign — `advisory/campaign.py`

**What it does.** The higher-order agent. It fixes the **whole posture**: it plans a
worst-first sequence and drives the **critical count to zero**, re-simulating after every
step so each fix is judged against the *cumulative* state (fixing one rule changes the
graph, which can resolve or introduce other findings).

**How it works (sequential decision-making with feedback).**
1. Re-analyze the current records → pick the worst still-open finding.
2. Draft a fix for it via the **remediation loop above** (agent #1) against the *accumulated*
   records — not the original snapshot.
3. **Campaign-level gate:** re-simulate the candidate on the cumulative records and **apply
   it only if it removes the target and opens no new critical.** Otherwise mark it
   *needs-review* and skip — the campaign never makes the posture worse.
4. Record the critical count after each applied step (the trajectory), plus any cascade
   (one fix often clears several findings). Repeat until no targeted findings remain.

**Output.** `criticals_trajectory` (e.g. `[4,3,2,1,0]`), ordered `steps` (each `applied` or
`needs_review`, with the sub-loop's own trace), `residual_findings`, and `cleared_all_criticals`.
The UI (`Campaign.tsx`, on the Risk To-Do screen) renders the *"drove criticals 4 → 0"* headline
and each proven step.

**Persistence & acting on the plan.** The plan is **persisted per snapshot** (`campaign_plans`
table): `GET /api/campaign/plan` returns the cached plan on page load, so navigating away and back
re-uses it — only the explicit *Plan / Re-plan* button spends a planning pass. It is **advisory
only** — nothing is applied to the live snapshot. `POST /api/campaign/submit` sends every proven
(`applied`) fix to the **Change Gate**: each becomes its own change request the gate re-evaluates
and rules on individually (so the existing audit → staging → push flow is unchanged), and steps
flagged `needs_review` are skipped and reported. A recompute yields a new snapshot id, so a stale
plan naturally falls out of cache.

---

### 3. Triage investigator — `advisory/classify_change.py`

**What it does.** Decides `auto_approve` vs `escalate` for a proposed change — the
highest-stakes job. Before ruling, it **investigates**: the model gathers evidence by
calling the engine tools (ReAct-style), choosing which tool to call next itself.

**How it works.**
1. **Layer 1 — guardrail (deterministic, pre-model):** the engine has already simulated the
   change and computed the delta; catastrophic patterns (new internet→sensitive path,
   any/any, new internet→internal exposure) **force-escalate before any model call**.
2. **Investigation (`investigate`)** — a bounded ReAct loop (`MAX_TOOL_CALLS` = 4). Each turn
   the model returns JSON: either `{tool, args}` to gather evidence
   (`effective_policy` / `find_paths` / `reachable` / `resolve` / `risk_findings`) or
   `{done: true}`. Tool results are real engine computations; a hallucinated tool name or
   bad args is recorded as evidence, never a crash. This loop is **provider-portable** (it
   uses plain JSON completions, so it works identically on Ollama / OpenAI / Anthropic) and
   **fail-open** (no model → empty evidence → the decision proceeds on the delta alone).
3. **Decision** — the model rules on the *computed delta + gathered evidence* (the requester's
   justification is passed but labeled **UNTRUSTED**).
4. **Layer 2 — fail-closed:** any unparseable/invalid model output → **escalate**.
5. **Layer 3 — engine override:** even if the model says `auto_approve`, a non-clean delta
   forces **escalate**. The investigation can add evidence but can **never widen** what the
   gate will approve.

**Output.** A `ChangeDecision` whose `delta_summary.investigation` carries the evidence trail,
shown in the Change Gate result and the decision audit log (`ChangeGate.tsx`).

---

### 4. Connector-authoring loop — `advisory/authoring.py`

**What it does.** "Bring your own source." Given a **sample export** of an unknown tool, the
model proposes a declarative `SourceProfile` (config, not code) that the deterministic
normalizer can apply — self-correcting until the sample normalizes cleanly.

**How it works.**
1. The model proposes a profile (where the rules live, which fields map to source / dest /
   service / action / ref).
2. The engine **validates it by actually normalizing the sample** (`apply_profile`): did it
   produce records, and is every row's source / destination / service mapped?
3. On failure the concrete reason is fed back — *"zero records → rules_path is wrong"*,
   *"rows missing source → that field name is wrong"*, or a schema error — and the model
   **revises**, up to `MAX_ATTEMPTS` (3) rounds.
4. If it never fully validates, the **best partial** profile is returned flagged
   `needs_review`. At runtime the model is gone — only the deterministic profile normalizer
   would run.

⚠️ **Design-time only in this build.** The response always carries `approved: false`, and
that is literal: there is **no endpoint that registers an approved profile and no ingestion
path that uses one**. `/api/connectors/propose` returns a proposal plus a validation report
and stops there; the engine still reads only the three fixed mock exports. The
`"approve to register this connector"` phrasing in this endpoint's own `note` string
(`advisory/authoring.py`, the `note` returned on a clean validation) promises a step that
does not exist and is a known open correction.
Describe this capability as a **design-time preview** — see [FEATURES.md §1.7](FEATURES.md).

**Output.** `profile`, `validation` (with `unmapped` fields), `attempts`, and the `trace` of
each round, rendered in `Connectors.tsx`.

---

## Design guarantees (true for every agent)

- **The engine is the judge.** A model proposal is only honored if the deterministic engine
  proves it (re-simulation for remediation/campaign; the delta + 3 guardrail layers for
  classify; normalizing the real sample for authoring).
- **Fail-closed / fail-safe.** Model unreachable, slow, or emitting garbage → a deterministic
  outcome (a proven fallback fix, an escalate, a "needs review"), never a crash or a silent
  bad result.
- **Bounded.** Every loop has a hard round/tool-call cap and a per-call timeout.
- **Provider-agnostic for structured judgment — with one documented exception.** The
  structured-judgment capabilities (classify, remediate, campaign, explain, rank, report,
  intake, authoring) go through `advisory/client.py:complete()`, which speaks plain JSON
  completions, so they run under identical contracts and identical guardrails on Ollama,
  OpenAI and Anthropic. Two things are **not** provider-symmetric, and pretending otherwise
  is the kind of claim an architect checks first:
  - **Native tool-calling is implemented for Ollama only.** `agent/assistant.py:ask()` runs
    the real `_ollama_loop` (the `/api/chat` `tools` protocol, up to 5 turns, each tool a
    genuine engine call) **only when `active_provider() == "ollama"`**. On OpenAI or
    Anthropic it takes `_grounded_fallback`: **one** completion over a *precomputed*
    `risk_findings` list. It still cannot invent facts — the answer is grounded in engine
    output and the trace shows the single `risk_findings` call — but it **cannot call
    `reachable`, `find_paths` or `effective_policy`**, so it cannot answer a question the
    precomputed findings do not already contain. Agent #3's `investigate` loop is different
    and *is* portable: it drives tool selection through plain JSON completions rather than a
    provider's tool protocol, so it works identically everywhere.
  - **The Anthropic path is capped at 1500 output tokens** (`client.py:_anthropic_complete`,
    `max_tokens=1500`). Long-form jobs — the posture report above all — can be truncated
    there in a way they are not on the other two providers.
- **Observable.** Every call is metered (tokens, latency, cost, role) and every agent returns
  a **trace** so a human can audit *how* it reached its answer.
- **Deterministic core.** Re-running the same snapshot yields byte-identical facts; only the
  language/judgment layer varies by model.

---

## Files

```
backend/src/advisory/
  remediation.py     # agent 1: propose -> re-simulate -> revise -> certify
  campaign.py        # agent 2: worst-first cumulative campaign (composes agent 1)
  classify_change.py # agent 3: investigate (ReAct) -> guardrailed decision
  authoring.py       # agent 4: propose -> normalize sample -> revise
  client.py          # provider-pluggable model client (Ollama/OpenAI/Anthropic), fail-closed
backend/src/agent/
  tools.py assistant.py   # the deterministic tools + the pre-existing "Ask the network" agent
backend/app/main.py       # endpoints: /remediate, /campaign/plan, /change/classify, /connectors/propose
backend/tests/test_agents.py  # both paths (deterministic fallback + stubbed model) for all four
frontend/components/
  RiskTodo.tsx Campaign.tsx ChangeGate.tsx Connectors.tsx   # the traces, rendered
```
