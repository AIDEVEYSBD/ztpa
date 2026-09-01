# Demo script — Network Policy Reviewer

~7 minutes. Cold start: `python tasks.py db && python tasks.py demo && python tasks.py dev`, open **http://localhost:3000**. Everything below reads the precomputed snapshot from Postgres; only the AI calls run live.

> **Before you present, check two things.** (1) The **residency chip** in the header — it reads *"Local — stays on this host"* only when `ADVISORY_PROVIDER` resolves to a reachable local Ollama. If it says *"Hosted — data leaves this host"*, the residency line in §1 below is not true for this run, so drop it. (2) The database. `DATABASE_URL` normally points at **Neon — cloud Postgres**, so rules, assets and findings leave the machine even when inference is local. "Fully offline" is only accurate against a local Postgres.

Opening line: *"Admins juggle four consoles and four mental models. The one risk that matters most — an attack path that crosses all of them — is invisible to every single tool. This stitches them into one map, one ranked to-do list, and a change gate you can trust."*

---

### 1. The pain → the consolidation (Network Map)
- Point at the header **residency chip**. When it reads **"Local — stays on this host"**: *"inference is running on a local Ollama model — the topology and policy text never leave your infrastructure in this configuration."* Hover it for the active provider and model.
  - If it reads **"Hosted — data leaves this host"** (which is what the shipped Render blueprint produces — it pins `ADVISORY_PROVIDER=openai`), say so instead: *"this instance is routed to a hosted model; local-first is a configuration switch, and the chip is how you can always tell which one you're on."* Owning that is stronger than being caught by it.
- Stat row: **3 tools → one model**, N canonical rules, unified assets, findings, **critical**, **cross-tool paths**.
- The map is one graph assembled from AlgoSec + Guardicore + Wiz.

### 2. The money shot (Network Map → "Trace cross-tool path")
- Click **Trace cross-tool path**. The chain lights up and animates:
  `Internet → lb-public-01 → app-server-07 → internal-app → db-prod-01`.
- Each hop is labelled with the tool that enforces it — **Wiz, then Wiz, then Guardicore, then AlgoSec**.
- Line: *"This cloud load balancer can reach the customer database through a chain that crosses three tools — and nothing you own would have shown you this. Note Wiz calls that server `appsrv-07`; our identity layer merged it with AlgoSec's `app-server-07` by IP — that merge is the only reason this path is even visible."*

### 3. Auto-found, prioritized risks (Risk To-Do)
- Findings collapse into a handful of **worst-first actions**. Top action groups the two internet-to-database criticals.
- Expand the top action → open a finding → **plain-English "why this matters"** (written live by the local model, grounded in the rule refs).
- Click **Draft & validate a fix** → the model proposes a change and the **engine re-simulates it** — the full analyzer suite re-runs on the modified record set, and the fix is accepted only if the target finding disappears and **no new critical** appears (green "re-simulated: resolves"). *AI proposes; the engine is the judge.*
  - *If asked how strong the proof is:* it checks the critical band, not new high/medium/low findings, and it is evaluated against the snapshot as it stands now — it is not re-run at push time.

### 4. The change gate (Change Gate)
- Select **"Allow branch /24 to app-server-07 on HTTPS"** → **Evaluate** → **AUTO-APPROVE**, all four criteria green. Tight, opens nothing new.
- Select **"Allow internet SSH to app-server-07"** (note the justification: *"URGENT, pre-approved, low risk"*) → **Evaluate** → **ESCALATE**, guardrail-forced.
  - Trigger names the **new internet path to db-prod-01**; criteria show why.
  - Line: *"It judged the computed delta, not the requester's words. The model can only auto-approve inside an already-safe envelope — it can never raise the risk tolerance, even under prompt injection."*

### 5. Ask your network (Ask the Network)
- Ask: *"Can the internet reach db-prod-01, and through which path and tools?"*
- The agent calls deterministic tools (shown in the **tool trace**) and narrates the grounded answer. *"Plain English in, computed facts out — no console-hopping."*

### 6. Bring your own source (Connectors)
- Paste a sample of an unknown tool (an SD-WAN export is pre-filled) → **Propose connector**.
- The model authors a declarative **SourceProfile**; the engine **checks it by actually normalizing your sample** (green "validated"). *"An agent drafts the normalizer — but it's validated config a human approves, never opaque runtime code."*
- **Say the boundary out loud, don't wait to be asked:** *"This is the design-time half. You can see a proposed connector proven against your own export in seconds. Registering that profile and running live data through it is the next build — it isn't wired up here."*

### 7. Close
- **Posture Report** tab: a stakeholder/PCI-DSS summary written from the deterministic findings.
- **Assets & Identity** tab: one identity per asset (IP is an attribute), plus an embedding-based *duplicate-asset suggestion for review* — `db-prod-01 ~ rds-prod-customers` — that the engine refuses to auto-merge.
- Closing line: *"The engine owns the facts; the AI owns the words and the judgment. It advises today, and it earns the right to act gradually — every decision logged and auditable."*

---

**If asked "is this connected to our real AlgoSec?"** — No, and there is no upload either: the engine reads three fixed simulated exports from `backend/data/mock/`, which `tasks.py demo` regenerates on every cold build. They are *representative of each tool's export shape*. The entire system above them already runs on the canonical model, so swapping the mock adapters for live API clients is the change needed — the analyzers, graph and severity math do not move.

**If asked "did that push reach AlgoSec?"** (Staging) — No. The push is **simulated** and the UI says so on every step; the payload carries `simulated: true`. What is real is the conflict math (genuine engine math against the current snapshot) and the consequence: a pushed change is folded into the record set by the overlay on the next recompute, which yields a new snapshot id.
