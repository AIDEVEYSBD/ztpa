# Demo script — ZeroTrust Policy Advisor

~7 minutes, fully local (no internet needed). Cold start: `make db && make demo && make backend && make frontend`, open **http://localhost:3000**. Everything below reads the precomputed snapshot from Postgres; only the AI calls run live (on Ollama).

Opening line: *"Admins juggle four consoles and four mental models. The one risk that matters most — an attack path that crosses all of them — is invisible to every single tool. This stitches them into one map, one ranked to-do list, and a change gate you can trust."*

---

### 1. The pain → the consolidation (Network Map)
- Point at the header: **"Local · Ollama · Data stays local"** — *the topology never leaves this machine.*
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
- Click **Draft & validate a fix** → the model proposes a change and the **engine re-simulates it to prove it resolves the finding** (green "re-simulated: resolves"). *AI proposes; the engine is the judge.*

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
- The model authors a declarative **SourceProfile**; the engine **validates it by normalizing your sample** (green "validated"). *"An agent makes the normalizer — but it's validated config a human approves, never opaque runtime code. New source, no new Python."*

### 7. Close
- **Posture Report** tab: a stakeholder/PCI-DSS summary written from the deterministic findings.
- **Assets & Identity** tab: one identity per asset (IP is an attribute), plus an embedding-based *duplicate-asset suggestion for review* — `db-prod-01 ~ rds-prod-customers` — that the engine refuses to auto-merge.
- Closing line: *"The engine owns the facts; the AI owns the words and the judgment. It advises today, and it earns the right to act gradually — every decision logged and auditable."*

---

**If asked "is this connected to our real AlgoSec?"** — No. These are *simulated exports representative of each tool*. The entire system already runs on the canonical model, so swapping the mock adapters for live API clients is the only change needed.
