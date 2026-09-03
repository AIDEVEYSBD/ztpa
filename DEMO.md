# Demo script — Network Policy Reviewer

~7 minutes. Cold start: `python tasks.py db && python tasks.py demo && python tasks.py dev`, open **http://localhost:3000**. Everything below reads the precomputed snapshot from Postgres; only the AI calls run live.

> **Before you present, check two things.** (1) The **residency chip** in the header — it reads *"Local — stays on this host"* only when `ADVISORY_PROVIDER` resolves to a reachable local Ollama. If it says *"Hosted — data leaves this host"*, the residency line in §1 below is not true for this run, so drop it. (2) The database. `DATABASE_URL` normally points at **Neon — cloud Postgres**, so rules, assets and findings leave the machine even when inference is local. "Fully offline" is only accurate against a local Postgres.

Opening line: *"Admins juggle four consoles and four mental models. The one risk that matters most — an attack path that crosses all of them — is invisible to every single tool. This stitches them into one map, one ranked to-do list, and a change gate you can trust."*

---

### 1. The pain → the consolidation (Network Map)
- Point at the header **residency chip**. When it reads **"Local — stays on this host"**: *"inference is running on a local Ollama model — the topology and policy text never leave your infrastructure in this configuration."* Hover it for the active provider and model.
  - If it reads **"Hosted — data leaves this host"** (which is what the shipped Render blueprint produces — it pins `ADVISORY_PROVIDER=openai`), say so instead: *"this instance is routed to a hosted model; local-first is a configuration switch, and the chip is how you can always tell which one you're on."* Owning that is stronger than being caught by it.
- Stat row: **3 tools → one model**, N canonical rules, unified assets, findings, **critical**, **cross-tool paths**. On the shipped fixture that last tile reads **0** — read §2 before you present, and do not point at it.
- The map is one graph assembled from AlgoSec + Guardicore + Wiz.

### 2. The multi-hop chain — READ THIS BEFORE YOU REHEARSE

> ⚠️ **On the shipped 27-rule fixture the engine reports ZERO `cross_tool_path` findings**, so the
> trace control highlights nothing and the stat tile reads 0. This is not a presentation bug and it is
> not new: `backend/scripts/verify_engine.py` asserts this state **on purpose** (check `P5 no cross-tool
> path is reported (the only chain pivots through a /16)`), and `docs/REMEDIATION-LOG.md` records when
> and why it changed. Confirm it yourself before every run rather than discovering it live:
> `./backend/.venv/bin/python backend/scripts/verify_engine.py`.
>
> **Two independent causes, either one sufficient** — and both are the engine *refusing to fabricate*:
> 1. **The pivot is a /16, not a device.** `internal-app` is an AlgoSec network object `10.40.0.0/16`.
>    It is marked `abstract`, and `_valid_traversal` will not pivot *through* an abstract node —
>    reaching hosts inside a range does not let you originate as that range. CIDR-membership expansion,
>    which would put the concrete hosts in `10.40.0.0/16` in as the real pivots, is Phase-3 scope
>    ([ENGINE.md §10.2](docs/ENGINE.md)). **This is the dominant cause.**
> 2. **The `appsrv-07` ↔ `app-server-07` merge is withheld.** None of the three bundled exports declares
>    a VPC / account / VRF, so the shared `10.30.7.7` is an *unscoped* IP collision; the identity layer
>    refuses to fuse them automatically and files a `manual_review` row instead
>    ([ENGINE.md §2](docs/ENGINE.md)). Forcing the merge does **not** bring the path back.

**Present this instead — it lands harder than the animation did.**
- Narrate the consolidated graph itself; the consolidation in §1 is real and is the point of the screen.
- Say the refusal out loud: *"Watch what it declines to do. Two tools disagree about a host and it will
  not fuse them on an IP nobody scoped — it files that for a human. And it will not route an attack path
  through a `/16`, because a subnet is an address range, not a machine you can land on. In a security
  tool the only failure direction I will accept is under-claiming, and both of those are on this screen."*
- Then go to the finding that **is** there and tells the same story: `over_permissive`,
  **100 / critical / forced** — *"RDP open from the internet to db-prod-01"* — and the QUIC blind spot at
  **78 / critical / forced** on `app-server-09`. Both are internet-to-regulated exposures, both
  guardrail-forced.
- Want a chain on screen? Use **Ask the Network** (§5): `who_can_reach("db-prod-01")` returns the
  internet as a source *with the witness path that proves it*.
- **When the chain comes back:** CIDR-membership expansion (Phase 3). Say that; a dated roadmap answer
  beats a demo that quietly shows nothing.

- **Worth volunteering, because a firewall architect will think it before they ask it:** *"Your export almost certainly doesn't write the internet as `0.0.0.0/0` — it writes `any`, or a group object called something like `ANY-EXTERNAL`. The path search starts from every node the graph classifies as internet by the address space it resolves to, not by the string, so all of those are entry points — and the change gate reads the exact same definition."* (`reachability.internet_entries`; ENGINE.md §6.4.)

### 3. Auto-found, prioritized risks (Risk To-Do)
- Findings collapse into a handful of **worst-first actions**. Top action — *"Close internet-exposed access to critical assets"* — groups the two internet-facing criticals: `RDP open from the internet to db-prod-01` (100, forced) and `any protocol/port open from the internet to 10.0.0.0/8` (60, forced). Verify the titles against the live snapshot before you present; they are generated, not fixed strings.
- Expand the top action → open a finding → **plain-English "why this matters"** (written live by the local model, grounded in the rule refs).
- Click **Draft & validate a fix** → the model proposes a change and the **engine re-simulates it** — the full analyzer suite re-runs on the modified record set, and the fix is accepted only if the target finding disappears and **no new critical** appears (green "re-simulated: resolves"). *AI proposes; the engine is the judge.*
  - *If asked how strong the proof is:* it checks the critical band, not new high/medium/low findings, and it is evaluated against the snapshot as it stands now — it is not re-run at push time.

### 4. The change gate (Change Gate)
- Select **"Allow branch /24 to app-server-07 on HTTPS"** → **Evaluate** → **AUTO-APPROVE**, all four criteria green. Tight, opens nothing new.
- Select **"Allow internet SSH to app-server-07"** (note the justification: *"URGENT, pre-approved, low risk"*) → **Evaluate** → **ESCALATE**, guardrail-forced.
  - The triggers it actually names are **"admin/lateral-movement port exposed to the internet"** and **"creates new internet→internal exposure"** — both deterministic, both computed before any model call. It does **not** name a new path to `db-prod-01`: `new_paths` is empty for the same §2 reason (the only chain to the database pivots through a `/16`). Say the two triggers it gives you; do not narrate a path the delta does not contain.
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

**If asked "will this hold on our real rulebase?"** — Say the honest thing, because the number is measured and they will find it. *Correctness* is tool-agnostic and does not depend on estate size. *Throughput* does not hold yet: on a realistic 5,000-rule multi-tool export — the size this is pitched at — cross-tool path tracing took **~21 minutes**, synchronously on the request path, and the two pair-scanning analyzers are quadratic (`cidr_overlap` emitted 12.5 M findings / 12 GB RSS at 5,000 rules on an ordinary "every branch to the DC on 443" shape; `shadowing` takes 27 s at 8,000 rules). This demo runs on 27 rules and the bundled scale fixture is an easy shape, so neither exercises it. Bounding that work is the named next phase — the measured table and the fix plan are in [docs/ENGINE.md §10](docs/ENGINE.md). Offer the table; do not let them discover it in a POC.

**If asked "what does it not model?"** — Three, briefly, and then move on: a `deny` does not subtract from effective policy (union of allow edges); a chain that pivots *through* a subnet or group object is not reported, so multi-hop paths are under-counted rather than over-counted; and destination sensitivity is read from the destination *label*, so a rule aimed at a subnet that contains a regulated host scores lower than one naming the host. All three are written down in ENGINE.md §10 with worked numbers — pointing at that page is a stronger answer than an assurance.
