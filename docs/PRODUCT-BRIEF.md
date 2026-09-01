# Network Policy Reviewer

> **What this document is.** A short walkthrough of how the Network Policy Reviewer works: what it reads, what it does with it in order, how it builds one picture of your network, and how it finds the route into your most sensitive systems that no single tool can show you.
>
> It is written to be read start to finish in about fifteen minutes. There is no code and no mathematics.

| | |
|---|---|
| **Product** | Network Policy Reviewer |
| **In one sentence** | One view of network access risk, assembled from several security tools that do not talk to each other, then explained, ranked, and used to gate changes. |
| **Who it is for** | Security teams, network teams, cloud teams, and the people who approve firewall changes. |
| **Where it stands today** | A complete, working system, running on representative policy exports from AlgoSec, Guardicore and Wiz. |
| **What comes next** | Direct connections to those three products, so the same system runs on live data. |

---

## Contents

1. [The background](#1-the-background)
2. [The core flow step by step](#2-the-core-flow-step-by-step)
3. [How the information gets in](#3-how-the-information-gets-in)
4. [Building the map and finding the critical path](#4-building-the-map-and-finding-the-critical-path)
5. [What else you should know](#5-what-else-you-should-know)
6. [Where the product is today](#6-where-the-product-is-today)

---

## 1. The background

Almost no large organisation controls network access from one place. The firewall team runs one product. The cloud team runs another. A segmentation product sits between the servers inside the data centre. Each of these is good at its job, and each one shows a complete and confident picture of its own territory.

The difficulty is at the seams. Every tool draws a boundary around what it can see, and an attacker does not respect those boundaries. A route into your most sensitive systems can begin in the cloud, pass through a server the firewall team manages, cross a segment the microsegmentation product governs, and end at a database none of those three consoles considered to be their responsibility. Every individual step looks reasonable. Every individual console reports that everything is fine. The combination is the exposure, and nothing is looking at the combination.

That happens because of three ordinary facts that hold in nearly every environment:

| Fact | Consequence |
|---|---|
| Each tool only sees the rules it enforces | A route that crosses two tools is invisible in both |
| Each tool names machines its own way | The same server appears as two or three unrelated things |
| Each tool scores risk on its own scale | A critical in one console and a critical in another are not comparable |

There is a second, quieter problem alongside it. Policy accumulates. A rule opened for a project three years ago is still there. A broad rule near the top of a list silently overrides a narrower one below it, so the narrow rule never applies and nobody knows. Over time a policy set becomes something no individual understands in full, and the team's honest position becomes "we cannot remove that, we do not know what it will break."

And a third. When a change request arrives, usually as a sentence, usually urgent, someone has to decide in minutes whether it is safe, from a written justification rather than from a calculation, without being able to see across the tools either. That is how a small approval creates a large exposure.

This product addresses all three: it merges the tools into one picture, it finds what is wrong in that picture, and it puts a calculation in front of every proposed change before anyone approves it.

One principle runs through the whole design and is worth stating before anything else:

> **The calculation owns the facts. The AI owns the words and the judgement.** Which machines are the same, what can reach what, which rules overlap, how severe something is, what a proposed change would open up: all of that is computed, repeatably, by ordinary software. The AI explains, ranks, drafts and recommends. It never works out a route through your network and never decides on its own whether a change is safe. When it needs a fact, it asks the engine and reasons about the answer it gets back.

---

## 2. The core flow step by step

This is the whole system in order.

```
   1  Collect        policy exports arrive from each source
   2  Translate      every rule becomes one common kind of statement
   3  Decode         work out what each rule actually permits
   4  Merge          the same machine under different names becomes one asset
   5  Map            build the picture of what can reach what
   6  Check          run five independent checks over that picture
   7  Score          rate every finding and sort worst first
   8  Explain        put it in plain language and group by root cause
   9  Fix            draft a change, then prove it works
  10  Gate           simulate any proposed change and rule on it
  11  Stage          hold it, check for conflicts, apply it
  12  Record         store the run, the decision and the audit trail
```

**Step 1. Collect.** Policy exports arrive from AlgoSec, Guardicore and Wiz, plus any additional source you have added. This is the same content those products already produce for reporting and review: the rules, the address objects those rules refer to, and the order rules are evaluated in.

**Step 2. Translate.** Each source is read by its own adapter, and every rule is rewritten as the same kind of statement: *this source may reach this destination, using this service, and it is allowed or denied.* Two things stay attached to every translated rule permanently: which tool it came from, and that tool's own reference for it, such as `ALGO-002`. From here on, nothing in the system needs to know which vendor a rule came from.

**Step 3. Decode.** For each rule the system works out what is really being permitted: the protocol, the port or range of ports, and the application that implies, such as web traffic, name lookups or remote administration. Named objects such as `db-prod-01` are resolved to what they stand for, along with their tags, so the system knows which destinations hold sensitive data.

**Step 4. Merge.** The same server appears under different names in different tools. Using only signals that cannot be wrong, the system merges those into one asset. This is the step that makes cross-tool analysis possible at all. Without it the map is three disconnected fragments.

**Step 5. Map.** Every permitted connection becomes a line on one map, carrying every rule that grants it, labelled by tool and rule reference. Each point on the map sits in a zone, so the system knows when a connection crosses from a less trusted area into a more trusted one.

**Step 6. Check.** Five independent checks run over the map: rules that permit far more than they need to, rules that overlap each other, rules that are never actually applied, routes from the internet to sensitive systems that cross more than one tool, and traffic permitted on paths your inspection tooling cannot see into.

**Step 7. Score.** Every finding gets a number from 0 to 100, built from four questions: how many parties could use it, how dangerous is what they can do, how much does the destination matter, and does it cross a trust boundary. Separately, three categorically unacceptable patterns are marked critical no matter what the number says. The list is sorted worst first, in a fixed order that does not change between runs.

**Step 8. Explain.** For each finding the AI writes a plain-language explanation of why it matters, grounded in the specific rules behind it. It then groups findings by underlying cause, so one root problem shows as one action rather than fifteen alerts.

**Step 9. Fix.** For any finding, the AI drafts a specific change. The engine applies that change to a copy of the data and re-runs all five checks to answer two questions: did the finding disappear, and did anything new and critical appear. If the answer is not clean, the model sees why and tries again. A fix is only accepted once the engine certifies it, and the whole attempt trail is shown on screen.

**Step 10. Gate.** Any proposed change, whether drafted by the system or requested by a person, is simulated against the current map before anyone judges it. The system computes what would newly become reachable, then three layers rule on that computed result: a guardrail that can only escalate, a model that investigates and recommends, and an engine override that can only escalate. The outcome is auto-approve or escalate, with the reasoning attached.

**Step 11. Stage.** Approved changes go to a staging area rather than straight to the source system. Staging checks the change against the current state of the target, detects conflicts, and applies it in steps.

**Step 12. Record.** Every analysis run is stored with an identifier derived from the policy that produced it. Every change and decision is written to an audit log. Every AI call is recorded with its duration, consumption and estimated cost.

### Where the AI enters, and where it does not

The same twelve steps, by who is responsible:

| Steps | Who does the work | What that means |
|---|---|---|
| 1 to 7 | Ordinary software only | Collecting, translating, decoding, merging, mapping, checking and scoring involve no AI at all. Run it twice, get the identical answer. |
| 8 | AI, with no consequence | Wording and grouping. A mistake here is a badly phrased explanation next to a correct finding. |
| 9 | AI proposes, engine proves | The model drafts; the engine re-runs the analysis and rejects anything that does not hold. You never see an unproven fix. |
| 10 | Both, with the engine holding a veto | The model can investigate and recommend. Two of the three layers are ordinary code and can only make the outcome stricter. |
| 11 and 12 | Ordinary software only | Conflict detection, application and record keeping involve no AI. |

### What a person actually does

The loop is short. You open the ranked list, read the top action and its explanation, ask the system to draft a fix, look at the proof that it resolves the finding, discuss it with a colleague in the comments if you need to, and send it to the gate. The gate rules on it, it goes to staging, and it gets applied. A change request arriving from elsewhere in the business enters at step 10 and takes the same path from there.

---

## 3. How the information gets in

### The three sources

| Source | What it governs | What it contributes |
|---|---|---|
| **AlgoSec** | Traditional firewalls at the network edge and between zones | Ordered firewall rule sets, address objects, and the order rules are evaluated in |
| **Guardicore** | Microsegmentation between workloads inside the environment | Server to server rules, labels, and application identity where it is declared |
| **Wiz** | Cloud posture and exposure | Which cloud resources are reachable from the internet, and how |

Together they cover the three places network access is actually decided: at the edge, between workloads, and in the cloud.

### One common way of describing a rule

Every rule from every source becomes the same statement: *something on one side may reach something on the other side, using a particular service, and this is allowed or denied.*

That sounds obvious, but it is doing real work. The three products express the same idea in three genuinely different ways, and the translation is what makes them comparable at all.

| What the rule really says | AlgoSec writes it as | Guardicore writes it as | Wiz writes it as |
|---|---|---|---|
| Who is allowed to connect | A source address or a named object | A label on a group of workloads | A cloud resource or exposure source |
| What they may reach | A destination address or object | A label on the destination group | The exposed cloud resource |
| What they may do | A service such as tcp/443 | A port with an optional application name | A port and protocol |

The tool of origin and that tool's own rule reference never get discarded. So when the system later tells you something is wrong, it points at the exact rule in the exact console where you go to fix it.

### Reading what a rule actually permits

A rule that says `tcp/443` is easy. Real policy is messier, and reading it properly is one of the places the product does more than the obvious. For each rule the system works out both the low-level detail, meaning protocol and port range, and the application that detail implies. Where a tool declares the application it is used. Where it does not, the system infers it from a fixed lookup table and records that it was inferred, so you can always tell a declared fact from an inferred one.

The clearest example of why this matters is a modern one. Newer web traffic increasingly uses a protocol called QUIC, which carries what used to be ordinary web traffic over UDP port 443 rather than TCP port 443. Many established firewalls cannot inspect it. So a rule permitting UDP on 443 can quietly create a channel your inspection tooling does not see into, while every console shows a perfectly normal looking allow rule.

Most tools see a UDP allow on port 443. This system sees QUIC, understands it is not inspectable by the controls in place, and flags it. It also catches the related case where the inspectable and uninspectable paths are both open at once, because traffic will silently prefer the one you cannot see, and the inspection you believe you have is not happening.

### Bringing your own source

Every organisation has something the standard list does not cover. You paste a sample of that tool's export, and the AI proposes a description of how to read it: where the rules live in the file, and which fields mean source, destination, service, action and reference. The engine then tests that description by actually using it to translate your sample, and reports what it could and could not map. If it failed, the specific reason goes back to the model and it tries again.

The important detail is what gets produced. The AI writes a description, not a program. When the connector actually runs, the model is not involved at all. You are approving a short piece of configuration you can read, not code you have to trust.

### What the data looks like today

Today the three connectors read representative policy exports rather than calling the live products. That was deliberate: it let the entire system be built and validated against a known dataset without needing access to anybody's production security tooling.

Everything after that first translation step is real and operates on real logic: the merging, the map, the five checks, the scoring, the change simulation, the fixes, the audit trail. Because all of it works on the common format rather than on any vendor's shape, connecting the live products means replacing the part that fetches the file. That is the immediate next step.

---

## 4. Building the map and finding the critical path

This section covers the two ideas the whole product rests on. They are worth reading closely, because between them they are the reason the system can show you something your existing tools cannot.

### First: working out what is the same machine

The same server appears in different tools under different names. The cloud tool calls it `appsrv-07`. The firewall calls it `app-server-07`. The segmentation product calls it something else again. Until the system knows those are one machine, the map has three disconnected fragments, and any route that crosses them is invisible.

The tempting approach is to guess: match similar looking names, assume things that sound alike are alike. The system deliberately does not do this, because a wrong merge does not produce a slightly worse answer. It produces a confident, false statement about what can reach what. So merging uses only signals that cannot be wrong:

| Signal | What it means |
|---|---|
| **Same address** | Two names observed at the same specific address are the same machine |
| **Same name in more than one tool** | A name appearing identically across tools is one thing |
| **A person confirmed it** | A reviewer looked at a suggestion and approved the merge |

Nothing else merges automatically, and every merge records which of the three reasons applied, so it can be inspected later.

For the cases the strict rules miss, there is a softer feature. A machine registered as `db-prod-01` in one place and `rds-prod-customers` in another is probably the same database, but "probably" is not good enough to act on. The system uses the AI to notice such pairs and put them forward for review. It will not merge them on its own. The AI is allowed to raise a question. It is not allowed to change a fact.

### Second: the map itself

With every rule in one format and every machine identified once, the system builds a map of allowed connections. Each point is a machine, a group, or a range of addresses, and the internet itself is a point on the map. Each line means access is permitted in that direction, and each line carries every rule that grants it, with the tool and rule reference attached.

Parallel grants are kept separate rather than collapsed together. If three rules in two tools all permit the same connection, the map shows three grants. This matters when you go to fix something: removing one rule may not close the connection if two others still allow it, and the map tells you that before you find out the hard way.

Every point sits in a zone, which is a straightforward lookup rather than a judgement. The internet is its own zone. Anything tagged internet facing or public is in the demilitarised zone. Anything tagged development, sandbox or test is development. Everything else is internal. Zones exist because the same connection means different things depending on direction. Access from the internet into an internal system is a boundary violation. Access from the internet into a system built to face the internet is not.

When the system says one thing can reach another, it means there is a chain of permitted connections leading from the first to the second. That chain can be several steps long, and each step can be permitted by a different tool. Working out those chains is done by a well-established graph traversal, not by an AI model, and it is the calculation everything else depends on.

### The critical path

Now the two ideas come together, and this is the capability the rest of the architecture exists to support.

The system looks for chains that start at the internet and end at something sensitive, and it keeps the ones that cross at least two different tools. A route contained inside one product is something that product could in principle have shown you. A route crossing two or three is one that nothing you own can show you, because no single console holds all the pieces.

In the demonstration dataset it looks like this:

```
   Internet  ->  lb-public-01  ->  app-server-07  ->  internal-app  ->  db-prod-01

                     Wiz              Wiz            Guardicore         AlgoSec

                cloud load        the server         the internal      the customer
                 balancer       the cloud tool        application        database
                                calls appsrv-07                      holding card data
```

Read it hop by hop.

Wiz permits the internet to reach a public load balancer. Entirely normal, and exactly what a load balancer is for. Wiz permits the load balancer to reach an application server. Also normal. Guardicore permits that application server to reach the internal application tier. Again normal. AlgoSec permits the internal application tier to reach the production database, which is the most normal thing on the list.

Four reasonable decisions. One route from the open internet to the customer database. Each console involved is correct about its own hop and blind to the other three, so each one reports that everything is fine, and each one is telling the truth about what it can see.

Now look at the third hop again. Wiz calls that server `appsrv-07`, while AlgoSec and Guardicore call it `app-server-07`. Without the identity merge described above, the chain breaks at exactly that point and the route does not exist as far as the system is concerned. That merge is not a convenience feature. It is the thing that makes the entire differentiator work.

Routes like this are automatically treated as critical when they cross from the internet into an internal system and end somewhere sensitive, regardless of what any score would otherwise have produced.

---

## 5. What else you should know

### How it decides what is serious

Everyone who has used a security product has been handed a list of two thousand findings all marked high. The score here comes from four questions, and each one is a lookup rather than an opinion.

| Question | What it measures | Highest rating goes to |
|---|---|---|
| **How many parties could use this?** | How wide the source of the rule is | The entire internet, or any source at all |
| **How dangerous is what they can do?** | The kind of access granted | Any protocol at all, or remote administration |
| **How much does the destination matter?** | The tags on the destination | Crown jewel, then payment card, customer or health data |
| **Does it cross a trust boundary?** | The direction it travels | The internet into an internal system |

Two of these combine into impact, meaning how much damage this access would do to this destination. The destination sets a ceiling, so however dangerous the access, a finding about a sandbox machine can never outrank one about a customer database. That single property is what stops the ranked list filling with technically severe findings about systems nobody cares about. Exposure then scales that impact, and the boundary factor raises it if a real boundary is crossed. The result is capped at 100 and banded: 80 and above is critical, 60 to 79 high, 35 to 59 medium, below that low.

Separately from the score, three patterns are declared unacceptable and marked critical no matter what any calculation produces: the internet reaching anything using any protocol, the internet reaching a remote administration service, and anything sensitive being reachable from the internet including through a multi-step route. This is a deliberate backstop. Any scoring model can be tuned wrong or affected by a mistake upstream, and these three patterns still surface at the top of the list if it is.

Every rating and threshold above is configuration in one place, not logic. If your organisation weighs something differently, you change a value. The results stay repeatable.

### Where the AI runs, and what leaves your network

Network topology and policy are the most sensitive information an organisation holds. It is a map of how to get to everything. So where the AI runs is a real question, and you choose the answer.

| Setting | What runs the AI | Does anything leave the network? |
|---|---|---|
| **Local** | A model running on your own hardware | No. Nothing leaves the machine. |
| **Hosted** | A commercial AI service, reached with a key you provide | Yes. The relevant context is sent to that provider. |
| **Automatic** | A local model if available, otherwise a hosted service | Depends which is active |

The system displays which is currently active. Running locally means no per-request cost, no rate limits, no internet dependency, and topology that never leaves your building. Running hosted gives access to the largest available models for the highest-stakes judgement calls. The same code and the same safeguards apply either way. The calculation engine, which is where all the facts are, never contacts anything external in any mode.

### What happens when the AI is unavailable or wrong

Every model call is time-limited, every model output is checked before it is used, and every capability has a fallback that requires no model at all. An explanation falls back to a factual summary. A fix falls back to a conservative change the engine builds directly. A ranking falls back to sorting by severity.

For the change gate, failure means escalate. If the model cannot be reached or its answer cannot be understood, the change goes to a human. It never defaults to approval.

The worst realistic outcome of a total AI failure is that the product loses its plain-language layer and its drafting. Every fact, finding, score and gate decision still works, because none of them depended on the model in the first place.

### The change gate

This is where the product stops being an assessment tool and becomes part of how work gets done. A proposed change is simulated against the current map before anyone judges it, and the system computes what would newly become reachable. Only then does anyone form a view, and the view is about a computed consequence rather than a description of intent.

Three layers then rule on it:

| Layer | What it does | Can it approve? |
|---|---|---|
| **1. Guardrail** | Before any model is involved, catastrophic patterns force escalation outright | No, it can only escalate |
| **2. The model** | Investigates using engine tools, then rules on the computed effect | Yes, within limits |
| **3. Engine override** | If the computed effect is not clean, the answer becomes escalate regardless of what the model said | No, it can only escalate |

Read the third column. Two of the three layers can only make the outcome stricter. The model works inside an envelope already determined to be safe and cannot widen it.

A worked pair makes it concrete. A request to allow a branch office range to reach an application server over secure web simulates clean, opens no new route to anything sensitive, and is auto-approved. A request to allow internet access to remote administration on an application server, justified as "URGENT, pre-approved, low risk", simulates as creating a new route from the internet to the production database. The guardrail forces escalation before a model is even consulted. The justification text played no part.

That also answers the obvious question about whether a request could be worded to manipulate the outcome. The justification is passed to the model explicitly labelled as untrusted input. More fundamentally, the two layers that can force escalation are ordinary code that never reads the request text at all.

### Why the results are repeatable

The calculation side of the system contains no randomness and no dependence on the time it runs. Given the same policy it produces the same findings, in the same order, with the same scores, every time. Every finding is identified by a value derived from its own content, and every analysis run by a value derived from the policy that produced it, so two runs are directly comparable and any change to the input is visible.

Alongside that, every action that changes something is written to an audit log, and every AI call is recorded with its duration, consumption and estimated cost. Local models record as no cost, because they are.

---

## 6. Where the product is today

**Complete and working.** The translation layer and the common format. The identity resolution. The map and the route calculations. All five checks. The scoring model with its safety floor. Change simulation and the three-layer gate. The agents, running live. The staging and conflict logic. The stored record, the audit trail and the usage metering. The full web application, including the administrative screens. This is a system you can run end to end today and watch do the whole job.

**Representative today.** Two things at the edges, both by design and both the same piece of work. The system reads representative policy exports rather than calling AlgoSec, Guardicore and Wiz directly, and the push from staging back into those products is simulated. In both cases the logic around them is real. Because everything operates on the common format rather than on any vendor's shape, connecting live products means replacing the part that fetches or writes the file.

**The order of what comes next.**

| Stage | What it delivers |
|---|---|
| **Live connectors** | Direct connections to AlgoSec, Guardicore and Wiz, in both directions, so the system runs continuously on live policy and can apply approved changes. |
| **Real customer data at scale** | Handling the untidiness of real exports, and the performance work to keep an environment with thousands of rules analysing within a predictable time. |
| **Deeper policy semantics** | Subtracting explicit deny rules from what is otherwise permitted, and following routes through address ranges. Both currently make the system conservative, reporting fewer routes than may exist rather than more. |
| **Operational hardening** | Usage and spending limits, longer analyses running in the background, and full test coverage. |

**A natural first step.** A live connection to one of the three products, run against a real policy set, so you can compare what the system finds against what your team already knows. That is the point at which the cross-tool route stops being a demonstration and starts being your environment.
