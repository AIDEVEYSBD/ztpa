# Network Policy Reviewer

> **What this document is.** A complete walkthrough of the Network Policy Reviewer: the problem it solves, how information gets into it, the core flow from end to end, how it works out what is risky, where the artificial intelligence sits and what it is not allowed to touch, and what a person actually does with it day to day.
>
> It is written for someone evaluating the product rather than building it. There is no code and no mathematical notation. Where a technical term is unavoidable, it is explained the first time it appears. If a question occurs to you while reading, it is probably answered later in the same section or in the common questions at the end.

| | |
|---|---|
| **Product** | Network Policy Reviewer |
| **In one sentence** | One view of network access risk, assembled from several security tools that do not talk to each other, then explained, ranked, and used to gate changes. |
| **Who it is for** | Security teams, network teams, cloud teams, and the people who have to approve firewall changes. |
| **Where it stands today** | A complete, working system. It runs on representative policy exports from AlgoSec, Guardicore and Wiz. |
| **What comes next** | Direct connections to those three products through their own interfaces, so the same system runs on live data. |

---

## Contents

1. [The problem this solves](#1-the-problem-this-solves)
2. [What the product does](#2-what-the-product-does)
3. [The core flow step by step](#3-the-core-flow-step-by-step)
4. [How the information gets in](#4-how-the-information-gets-in)
5. [Working out what is the same machine](#5-working-out-what-is-the-same-machine)
6. [Building the map](#6-building-the-map)
7. [The five checks it runs](#7-the-five-checks-it-runs)
8. [How it decides what is serious](#8-how-it-decides-what-is-serious)
9. [Where the AI fits](#9-where-the-ai-fits)
10. [The five agents](#10-the-five-agents)
11. [The change gate](#11-the-change-gate)
12. [Staging and push](#12-staging-and-push)
13. [What you see on screen](#13-what-you-see-on-screen)
14. [Why the results are repeatable](#14-why-the-results-are-repeatable)
15. [Where the product is today](#15-where-the-product-is-today)
16. [Common questions](#16-common-questions)

---

## 1. The problem this solves

Almost no large organisation controls network access from one place. The firewall team runs one product. The cloud team runs another. A segmentation product sits between the servers inside the data centre. Each of these is good at its job, and each one shows a complete and confident picture of its own territory.

The difficulty is at the seams. Every tool draws a boundary around what it can see, and an attacker does not respect those boundaries. A route into your most sensitive systems can begin in the cloud, pass through a server the firewall team manages, cross a segment the microsegmentation product governs, and end at a database none of those three consoles considered to be their responsibility. Every individual step looks reasonable. Every individual console reports that everything is fine. The combination is the exposure, and nothing is looking at the combination.

This is not a hypothetical failure mode. It is the ordinary consequence of three facts that hold in nearly every environment:

| Fact | Consequence |
|---|---|
| Each tool only sees the rules it enforces | A route that crosses two tools is invisible in both |
| Each tool names machines its own way | The same server appears as two or three unrelated things |
| Each tool scores risk on its own scale | A critical in one console and a critical in another are not comparable |

There is a second, quieter problem. Policy accumulates. A rule opened for a project three years ago is still there. A broad rule near the top of a list silently overrides a narrower one below it, so the narrow rule never applies and nobody knows. Two rules overlap and only one of them is doing anything. Over time a policy set becomes something no individual understands in full, and the team's honest position becomes "we cannot remove that, we do not know what it will break."

The third problem is the change process itself. A request arrives, usually written in plain language, often marked urgent, and someone has to decide whether it is safe. That decision is made in a hurry, from a written justification rather than from a calculation, and it is made by a person who cannot see across all the tools either. This is how a small approval creates a large exposure.

The Network Policy Reviewer addresses all three: it merges the tools into one picture, it finds what is wrong in that picture, and it puts a calculation in front of every proposed change before anyone approves it.

---

## 2. What the product does

At the highest level, the system takes policy from several sources, turns it all into one common description, works out what can actually reach what, checks that picture against a set of rules about what good looks like, scores what it finds, explains it in plain language, and then uses the same machinery to judge proposed changes before they go live.

```
  Sources                What the system does                   What you get
  -------                --------------------                   ------------
  AlgoSec                1. Translate every rule into           One map
  Guardicore                one common format                   One ranked list of problems
  Wiz            ----->  2. Merge duplicate machines    ----->   Plain English explanations
  Your own                  into one identity                    Proven fixes
  source                 3. Map what can reach what              A gate on every change
                         4. Run five checks over that map        An audit trail
                         5. Score, rank and explain
```

Five things come out of that.

| Output | What it means in practice |
|---|---|
| **One picture** | Every rule from every source described the same way, on one map, with each connection labelled by the tool that permits it. |
| **A ranked list of real problems** | Not thousands of alerts. A short worst-first list, grouped by underlying cause, so the top item is genuinely the thing to do first. |
| **An explanation for each one** | Written in plain language, tied to the specific rules that cause it, so an engineer can act on it and a manager can understand it. |
| **A fix that has been proven** | The system drafts a change and then re-runs its own analysis to confirm the change actually removes the problem and does not create a new critical one. |
| **A gate on changes** | Every proposed change is simulated first. The decision is made on what the change would actually do, not on how the request was worded. |

One principle runs through all of it and is worth stating early, because it answers most of the questions people have about trusting an AI system with network policy:

> **The calculation owns the facts. The AI owns the words and the judgement.** Which machines are the same, what can reach what, which rules overlap, how severe something is, what a proposed change would open up: all of that is computed, repeatably, by ordinary software. The AI model explains, ranks, drafts and classifies. It never computes a route through the network and never decides on its own whether a change is safe. When it wants a fact, it asks the calculation engine and works from the answer it gets back.

Section 9 covers what that boundary means in detail and why it is enforced rather than merely intended.

---

## 3. The core flow step by step

This is the whole system in order. Everything in the rest of the document is a detail of one of these twelve steps.

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

**Step 2. Translate.** Each source is read by its own adapter and every rule is rewritten as the same kind of statement: *this source may reach this destination, using this service, and it is allowed or denied.* Each translated rule keeps two things attached to it permanently: which tool it came from, and that tool's own reference for it, such as `ALGO-002`. From this point on, nothing in the system needs to know or care which vendor a rule came from.

**Step 3. Decode.** For each rule the system works out what is really being permitted: the protocol, the port or range of ports, and the application that implies, such as web traffic, name lookups or remote administration. Where a tool states the application explicitly it is used; where it does not, the system infers it from a fixed lookup table and records that it was inferred. Named objects such as `db-prod-01` are resolved to what they stand for, along with their tags, so the system knows which destinations hold sensitive data.

**Step 4. Merge.** The same server appears under different names in different tools. Using only signals that cannot be wrong, the system merges those into one asset. This is the step that makes cross-tool analysis possible at all: without it, the map is three disconnected fragments.

**Step 5. Map.** Every permitted connection becomes a line on one map, with every rule that grants it attached, labelled by tool and rule reference. Each point on the map is placed in a zone, so the system knows when a connection crosses from a less trusted area to a more trusted one.

**Step 6. Check.** Five independent checks run over the map: overly broad rules, overlapping rules, rules that are never actually applied, routes from the internet to sensitive systems that cross more than one tool, and traffic permitted on paths your inspection tooling cannot see into.

**Step 7. Score.** Every finding gets a number from 0 to 100, built from four questions: how many parties could use it, how dangerous is what they can do, how much does the destination matter, and does it cross a trust boundary. Separately, three categorically unacceptable patterns are marked critical no matter what the number says. The list is sorted worst first, in a fixed order that does not change between runs.

**Step 8. Explain.** For each finding the AI writes a plain-language explanation of why it matters, grounded in the specific rules behind it. It then groups findings by underlying cause so one root problem shows as one action rather than fifteen alerts, and ranks the resulting actions.

**Step 9. Fix.** For any finding, the AI drafts a specific change. The engine applies that change to a copy of the data and re-runs all five checks to answer two questions: did the finding disappear, and did anything new and critical appear. If the answer is not clean, the model sees why and tries again. A fix is only accepted once the engine certifies it. The whole attempt trail is shown on screen.

**Step 10. Gate.** Any proposed change, whether drafted by the system or requested by a person, is simulated against the current map before anyone judges it. The system computes what would newly become reachable, then three layers rule on that computed result: a guardrail that can only escalate, a model that investigates and recommends, and an engine override that can only escalate. The outcome is auto-approve or escalate, with the reasoning attached.

**Step 11. Stage.** Approved changes go to a staging area rather than straight to the source system. Staging checks the change against the current state of the target, detects conflicts, and applies it in steps.

**Step 12. Record.** Every analysis run is stored with an identifier derived from the policy that produced it. Every change and decision is written to an audit log. Every AI call is recorded with its duration, consumption and estimated cost.

### Where the AI enters, and where it does not

The same twelve steps, coloured by who is responsible:

| Steps | Who does the work | What that means |
|---|---|---|
| 1 to 7 | Ordinary software only | Collecting, translating, decoding, merging, mapping, checking and scoring involve no AI at all. Run it twice, get the identical answer. |
| 8 | AI, with no consequence | Wording and grouping. A mistake here is a badly phrased explanation next to a correct finding. |
| 9 | AI proposes, engine proves | The model drafts; the engine re-runs the analysis and rejects anything that does not hold. You never see an unproven fix. |
| 10 | Both, with the engine holding a veto | The model can recommend and investigate. Two of the three layers are ordinary code and can only make the outcome stricter. |
| 11 and 12 | Ordinary software only | Conflict detection, application and record keeping involve no AI. |

### What a person actually does

In practice the loop is short. You open the ranked list, read the top action and its explanation, ask the system to draft a fix, look at the proof that it resolves the finding, discuss it with a colleague in the comments if you need to, and send it to the gate. The gate rules on it, it goes to staging, and it gets applied. If a change request arrives from elsewhere in the business, it enters at step 10 and takes the same path from there.

---

## 4. How the information gets in

### 4.1 The three sources

The system reads policy from three products today, chosen because together they cover the three places network access is usually decided.

| Source | What it governs | What it contributes |
|---|---|---|
| **AlgoSec** | Traditional firewalls at the network edge and between zones | Ordered firewall rule sets, address objects, and the order rules are evaluated in |
| **Guardicore** | Microsegmentation between workloads inside the environment | Server to server rules, labels, and application identity where it is declared |
| **Wiz** | Cloud posture and exposure | Which cloud resources are reachable from the internet, and how |

These are read as policy exports: the same content those products already produce for reporting and review. Today the system runs on representative exports of that kind, so the whole product can be demonstrated end to end without touching a customer environment. The next step is direct connections to each product's own interface so the exports arrive automatically and continuously. Nothing downstream changes when that happens, because everything after the first translation step already works on the common format rather than on any vendor's own shape. Section 15 covers this in more detail.

### 4.2 One common way of describing a rule

The first thing the system does is translate. Every rule from every source becomes the same kind of statement:

> Something on one side may reach something on the other side, using a particular service, and this is allowed or denied.

That sounds obvious, but it is doing real work. The three products express the same idea in three genuinely different ways, and the translation is what makes them comparable at all.

| What the rule really says | AlgoSec writes it as | Guardicore writes it as | Wiz writes it as |
|---|---|---|---|
| Who is allowed to connect | A source address or a named address object | A label on a group of workloads | A cloud resource or an exposure source |
| What they may reach | A destination address or object | A label on the destination group | The exposed cloud resource |
| What they may do | A service such as tcp/443 | A port with an optional application name | A port and protocol |
| Whether it applies | Rule order within the device | Policy ordering | Effective exposure |

After translation each rule carries the same fields regardless of where it came from, plus two things that matter later: which tool it came from, and that tool's own reference for the rule, such as `ALGO-002`. That reference is never discarded. When the system later tells you something is wrong, it can point at the exact rule in the exact console where you go to fix it.

### 4.3 Reading what a rule actually permits

A rule that says `tcp/443` is easy. Real policy is messier, and reading it correctly is one of the places the product does more than the obvious.

The system works out, for each rule, both the low-level detail and the application that detail implies. Low-level means the protocol and the port or range of ports. The application means what actually travels over it: web traffic, name lookups, remote administration, and so on. Some tools declare the application explicitly. Where they do not, the system infers it from a fixed lookup table, and it records which of the two happened so you can always tell a declared fact from an inferred one. The inference is a table lookup, not a judgement call, and not a model call.

This matters more than it sounds, and the clearest example is a modern one.

**The QUIC blind spot.** Newer web traffic increasingly uses a protocol called QUIC, which carries what used to be ordinary web traffic over UDP port 443 rather than TCP port 443. Many established firewalls cannot inspect it. So a rule that permits UDP on port 443 can quietly create a channel that your inspection tooling does not see into, while every console reports a perfectly normal looking allow rule.

Most tools see a UDP allow on port 443. This system sees QUIC, understands that QUIC is not inspectable by the controls in place, and flags it. It also checks a related case: if both the inspectable path and the uninspectable one are open at the same time, traffic will silently prefer the uninspectable one, and the inspection you believe you have is not happening. That check is called fallback not blocked, and it is the kind of finding that only exists if you decode the rule rather than reading its numbers.

### 4.4 Named objects

Firewall rules rarely contain raw addresses. They contain names such as `db-prod-01` or `app-segment`, defined elsewhere in the same export. The system reads those definitions, so it knows that `db-prod-01` means one specific machine and that `app-segment` means a whole range, and it knows the tags attached to them, such as whether a machine holds payment card data.

Those tags are the reason the system can distinguish a broad rule pointing at a test box from the same broad rule pointing at a customer database. Section 8 explains how they feed into scoring.

### 4.5 Adding a source that is not on the list

Every organisation has something the standard list does not cover: an SD-WAN product, a cloud provider's native controls, a home-grown policy store.

The system handles this without new development. You paste a sample of that tool's export. The AI proposes a description of how to read it: where the rules live in the file, and which fields mean source, destination, service, action and rule reference. Then the engine tests that description by actually using it to translate your sample, and reports whether it worked and which fields it could not map. If it did not work, the specific reason goes back to the model and it tries again, up to three attempts. A person reviews and approves the result before anything is registered.

The important detail is what gets produced. The AI writes a description, not a program. At the point the connector runs, the model is not involved at all: the ordinary, deterministic translator follows an approved description. You are approving a short piece of configuration you can read, not code you have to trust.

### 4.6 What the sample data means today

Today the three connectors read representative exports rather than calling the live products. That was a deliberate choice so the entire system could be built, tested and demonstrated on a known dataset without needing access to anybody's production security tooling.

Everything after that first translation step is real and operates on real logic: the merging, the map, the five checks, the scoring, the change simulation, the fixes, the audit trail. Substituting live connections means replacing the part that fetches the file. The common format the rest of the system depends on stays exactly as it is.

---

## 5. Working out what is the same machine

This section is short, and it is one of the two ideas the whole product rests on.

The same server appears in different tools under different names. The cloud tool calls it `appsrv-07`. The firewall calls it `app-server-07`. The segmentation product calls it something else again. Until the system knows those are one machine, the map has three disconnected fragments and the route that crosses them is invisible. The merge is the only reason a cross-tool route can be seen at all.

The tempting approach is to guess: match similar looking names, assume things that sound alike are alike. The system deliberately does not do this, because a wrong merge does not produce a slightly worse answer. It produces a confident, false statement about what can reach what. So merging uses only signals that cannot be wrong.

| Signal | What it means |
|---|---|
| **Same address** | Two names observed at the same specific address are the same machine |
| **Same name in more than one tool** | A name that appears identically across tools is one thing |
| **A person confirmed it** | A reviewer looked at a suggestion and approved the merge |

Nothing else merges automatically. When a merge does happen, the system records which of the three reasons applied, so any merge can be inspected and explained later.

There is a separate, softer feature for the cases the strict rules miss. A machine registered as `db-prod-01` in one place and `rds-prod-customers` in another is probably the same database, but "probably" is not good enough to act on. The system uses the AI to notice such pairs and **suggest** them for review. It presents them on the Assets and Identity screen and waits. It will not merge them on its own, and a reviewer can undo a confirmed merge afterwards.

The distinction is deliberate: the AI is allowed to raise a question. It is not allowed to change a fact.

---

## 6. Building the map

With every rule in one format and every machine identified once, the system builds a map of allowed connections.

Each point on the map is a machine, a group, or a range of addresses. The internet itself is a point on the map. Each line between two points means access is permitted from one to the other, and each line carries every rule that grants that access, with the tool and rule reference attached.

Parallel grants are kept separate rather than merged together. If three different rules in two different tools all permit the same connection, the map shows three grants, not one line. This matters when you go to fix something: removing one rule may not close the connection if two others still allow it, and the map tells you that before you find out the hard way.

### Zones and trust boundaries

Every point on the map is placed in a zone. This is a straightforward lookup rather than a judgement.

| Zone | What lands there |
|---|---|
| **Internet** | The internet itself |
| **Demilitarised zone** | Anything tagged as internet facing, public, or in the DMZ |
| **Development** | Anything tagged development, sandbox or test |
| **Internal** | Everything else, which in practice means production and internal systems |

Zones exist because the same connection means different things depending on which direction it crosses. Access from the internet into an internal system is a boundary violation. Access from the internet into a system that was built to face the internet is not. The system treats these differently, and Section 8 explains how.

### What "can reach" means here

When the system says one thing can reach another, it means there is a chain of permitted connections leading from the first to the second. That chain can be several steps long, and each step can be permitted by a different tool. Working out those chains is done by a well-established graph traversal, not by an AI model, and it is the calculation everything else depends on.

Two deliberate boundaries are worth stating plainly. First, the system limits how long a chain it will follow and how many candidate routes it will consider, because the number of possible routes through a large network grows explosively and an unbounded search would never finish. Second, it does not treat an address range as a stepping stone. If a rule permits access to a whole subnet, the system counts machines in that subnet as destinations, but does not assume an attacker can then act as that entire subnet to reach somewhere else. This is conservative: it means the system may find fewer routes than exist, never more. Both boundaries are on the list of things that get extended for real customer data, and both are documented rather than hidden.

---

## 7. The five checks it runs

Five independent checks run over the map. They do not overlap and each answers a different question.

| Check | The question it answers | Why it matters |
|---|---|---|
| **Overly broad rules** | Does this rule permit far more than it needs to? | The single most common source of real exposure |
| **Overlapping rules** | Do two rules cover the same ground? | Policy hygiene. One of them is probably doing nothing |
| **Shadowed rules** | Is this rule never actually applied? | A rule that looks like protection but is not |
| **Cross-tool routes** | Can the internet reach something sensitive through a chain that crosses tools? | The exposure no single console can show you |
| **Uninspectable traffic** | Is traffic permitted on a path your controls cannot see into? | The QUIC blind spot and its relatives |

### Overly broad rules

A rule is flagged when it grants more than it plausibly needs. Several patterns trigger this: a rule that permits every protocol rather than a specific one; a rule that lets the entire internet reach something sensitive; a rule that opens remote administration or database access to a wide range of sources rather than to specific machines; a rule that lets a broad range reach a sensitive system when a single machine would do.

This check catches the ordinary, unglamorous problem that causes most incidents. The rule was opened wide during a migration, the migration finished, and nobody narrowed it again.

### Overlapping rules

The system compares address ranges properly rather than comparing text. Two rules written differently can cover exactly the same ground, and one rule can sit entirely inside another. Where that happens the system reports it, saying whether one contains the other or they merely overlap.

This is hygiene rather than exposure, and it is scored accordingly: these findings stay low priority and never crowd out something urgent. But they are how a policy set gets smaller instead of larger, and a team that cleans them up gets a policy they can actually reason about.

### Shadowed rules

Firewall rules are evaluated in order, and the first match wins. So a broad rule near the top can prevent a narrower rule below it from ever being reached.

Two versions of this exist and they are very different in seriousness. If a **deny** rule is shadowed by an earlier allow, then traffic you believe you are blocking is in fact permitted. The console shows the deny sitting there and it does nothing. The system treats this as a real exposure and scores it on the full scale. If an **allow** rule is shadowed, the effect is dead configuration: harmless, but it should be removed, and it is scored as low priority.

### Cross-tool routes

This is the headline capability and the reason the rest of the architecture exists.

The system looks for chains that start at the internet and end at something sensitive, and it keeps the ones that cross at least two different tools. A route contained inside one product is something that product could in principle have shown you. A route that crosses two or three is one that nothing you own can show you, because no single console holds all the pieces.

In the demonstration dataset the route looks like this:

```
   Internet  ->  lb-public-01  ->  app-server-07  ->  internal-app  ->  db-prod-01

                     Wiz              Wiz            Guardicore         AlgoSec

                cloud load        the server         the internal      the customer
                 balancer       the cloud tool        application        database
                                calls appsrv-07                      holding card data
```

Read it hop by hop. Wiz permits the internet to reach a public load balancer, which is entirely normal and exactly what a load balancer is for. Wiz permits the load balancer to reach an application server, which is also normal. Guardicore permits that application server to reach the internal application tier, which is again normal. AlgoSec permits the internal application tier to reach the production database, which is the most normal thing on the list.

Four reasonable decisions. One route from the open internet to the customer database. Each console involved is correct about its own hop and blind to the other three.

Note the third hop in particular. Wiz calls that server `appsrv-07` while AlgoSec and Guardicore call it `app-server-07`. Without the identity merge described in Section 5, the chain breaks at that point and the route simply does not exist as far as the system is concerned. That merge is not a convenience feature. It is the thing that makes the differentiator work.

Routes like this are automatically treated as critical when they cross from the internet into an internal system and end somewhere sensitive, regardless of what the score would otherwise have been.

### Uninspectable traffic

Described in Section 4.3. The system flags traffic permitted on paths your inspection tooling cannot see into, particularly QUIC on UDP port 443 reaching sensitive systems from a lower trust zone, and the case where an inspectable and an uninspectable path are open at the same time so traffic silently takes the one you cannot see.

---

## 8. How it decides what is serious

Everyone who has used a security product has been handed a list of two thousand findings all marked high. The score is only useful if it means something, so it is worth explaining exactly how this one is arrived at. There is no notation in this section.

Every finding gets a number from 0 to 100. That number comes from four questions.

### Question one: how many parties could use this?

Measured from how wide the source of the rule is. A rule that permits the entire internet is at the top of this scale. A rule that permits one specific machine is at the bottom.

| The rule permits | Rated |
|---|---|
| The whole internet, or any source at all | Highest |
| A very large block of addresses | High |
| A medium block, such as a corporate network | Moderate |
| A small block, such as one office | Low |
| A single machine, or one named identity | Lowest |

### Question two: how dangerous is what they can do?

Not all access is equal. Being able to load a web page is different from being able to log in and run commands.

| The access granted | Rated | Examples |
|---|---|---|
| Any protocol at all, unrestricted | Highest | A rule with no service restriction |
| Remote administration and lateral movement | Highest | Remote desktop, secure shell, Windows file sharing and remote management |
| Direct database access | High | The standard ports for the common database products |
| Infrastructure control planes | High | Container orchestration control interfaces |
| Ordinary web and application traffic | Low | Web, secure web, name lookups, time sync |
| Anything unrecognised | Moderate | Treated cautiously rather than dismissed |

Administration access sits at the top alongside "any protocol" for a reason. If someone can log in and run commands on a machine, everything else that machine can reach is effectively theirs too. That is how a single foothold becomes a breach.

### Question three: how much does the destination matter?

Taken from the tags on the destination, using the most serious one that applies.

| The destination is tagged | Rated |
|---|---|
| Crown jewel | Highest |
| Payment card data, customer data, or health data | High |
| Production | Moderate |
| Development, sandbox or test | Lowest |
| Untagged | Slightly below moderate |

### Question four: does it cross a trust boundary?

The first three questions describe the connection. This one describes the direction it travels.

| The connection goes | Effect on the score |
|---|---|
| From the internet into an internal system | Raised by half again |
| From the DMZ into an internal system | Raised by a quarter |
| From development into production | Raised by a quarter |
| Anywhere else, including from the internet into the DMZ | No change |

That last row is deliberate and worth pausing on. A system in the DMZ is supposed to face the internet. Treating that as a boundary violation would flood the list with findings about systems doing exactly what they were built to do, and the genuinely serious items would be buried underneath. The boundary factor only ever raises a score, and only when a real boundary is actually crossed.

### How the four combine

Questions two and three combine into a measure of impact: how much damage this particular access would do to this particular destination. Importantly, the destination sets a ceiling. However dangerous the access, a finding about a sandbox machine cannot outrank a finding about a customer database. This is the single most useful property of the model, because it is what stops the ranked list filling up with technically severe findings about systems nobody cares about.

Question one then scales that impact according to how many parties could exploit it, but it never scales it to nothing. Even a single-machine source keeps meaningful weight, because a compromise of that one machine is exactly how these things start.

Finally question four raises the result if a real boundary is crossed. The outcome is capped at 100 and sorted into four bands.

| Score | Band |
|---|---|
| 80 and above | Critical |
| 60 to 79 | High |
| 35 to 59 | Medium |
| Below 35 | Low |

### A worked example

A rule permits remote desktop access from the entire internet to a database tagged as holding payment card data.

| Question | Answer | Rating |
|---|---|---|
| How many parties could use it? | The entire internet | Highest |
| How dangerous is the access? | Remote desktop, which is full remote administration | Highest |
| How much does the destination matter? | It holds payment card data | High |
| Does it cross a boundary? | Internet into internal | Raises by half again |

Every factor is at or near its maximum, and the boundary crossing pushes the raw result past the ceiling. The finding scores 100 and lands in the critical band. Which is correct, because that is a genuine emergency.

### The safety floor

Separately from the score, certain patterns are declared unacceptable and are marked critical no matter what any calculation produces. There are three:

- A rule that lets the internet reach anything using any protocol at all
- A rule that lets the internet reach a remote administration service
- Anything sensitive being reachable from the internet, including through a multi-step route

This exists for a specific reason. The score is a model, and any model can be tuned wrong, drift as tags change, or be affected by a mistake somewhere upstream. The floor is a hard backstop: even if every other part of the system got the numbers wrong, these three patterns still surface at the top of the list. A forced finding also sorts above an equally severe non-forced one, so it appears first on screen.

### The numbers are yours to set

Every rating and threshold described above is configuration rather than logic. The band cut-offs, the weighting given to exposure versus impact, the boundary multipliers, and the ratings for each class of service and destination are all adjustable in one place. If your organisation treats development to production traffic as more serious than the default, you change one value. The logic does not change, and the results stay repeatable.

The ratings themselves are lookup tables rather than calculations, and that is intentional. Whether remote desktop access is more dangerous than web access is a policy position, not something to be derived. The tables hold the policy; the way they combine is the engineering.

---

## 9. Where the AI fits

This is usually the section people read first, so it is worth being direct.

### The dividing line

There is one rule, and it is enforced by how the system is built rather than by instructions given to a model.

| The calculation engine owns | The AI owns |
|---|---|
| Translating rules into the common format | Explaining a finding in plain language |
| Deciding which machines are the same | Grouping findings by underlying cause and ranking them |
| All address and range arithmetic | Drafting a proposed fix |
| Working out what can reach what | Recommending approve or escalate on a change |
| Which findings exist and what they score | Writing the posture report |
| What a proposed change would open up | Turning a written request into a structured one |
| Whether a proposed fix actually works | Suggesting possible duplicate machines for review |

The model never works out a route through your network. When it needs to know whether one thing can reach another, it asks the engine and reasons about the answer it gets back. This is not a stylistic preference. It is the difference between a system whose facts you can verify and one whose facts you have to trust.

### Where the model runs, and what leaves your network

Network topology and policy are the most sensitive information an organisation holds. It is a map of how to get to everything. So the question of where the AI runs is a real one, and the answer is that you choose.

| Setting | What runs the AI | Does anything leave the network? |
|---|---|---|
| **Local** | A model running on your own hardware | No. Nothing leaves the machine. |
| **Hosted** | A commercial AI service, reached with a key you provide | Yes. The relevant context is sent to that provider. |
| **Automatic** | A local model if one is available, otherwise a hosted service | Depends which is active |

The system shows which is currently active. Running locally means no per-request cost, no rate limits, no internet dependency, and topology that never leaves your building. Running hosted means access to the largest available models for the highest-stakes judgement calls. The same code, the same safeguards, and the same handling of bad model output apply either way. Switching between them changes only who generates the language.

Two things never require any AI service at all, because they are ordinary software: the facts the engine computes, and the fallback behaviour described below.

### The eight things the AI does

| # | Capability | What it produces |
|---|---|---|
| 1 | **Change triage** | A recommendation to auto-approve or escalate, made from the computed effect of the change |
| 2 | **Ask your network** | A plain-language answer to a plain-language question, built from engine results |
| 3 | **Explanation** | Why a specific finding matters, tied to the specific rules causing it |
| 4 | **Grouping and ranking** | Findings collapsed into a short worst-first list of actions by underlying cause |
| 5 | **Fix drafting** | A concrete proposed change, then proven by the engine |
| 6 | **Posture report** | A summary for stakeholders, including compliance and zero-trust framing |
| 7 | **Request intake** | A free-text change request turned into a structured, checkable one |
| 8 | **Duplicate suggestions** | Possible duplicate machines put forward for human review, never merged automatically |

### What happens when the model is unavailable or wrong

This is the question that separates a demonstration from something you would run. Models are sometimes slow, occasionally unreachable, and sometimes produce output that does not make sense.

Every part of the system that uses a model has a defined behaviour for all three cases, and none of them is "crash" or "guess".

- **Every model call is time-limited.** A slow or cold model is abandoned rather than left to hang the screen.
- **Every model output is checked before use.** If the output cannot be understood, it is discarded.
- **Every capability has a fallback that requires no model at all.** An explanation falls back to a factual summary. A fix falls back to a conservative change the engine builds directly. A ranking falls back to sorting by severity.
- **For the change gate, failure means escalate.** If the model cannot be reached or its answer cannot be understood, the change goes to a human. It never defaults to approval. This is the one place where the safe direction is unambiguous, and the system always takes it.

The worst realistic outcome of a total AI failure is that the product loses its plain-language layer and its drafting. Every fact, every finding, every score and every gate decision still works, because none of them depended on the model in the first place.

---

## 10. The five agents

An agent, here, means the model working in a loop rather than answering once: it proposes something, the engine tests it, the model sees the result, and it revises. The engine is always the judge. The model gets to try again; it does not get to declare itself correct.

There are five.

| Agent | What it does | Where you see it |
|---|---|---|
| **The fix loop** | Drafts a fix for one finding and proves it works | Risk To-Do |
| **The campaign** | Fixes the whole posture in worst-first order | Risk To-Do |
| **The change investigator** | Gathers evidence, then rules on a proposed change | Change Gate |
| **The connector author** | Writes and tests a reader for an unfamiliar source | Connectors |
| **Ask the network** | Answers questions by calling engine tools | Ask the Network |

### The fix loop

Given one finding, the model proposes a change: remove this rule, narrow its source to this range, restrict it to this service, or move it above another rule. The engine then applies that change to a copy of the data and re-runs all five checks.

That re-run is the proof. Two questions get answered: did the original finding disappear, and did anything new and critical appear? Both have to come out right. The model sees the verdict and, if the fix did not hold or created a new problem, tries a different approach, up to three attempts.

A fix is only accepted when the engine certifies it. If no proposal from the model passes, the system falls back to a conservative change it constructs itself, and validates that the same way.

You see the whole attempt trail on screen, for example "narrow rule fourteen, still reachable, remove rule fourteen, resolved." You are not asked to trust the outcome. You are shown the working.

### The campaign

The fix loop handles one finding. The campaign handles the posture.

It picks the worst open finding, drafts a fix for it, and then does something important: it re-simulates against the accumulated state, not against the original snapshot. This matters because fixing one rule changes the map, which can resolve other findings or expose new ones. A plan built by fixing each finding in isolation would not survive contact with reality.

Each step is applied only if it removes its target and opens nothing new and critical. Anything that fails that test is marked for human review and skipped. The campaign is not permitted to make the posture worse at any step.

What comes out is a sequence with a trajectory attached, for example criticals going from four to three to two to one to zero, along with the specific proven change at each step and any residual findings.

The plan is advisory. Nothing is applied to live policy. When you are satisfied, you submit it, and each proven step becomes its own change request that goes through the change gate individually. The gate rules on each one separately, and the normal audit and staging flow applies. The campaign proposes an agenda. It does not enact one.

### The change investigator

This one has the highest stakes: deciding whether a proposed change is safe. It is covered in full in Section 11.

### The connector author

Covered in Section 4.5. Proposes a description of an unfamiliar export format, has the engine test it by actually translating your sample, and revises from the specific failure reason, up to three attempts. A person approves the result.

### Ask the network

A question box. You ask something like "can the internet reach the production database, and through which route and which tools?" The agent decides which engine tools it needs, calls them, and narrates the answer from the results.

The tools available to it are a fixed, small set: look up a machine, check whether one thing can reach another, find the routes between two things, show everything that can reach a given system, list findings, and simulate a change. Each returns computed facts.

The answer arrives with the trail of tool calls that produced it, so you can see which facts it used. The value is not that it knows something you could not find out. It is that finding out currently means opening four consoles and holding the answer in your head.

### What all five have in common

| Guarantee | What it means |
|---|---|
| **The engine judges** | A proposal is only honoured if the engine proves it, by re-simulation, by computed effect, or by actually translating your sample |
| **Bounded** | Every loop has a hard limit on rounds and tool calls, and every call has a time limit |
| **Fails safely** | An unreachable or nonsensical model produces a defined conservative outcome, never a crash and never a silent wrong answer |
| **Portable** | Local or hosted, the contracts and safeguards are identical |
| **Metered** | Every call records what was used, how long it took and what it cost |
| **Auditable** | Every agent returns its working, and the screen shows it |

---

## 11. The change gate

The change gate is where the product stops being an assessment tool and starts being part of how work gets done.

### The problem it addresses

Someone requests a firewall change. It arrives as a sentence. It is usually urgent. The approver has minutes, cannot see across all the tools, and is reading a justification written by the person who wants the change approved. That is not a decision process; it is a negotiation with incomplete information.

### How a change moves through

```
   Written request
        |
        v
   Turned into a structured change      the model reads the text, the engine checks the result
        |
        v
   Simulated against the current map    what would this actually open up?
        |
        v
   Three layers of judgement            guardrail, then model, then engine override
        |
        v
   Auto-approve  or  Escalate           with the reasoning and evidence attached
        |
        v
   Staging                              then push to the source system
```

### Simulate first, judge second

This ordering is the whole design. The system builds a second copy of the map with the proposed rule added, compares it to the current one, and computes what changed:

- Which new routes from the internet to sensitive systems now exist that did not before
- Which systems became newly exposed
- Which trust boundaries the new routes cross
- Whether the rule itself trips any of the overly-broad patterns

Only then does anyone, human or model, form a view. The judgement is made about a computed consequence, not about a description of intent.

### Three layers

| Layer | What it does | Can it approve? |
|---|---|---|
| **1. Guardrail** | Before any model is involved, catastrophic patterns force escalation outright | No, it can only escalate |
| **2. The model** | Investigates, gathers evidence from engine tools, and rules on the computed effect | Yes, within limits |
| **3. Engine override** | If the computed effect is not clean, the decision becomes escalate regardless of what the model said | No, it can only escalate |

Read the third column. Two of the three layers can only ever make the outcome stricter. The model operates inside an envelope that was already determined to be safe, and it cannot widen that envelope. It can add evidence and it can recommend escalation. It cannot raise the organisation's risk tolerance.

Between layers one and two the model investigates. Rather than ruling immediately, it decides what it needs to know and calls engine tools to find out: who can currently reach this system, what routes exist between these two points, are there existing findings here. It gets up to four such calls. All results are real computations. If it asks for a tool that does not exist or supplies bad arguments, that is recorded as evidence and the loop continues rather than failing.

Its final answer, and the evidence trail behind it, is shown with the decision.

### Two requests, side by side

**Request one: allow a branch office range to reach an application server over secure web.**

The simulation shows a narrow source, an ordinary service, and no new route to anything sensitive. All criteria come back clean. Result: auto-approve.

**Request two: allow internet access to remote administration on an application server. Justification: "URGENT, pre-approved, low risk."**

The simulation shows that this creates a new route from the internet to the production database, and that the rule opens remote administration to the entire internet. The guardrail forces escalation before a model is even consulted. Result: escalate, with the specific new route named.

The justification text played no part. The system judged what the change would do.

### About the wording of requests

Since the system reads text written by whoever wants the change, an obvious question is whether a request could be written to manipulate the outcome.

Two things prevent it. The requester's justification is passed to the model explicitly labelled as untrusted input, so it is treated as context rather than instruction. More fundamentally, the model's approval is bounded by layers one and three, which are ordinary code and read no text at all. They read the computed effect. A request that opens a new internet route to a sensitive system escalates regardless of what any accompanying text says, because the code that made that decision never looked at the text.

### The audit trail

Every decision is recorded: what was requested, what the simulation computed, what the model concluded, what evidence it gathered, which layer produced the final answer, and what that answer was. The decision log is on screen. Decisions are computed fresh each time from the current state rather than stored as fixed verdicts, so a decision always reflects the policy as it stands.

---

## 12. Staging and push

A decision is not a deployment. After the gate rules on a change, approved changes go to a staging area rather than straight to the source system.

Staging holds a change and shows what it will do. When you push it, the system runs a stepped process that checks the change against the current state of the target system and detects conflicts: another rule that would interfere, a change to the same rule since the request was raised, an ordering problem. Where it can resolve a conflict it shows the resolution and the reasoning. The conflict detection uses the same engine calculations as everything else.

The push itself is currently simulated, for the same reason the connectors read sample exports: the system does not yet write to a live security product. The steps, the conflict detection and the resolution logic are real. Turning on a live push is the same piece of work as turning on a live connector, in the opposite direction, and it is part of the same next step described in Section 15.

The full path a change takes, from problem to deployment, is:

```
  Risk To-Do            Change Gate            Staging              Source system
  find it, draft   -->  simulate and     -->   hold, check    -->   apply
  a fix, discuss        decide                 for conflicts
```

Each stage keeps its own record, and the finding, the change request, the decision and the staged item stay linked, so any deployed change can be traced back to the risk that prompted it.

---

## 13. What you see on screen

The product is one web application. These are the screens.

| Screen | What you do there |
|---|---|
| **Network Map** | See the whole environment as one map, filter it, and trace the cross-tool route from the internet to a sensitive system with each hop labelled by the tool that permits it. |
| **Risk To-Do** | The ranked worst-first list. Expand an action to see the findings behind it, read the plain-language explanation, draft a fix and watch the engine prove it, comment, iterate, and send it on. Also where you run and review a whole-posture campaign. |
| **Change Gate** | Submit a change in plain language or as structured fields, evaluate it, and see the decision with the criteria, the evidence the investigator gathered, and the decision log. |
| **Staging Area** | Approved changes waiting to be applied, with the conflict check and stepped push. |
| **Ask the Network** | Ask a question in plain language, get a grounded answer with the trail of engine tools that produced it. |
| **Posture Report** | A written summary for stakeholders, including compliance and zero-trust framing, built from the actual findings. |
| **Connectors** | Paste a sample from an unfamiliar tool, have a reader proposed and tested, and approve it. |
| **Assets and Identity** | Every machine as one identity, which tools saw it, which addresses it has, and the duplicate suggestions waiting for review. |
| **Ingested data** | Exactly what came in from each source, so you can check the input rather than take it on faith. |
| **Snapshots** | Each analysis run, when it happened and what it contained. |
| **Tools and usage** | Which capabilities are available to which roles. |
| **Metrics and cost** | AI usage: how many calls, how long they took, what they cost, broken down by capability. |

---

## 14. Why the results are repeatable

For a system that produces findings people will act on, "run it twice, get the same answer" is not a technical nicety. It is the basis for trusting anything it says.

The calculation side of this system contains no randomness and no dependence on the time it runs. Given the same policy, it produces the same findings, in the same order, with the same scores, every time.

That is enforced structurally. Every finding is identified by a value derived from its own content, so the same finding arising from the same data always gets the same identifier. Every analysis run gets an identifier derived from the policy that produced it, so any change to the input produces a visibly different run. Findings are sorted by a fixed, fully specified ordering, so two runs never disagree about which item is third on the list.

Three practical consequences:

- **You can compare two runs.** A finding that appears in both is the same finding, so you can see what changed between Monday and Friday.
- **You can verify it.** Rerun an analysis and compare. Any difference means the input changed, and you can find out what.
- **Nothing is hidden in a cache.** The analysis is recomputed from the policy rather than read from a stored verdict.

Alongside that, two records accumulate. Every action that changes something is written to an audit log: what happened, to what, and when. And every AI call is recorded with the model used, how long it took, how much was consumed and an estimated cost, which is what the Metrics and Cost screen reads. Local models record as no cost, because they are.

The AI layer, by its nature, will phrase things differently between runs. That is why the boundary in Section 9 matters: the varying part of the system is the wording, not the findings.

---

## 15. Where the product is today

### What is complete and working

The translation layer and the common format. The identity resolution. The map and the route calculations. All five checks. The scoring model with its safety floor. Change simulation and the three-layer gate. All five agents, running live. The staging and conflict logic. The stored record, the audit trail and the usage metering. The full web application, including the administrative screens.

This is a system you can run end to end today and watch do the whole job.

### What is representative today

Two things at the edges, both by design and both the same piece of work.

**Reading from the three products.** The system reads representative policy exports rather than calling AlgoSec, Guardicore and Wiz directly. This let the entire product be built and validated against a known dataset. Because everything downstream operates on the common format rather than on any vendor's shape, connecting the live products means replacing the part that fetches the file. That is the immediate next step.

**Writing back to them.** The push from staging is simulated for the same reason. The conflict detection and resolution are real calculations; what is not yet live is the final write.

### The order of what comes next

| Stage | What it delivers |
|---|---|
| **Live connectors** | Direct connections to AlgoSec, Guardicore and Wiz, in both directions, so the system runs continuously on live policy and can apply approved changes. |
| **Real customer data at scale** | Handling the untidiness of real exports: unusual field shapes, rules the system cannot read, address objects resolved to their actual ranges rather than kept as labels, and the performance work to keep an environment with thousands of rules analysing within a predictable time. |
| **Deeper policy semantics** | Extending the map to subtract explicit deny rules from what is otherwise permitted, and following routes through address ranges. Both currently make the system conservative, reporting fewer routes than may exist rather than more. |
| **Operational hardening** | The work of running it for someone else: usage and spending limits, longer analyses running in the background, and full test coverage across every path. |

### Boundaries worth knowing now

Stated plainly, because you would find them eventually and they are better heard from us.

- **Effective policy is currently the sum of what is allowed.** An explicit deny that would cancel out an allow is not yet subtracted from the map, although the system does detect and report denies that have been rendered ineffective by rule ordering. In practice this makes it conservative in the direction that matters: it will not tell you something is blocked when it is not.
- **Address ranges are destinations, not stepping stones.** Described in Section 6. Again conservative: fewer routes reported, never more.
- **Route enumeration is bounded.** Long chains and very large candidate sets are cut off deliberately so analysis finishes in predictable time.
- **The connector author is a design-time assistant.** It proposes and validates a reader for a new source. Registering that reader and ingesting through it in production is part of the live-connector work.

None of these affect what the system does with the data it has. They are the difference between a system proven on a known dataset and one proven on yours, and they are the substance of the next stage.

---

## 16. Common questions

**Does the AI decide whether my network is safe?**
No. It explains, ranks, drafts and recommends. Whether something is reachable, whether a finding exists, what it scores and whether a change is clean are all computed by ordinary software. The model can recommend escalating a change. It cannot approve one that the calculation says is not clean.

**Does our network topology leave our building?**
Only if you choose a hosted AI service. Running with a local model means nothing leaves the machine. The system displays which mode is active. Either way, the calculation engine, which is where all the facts are, never contacts anything external.

**What happens if the AI is wrong?**
It depends where. A wrong explanation is wrong wording next to a correct finding. A wrong fix is caught by the engine's re-simulation and rejected before you see it. A wrong ranking changes the order of a list whose contents are still correct. A wrong approval on a change is prevented by the two layers that are ordinary code and can only make the decision stricter. The system is built so that a model error costs you quality, not safety.

**What if the AI is unavailable entirely?**
Every capability has a fallback that needs no model. You lose the plain-language layer and the drafting. Every fact, finding, score and gate decision still works.

**Is this connected to our live AlgoSec, Guardicore and Wiz today?**
Not yet. It reads representative exports of the kind those products already produce. Everything downstream is real and already runs on a common format, so connecting the live products is a change at the very edge of the system. It is the immediate next step.

**Does it replace our existing tools?**
No, and it does not want to. It reads them. They keep enforcing policy; this sits above them and shows you the combined picture none of them can, then routes changes back to whichever tool owns the rule.

**Why can it see things our tools cannot?**
Because the exposure is in the combination. Each tool is correct about its own territory. A route from the internet to your database that passes through three tools is invisible to each of them individually and obvious once you put them together. Putting them together requires recognising that the same machine appears under different names in different tools, which is the piece of work described in Section 5.

**Can someone get a change approved by wording the request cleverly?**
No. The justification is treated as untrusted context. The decision is made on the computed effect of the change, and the two layers that can force escalation are ordinary code that never reads the request text at all.

**How many findings will we get?**
Fewer than you expect, and that is the point. Findings are grouped by underlying cause into a short worst-first list of actions, so one root cause presents as one item rather than fifteen. Hygiene findings such as overlapping rules are scored to stay low and never crowd out something urgent.

**Can we tune the scoring to our own risk appetite?**
Yes. Every rating and threshold is configuration in one place. Change a value and the results stay repeatable.

**Can we add a source you do not support?**
Yes. Paste a sample of its export and the system proposes a reader for it, tests that reader on your sample, and shows you what it could and could not map. You approve short, readable configuration rather than code. At runtime no AI is involved in reading that source.

**What does it cost to run the AI?**
Nothing per request if you run a local model. If you use a hosted service, every call is metered with consumption, duration and estimated cost, broken down by capability, on the Metrics and Cost screen. You can see what you are spending and on what.

**Can we prove what it told us, after the fact?**
Yes. Findings and analysis runs are identified by values derived from their own content, so the same data always produces the same identifiers and any two runs are directly comparable. Every change and decision is written to an audit log. Every agent shows its working on screen.

**How long does an analysis take?**
On a dataset of the size the system runs on today, it is fast enough to be interactive. Keeping that true on environments with thousands of rules is explicit, planned work, listed in Section 15.

**Who can use it, and can we restrict features?**
The application has sign-in including single sign-on, and different roles for different kinds of user. Individual capabilities can be switched on or off per role from the administration screens.

**What would a pilot look like?**
The natural first step is a live connection to one of the three products, run against a real policy set, so you can compare what the system finds against what your team already knows. That is the point at which the cross-tool route stops being a demonstration and starts being your environment.
