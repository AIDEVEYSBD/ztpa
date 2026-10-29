# Test backlog

Everything that is built but not yet tested the way it ultimately has to be. Each line says
what is untested, why it matters, and what unblocks it. Updated as work lands; when an item
is tested, move it to **Done** with the date and the evidence.

Feature status lives in [TRACKER.md](TRACKER.md); this file is only about verification.

## Needs a person (UI and review quality)

| # | What | Why it matters | Unblocked by |
|---|---|---|---|
| T1 | Every FRR screen in a real browser: Exports, Context data, Rule review, Change package, Approvers, Knowledge | All UI checks so far are type check, lint, build and HTTP calls through the frontend; nobody has looked at it | Anyone with the staging proxy (`gcloud run services proxy frr-staging-web …`) and the break-glass login |
| T2 | Narrow-screen / small-laptop layout of the register and package screens | Wide tables with expandable rows are where layouts break | T1 |
| T3 | The two-stage approval with two different people end to end in the UI | Staging proved owner validation and the four-eyes refusal via the API, not a second person approving | Two testers, each granted a duty |
| T4 | Narrative quality judged by network owners on real rules | Model output was checked for schema and citations, not for usefulness to an owner | Real export + client standards loaded |
| T21 | NAT semantics confirmed with a Check Point engineer: whether access rules match pre- or post-NAT on the client's gateways, and whether NAT-rule shadowing matches Check Point's own NAT order (manual vs automatic sections) | The review deliberately does not rewrite grants through NAT; if the gateways match post-NAT, internet exposure via NAT could be under-reported | A Check Point engineer + one real NAT rulebase |
| T5 | `mgmt_cli` commands and rollbacks executed on a lab Check Point management server | The commands follow the documented syntax but have never been run; a wrong rollback is worse than none | A Check Point lab / test management server and an engineer |

## Needs real client data

| # | What | Why it matters | Unblocked by |
|---|---|---|---|
| T6 | Check Point parser on a real, sanitised export (with hit counts, NAT, sections, inline layers) | Only synthetic exports have been parsed | Sanitised export from the client |
| T7 | Stealthwatch flow export and CMDB/IPAM extract in their real column layouts | Column aliases are guesses from typical exports | Sample files |
| T8 | Skybox export | Parser not built: format unknown | A sample export (01.1b) |
| T9 | Evaluation on the reviewers' labelled rulebase; decide the severity-tuning signal (broad internal admin, internet-exposed DB ports) | Current eval set is labelled by construction | Labelled rulebase (FRR-01.5) |
| T22 | Narrative eval on the client's own rules and documents | Live runs so far (Vertex gemini-2.5-pro, Azure gpt-4.1-mini, both clean) used the synthetic rulebase and two sample excerpts | T6, T10 |
| T10 | Knowledge base with the client's standards, exceptions and runbooks; check retrieval picks the right passages | Retrieval tested on a two-section sample | Client documents |

## Needs a deployment or environment

| # | What | Why it matters | Unblocked by |
|---|---|---|---|
| T11 | SSO with the client's identity provider: login, role map, logout | Staging uses break-glass | IdP app registration (docs/SSO.md) |
| T12 | Azure: KEDA queue-depth scale-out under load, and Front Door + edge lock (needs a domain) | Staging is deployed and exercised, but worker scaling stayed at 1 replica and Front Door was not enabled | A burst of jobs in staging; a domain |
| T13 | GCP edge: HTTPS load balancer + managed certificate + Cloud Armor + IAP | Staging uses the run.app URL through the IAM proxy | A domain for staging |
| T14 | GitHub Actions: CI (`ci.yml`) and both deploy workflows on GitHub | Linted with actionlint, never run | Push the branch; configure environments |
| T15 | Autoscaling under load: API instances scaling out, worker scaling, Cloud SQL connection budget at max instances | Staging load test stayed within a couple of instances | A load test from inside the VPC at production size |
| T23 | Streaming parse for exports above 300 MB | One-pass JSON parse is refused above `NPR_MAX_PARSE_BYTES`; very large estates must upload per layer | Build an incremental parser (ijson) if real exports exceed it |
| T17 | Alerts reach a real channel (5xx, worker down, DB CPU) | Policies exist, no channel attached | A notification channel |
| T18 | Point-in-time restore rehearsal and secret rotation (runbook steps) | Documented, never performed | A staging window |
| T19 | Model provider failure in the cloud (quota / 429 / outage) degrades to labelled engine text | Fallback tested offline with stubs | Temporarily point staging at an invalid model |
| T20 | Rate limit holds across replicas in the cloud | Tested on one database locally | T15 |

## Done

| # | What | When | Evidence |
|---|---|---|---|
| T16 | Large upload in the cloud: 36.1 MiB / 70,000-rule export through the staging frontend | 2026-10-29 | Single request refused 413 by Cloud Run (cap confirmed); multipart 5 parts in 20 s, finalized in 24.5 s, accepted and reviewed 88 s after start. Found: register pages 1.5–2.5 s on large reviews (whole-document load per process) → moved to indexed rows |
| T16b | Register pages at 70,000 rules in staging, after moving to rows + summarised effective policy + gzip | 2026-10-29 | Server-side p50 178 ms (was ~2 s); end-user 470–650 ms over a ~365 ms network floor (was 1.3–2.5 s) |
| T12a | Azure staging end to end: Terraform apply (55 resources), migrations on Flexible Server, in-VNet smoke test, break-glass through the public frontend, FRR flow, AI Foundry narratives via managed identity, Key Vault references, Application Insights | 2026-10-29 | Export accepted 5.5 s; agent run 12 s, 7/7 narrated on gpt-4.1-mini; 40k-rule export reviewed 32 s, register page 290 ms. Found: `az containerapp job start --args` mangles command lines → `scripts/azure/start-job.sh` |
| T24 | Multipart on Azure Blob staged blocks (and GCS compose, T16) against the real services | 2026-10-29 | 20.5 MiB in 3 parts committed as blocks, finalized and reviewed |
| T22a | Narrative eval on Azure gpt-4.1-mini | 2026-10-29 | 20 items: fallback 0, ungrounded 0, contradictions 0, citation 1.0 |
| — | GCP staging deploy, migrations, smoke test, end-to-end FRR flow, Vertex narratives, tracing, staging load test | 2026-10-29 | [TRACKER.md](TRACKER.md) changelog; REMEDIATION-LOG "First real deployment" |
