# Firewall Rule Review — UAT scenarios

Acceptance scenarios for the Firewall Rule Review release, run in the staging environment by
the people who will use it. Each scenario lists who runs it, the steps, and what must be true
for it to pass. Record the result, the tester and any defect id in the last column of the
results sheet at the end.

**Roles in these scenarios**

| Role | Who | Product access |
|---|---|---|
| Analyst | Runs reviews | Product role *analyst* |
| Network owner | Validates findings and availability impact | Duty `network_owner` for the layers under review |
| Security approver | Approves the change package | Duty `security_approver` |
| Administrator | Manages duties and the knowledge base | Product role *admin* |

Duties are granted under **Rule Review → Approvers**. The network owner and the security
approver must be different people.

**Test data**

- A current Check Point export of one access layer, exported with
  `show-access-rulebase … details-level full use-object-dictionary true show-hits true`
  (and `show-nat-rulebase` for NAT), taken within the last 30 days.
- The labelled test rulebase agreed under FRR-01.5: a copy of the export with the expected
  checks and band for each rule, in the labels format described in `backend/src/frr/evals.py`.
- Optional: a CMDB/IPAM CSV and a flow (Stealthwatch) CSV for the same estate.
- The network standards, exception register and change/rollback runbooks as text or Markdown.

---

## A. Intake

| # | Scenario | Steps | Pass when |
|---|---|---|---|
| A1 | Upload a current export | Analyst: Exports → choose file → Upload | Status goes *processing* → *accepted* within a minute; rule, grant and NAT counts match the console |
| A2 | Same file twice | Upload A1's file again | Reported as a duplicate of the first export; no second review |
| A3 | Stale export | Upload an export taken more than 30 days ago | *rejected*, reason states the export date and the 30-day limit |
| A4 | Incomplete export | Upload one page of a paginated export (`to` < `total`) | *rejected*, reason names the page range |
| A5 | Wrong file | Upload any non-rulebase JSON | *rejected*, reason says it is not a rulebase export; no empty register is shown |
| A6 | No export time | Upload an export with no `exported_at`, without declaring one | *rejected*, asks for the export time; re-upload with "exported at" set is accepted |
| A7 | Viewer cannot upload | A viewer opens Exports | Upload is refused with a permission message |

## B. Rule-risk register

| # | Scenario | Steps | Pass when |
|---|---|---|---|
| B1 | Register matches the labelled set | Open Rule review for the labelled export; compare with the labels | Every labelled check is present on the right rule; no unlabelled check appears, or each difference is logged as feedback (B6) |
| B2 | Evidence | Expand three flagged rules of different checks | Each check shows its evidence (resolved addresses, ports, covering rule, hits, expiry) |
| B3 | Hits unknown vs zero | Review an export without `show-hits` | Hits show *unknown*; no rule is flagged *unused*; the limitations box says hit counts were absent |
| B4 | Shadowing respects gateways | Pick a rule covered on one gateway but installed on two | Not reported as shadowed; its limitations say where it is still effective; Effective policy shows it as shadowed on one gateway only |
| B5 | Limitations visible | Review an export with negated cells or application rules | The limitations box lists each approximation; affected rules carry their own limitation |
| B6 | Reviewer feedback | On three rules: agree with a check, disagree with a check (with reason and band), report a missed finding | Each verdict is saved and shown; Administrator's labels export reflects them |

## C. Change package and agents

| # | Scenario | Steps | Pass when |
|---|---|---|---|
| C1 | Agent run | Exports → Run agents | The five agents complete in order; the package shows an AI summary (or "Engine summary" if the model is unavailable) |
| C2 | Grounded narratives | Load the standards and runbooks (Knowledge); re-run on a new export | Item narratives cite only loaded documents; each cited excerpt supports the sentence that cites it |
| C3 | Safe proposals | Inspect items for: an unused any-any, a shadowed rule under a rule being narrowed, the cleanup rule | Unused any-any → disable then remove; shadowed-under-narrowed → revisit after, no commands; cleanup rule → never moved |
| C4 | Rollback present | Inspect five items with commands | Every item has rollback commands that restore the rule as exported |
| C5 | Flow-based narrowing | With flows loaded, open a narrowing item | Observed sources are listed with counts and prefilled in the owner form; sources older than 90 days are absent |
| C6 | Destination owners | With CMDB loaded, open any item | The destination's owner and application are shown |

## D. Human review (two stages)

| # | Scenario | Steps | Pass when |
|---|---|---|---|
| D1 | Owner decides | Network owner: accept, reject (with a note) and modify (with sources/services) one item each | Saved; accepting a narrowing item without sources, services and justification is refused with a message |
| D2 | No duty, no decision | A user without `network_owner` tries to decide an item | Refused, naming the missing duty |
| D3 | Validate | Owner decides every item, then Validate | Package becomes *owner validated* with name and time |
| D4 | Four eyes | The owner (also holding `security_approver`) tries to approve | Refused: the validator cannot approve |
| D5 | Approve | Security approver approves with a note | Package *approved*; runbook downloads; it lists only accepted/modified items, each with rollback, under the approval record |
| D6 | Reject | On a second package, the approver rejects without a note, then with one | First refused, second recorded; a redraft supersedes the rejected package |
| D7 | Re-run protection | Start a new agent run while an owner has decided items | The run refuses to replace the package under review |
| D8 | Audit | Administrator opens the audit trail | Draft, each decision, validation and approval are present with actor and time |

## E. Controls

| # | Scenario | Steps | Pass when |
|---|---|---|---|
| E1 | No device write | Search the product for any push/apply action on an FRR package | None exists; the older change gate's push is refused with "FRR mode" |
| E2 | Rate limit | Trigger more than 30 model-backed actions in a minute as one user | Further actions answer *429* with a retry time |
| E3 | Evaluation gate | Administrator runs `python -m src.frr.evals --export <labelled export> --labels <labels> --gate` | Precision and recall meet the agreed thresholds (default 0.98); band agreement is reported |

---

## Acceptance

The release is accepted when every scenario passes, or each failure has an agreed defect
with a fix date, and E3 meets the thresholds agreed under FRR-01.5 on the labelled rulebase.

| # | Result (pass / fail) | Tester | Date | Defect |
|---|---|---|---|---|
| A1 | | | | |
| … | | | | |
