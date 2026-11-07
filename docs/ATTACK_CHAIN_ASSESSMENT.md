# Evidence-Backed Vulnerability and Attack-Chain Workflow

## Goal

A request such as "perform a vulnerability assessment of this scoped application" should trigger a structured investigation, not a one-shot scanner run. Loki should enumerate the reachable attack surface, perform supported checks permitted by the engagement mode, validate leads, correlate evidence-backed findings, and attempt safe follow-up verification of plausible chains.

The workflow is autonomous only inside the operator-configured scope and policy. It does not ask for approval before every routine command, but it does stop at scope violations, hard policy blocks, missing capabilities, or separate elevated-approval gates.

## 1. Establish the engagement once

The authenticated operator configures:

- Assessment name and target domains/IPs/CIDRs.
- Explicit exclusions and any port restrictions.
- Allowed subdomain behavior and other scope settings.
- Execution mode (`SAFE`, `AUDIT`, or explicitly confirmed `NOMERCY`).
- Any special test constraints, time windows, and lab-only proof requirements.

After this setup, the scope and mode are the engagement-level authorization for ordinary supported actions. Every call still passes through the Execution Gateway. The model cannot authorize a new host, remove an exclusion, change mode, or override a block.

## 2. Investigate in phases

### Reconnaissance and attack-surface discovery

Use supported, scope-aware methods to identify DNS records, subdomains, resolved addresses, reachable services, HTTP endpoints, technologies, certificates, and security controls. Track the source and limits of every observation.

### Vulnerability discovery

Select checks based on the actual technologies and reachable attack surface. Prefer more than one independent evidence source for important claims. A scanner result is a lead; a banner or version number alone does not demonstrate a vulnerable code path.

Use the configured mode:
- `SAFE`: passive and low-impact checks.
- `AUDIT`: controlled active validation supported by Loki.
- `NOMERCY`: the broadest supported set after one explicit mode confirmation.

Do not treat a missing tool as evidence that a target is secure. Search the catalogue for alternatives, inspect the tool's actual availability, or report the capability gap.

### Validate individual findings

For each proposed finding:

1. Capture the exact tool output and its source.
2. Check whether the result is an application response, a WAF response, a generic error page, a soft 404, a redirect, or an infrastructure response.
3. Corroborate using a materially different supported method where practical.
4. Reproduce only with a scoped, low-impact check allowed by policy.
5. Record what the evidence proves and what it does not prove.

Do not equate scanner confidence with proof. A finding without a verified reproduction must remain potential or validating.

## 3. Automatic evidence capture

When an active assessment exists, successful tool results authorized by the Execution Gateway are stored as bounded, secret-redacted evidence. The tool result includes a stable marker:

`[LOKI_EVIDENCE_ID: <id>]`

The evidence record contains the tool name, assessment ID, task/call identifier, target metadata, execution timing, sanitized output, and output hash. Common authorization headers, cookies, bearer/basic credentials, JWTs, and credential-like query parameters are redacted before the evidence is stored and shown to the model.

When recording a vulnerability, Loki must provide:

- The active `session_id`.
- An `evidence_record_id` emitted by Loki for that assessment.
- An exact 15–2000 character excerpt from that stored output.
- An in-scope affected asset.
- A severity and CVSS estimate justified by the demonstrated technical impact.
- Supported capability labels only when the excerpt justifies them.

The recorder rejects missing or cross-assessment evidence IDs, unauthorized evidence records, hash mismatches, invented excerpts, invalid severity values, and unsupported capability labels.

## 4. Cross-finding correlation

After at least two findings have been recorded, Loki automatically runs cross-finding correlation. It can also be called directly:

```text
analyze_attack_chains(session_id)
```

The correlator checks the indexed evidence records and builds candidate links using a small, explicit vocabulary:

| Capability | Meaning |
| --- | --- |
| `unauthenticated_access` | A verified action was accessible without authentication |
| `authenticated_low_privilege` | A verified action was available to a low-privilege test principal |
| `sensitive_read` | Evidence demonstrates access to a designated test/sensitive object |
| `sensitive_write` | Evidence demonstrates a controlled write to a designated test object |
| `internal_service_access` | A permitted in-scope test demonstrated access to an internal service |
| `ssrf` | A controlled test demonstrated server-side request behavior |
| `file_read` | A controlled test demonstrated reading an approved fixture file |
| `code_execution` | A controlled test demonstrated execution of a harmless marker |
| `privilege_escalation` | A test principal demonstrably gained a higher privilege |
| `session_takeover` | A controlled test demonstrated another test session could be assumed |
| `account_takeover` | A controlled test demonstrated control of a test account |
| `security_control_bypass` | A specific control was demonstrably bypassed |
| `admin_function_access` | A test principal demonstrably invoked a restricted admin function |
| `tenant_boundary_crossing` | A tenant-isolation test demonstrated crossing between designated test tenants |

A finding's `enables` list describes a capability its evidence demonstrates. A finding's `requires` list describes a precondition that must be satisfied. A link is emitted only when one finding's enabled capability matches another finding's prerequisite.

### What a candidate means

A candidate is a hypothesis that the findings may compose. It does not establish exploitability, sequence feasibility, causality, or impact. The chain output includes the finding sequence, matched capability, affected assets, and evidence record IDs. Loki should identify missing preconditions and run supported, low-impact follow-up checks within the active scope.

Loki must not:
- Add individual CVSS scores or severities.
- Promote a candidate to confirmed based on graph adjacency.
- Assume credentials, roles, object IDs, network paths, or preconditions that were not observed.
- Report critical impact without direct evidence of the combined impact.

## 5. Safely validate a plausible chain

For each candidate, Loki should:

1. Check that every involved asset remains in the current scope and not excluded.
2. Write down the exact prerequisite at each transition.
3. Identify the evidence that supports each prerequisite and the evidence still missing.
4. Prefer read-only or low-impact checks using disposable test principals and fixtures.
5. Run only supported checks that pass the mode and gateway policy.
6. Capture an end-to-end reproduction record showing the starting condition, exact test action, observed result, and cleanup state.
7. Mark the chain verified only when direct evidence demonstrates the combined impact.

For sensitive data-access claims, use seeded canaries in a disposable lab. A canary must be absent from the control response and present in the controlled test response before the payload is credited with the access. Never extract real user records to prove impact.

If a safe reproduction is not possible, keep the chain as potential and state exactly which precondition or link remains unverified.

## 6. Evidence quality and confidence

| Status | Meaning |
| --- | --- |
| Potential | A hypothesis or alert without sufficient direct validation |
| Validating | Some relevant evidence exists, but a key claim or false-positive concern remains |
| Confirmed finding | A successful reproduction record demonstrates the claimed behavior |
| False positive | Evidence indicates a scanner, WAF, generic error, or other artifact was misinterpreted |
| Blocked / not tested | Scope, mode, isolation, missing tool, or approval policy prevented the check |

A finding may be technically serious yet still unconfirmed. Report technical severity separately from confidence and lifecycle status.

## 7. Final report structure

For each finding, report:

- ID and title.
- Status and confidence.
- Severity/CVSS with a short impact rationale.
- Affected asset and endpoint.
- Evidence record ID(s) and exact sanitized observation.
- Verification methods and reproduction details.
- False-positive analysis and remaining uncertainty.
- Remediation.

For each attack-chain candidate, report:

- Candidate ID and ordered finding IDs.
- Explicit prerequisite/capability transition.
- Evidence IDs supporting each transition.
- Which steps were tested and the observed results.
- Combined impact only when directly reproduced.
- Missing links and remediation priorities.

End with test coverage, methods not run, policy blocks, tool limitations, and a clear statement of what remains unknown.

## 8. Execution contract

Loki performs every supported, non-destructive command that is in scope and permitted by the selected mode without asking the operator to reconfirm each command. It must stop on scope violations, hard policy blocks, unavailable capabilities, or separate elevated-approval requirements. It must never weaken isolation, evade a control, widen scope, or make an unsupported claim to complete a chain.
