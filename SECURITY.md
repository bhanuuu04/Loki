# Security Policy and Rules of Engagement

## Purpose

Loki is an agentic security-assessment framework. Its autonomy is designed for systems that the operator owns or is explicitly authorized to assess. A configured scope is an execution boundary, not a claim that every technique or action is permitted.

## Engagement-level authorization

Before testing, an authenticated operator must configure the assessment name, targets, exclusions, allowed ports and applicable constraints. The operator also selects the execution mode:

- **SAFE** — passive reconnaissance and low-impact checks.
- **AUDIT** — controlled active vulnerability checks that are supported by Loki and permitted by the configured policy.
- **NOMERCY** — the broadest supported assessment mode. Enabling it requires one explicit operator confirmation.

Once the scope and mode are configured, they act as the engagement-level authorization for ordinary supported checks. Loki should not ask the operator to approve every individual command again. It should autonomously select, sequence, and execute commands that target assets in the active scope and pass the Execution Gateway.

This does **not** grant blanket permission. The gateway must still validate every tool invocation. Exclusions, DNS-rebinding protections, target extraction, port restrictions, rate limits, isolation, tool metadata, and hard policy blocks continue to apply. A user request cannot override those controls. A blocked action is reported as blocked; Loki must not seek a bypass or silently widen scope.

## Actions that remain prohibited or separately gated

The autonomous assessment path must not perform:

- Denial-of-service, stress, flooding, or resource-exhaustion testing.
- Destructive changes to data, services, accounts, infrastructure, or files.
- Persistence, backdoors, reverse shells, or stealth mechanisms.
- Lateral movement or attempts to reach assets outside the approved scope.
- Unauthorized privilege escalation, credential theft, or extraction of real user data.
- Cloud metadata access or other internal-network access unless the relevant assets are explicitly and safely included in scope and the dedicated control permits it.
- Automatic installation of tools, privilege elevation, or weakening the shell/container isolation boundary.

Credential-audit tools remain subject to the configured mode, the existing NOMERCY confirmation, and explicit rules of engagement. Use test-only accounts and disposable environments; do not treat scope membership alone as permission to guess passwords against real users.

A separate human approval may still be required by tool metadata for elevated or administrative capabilities. The agent must stop when that approval is unavailable. It must not treat the engagement-level grant as authorization for destructive or otherwise prohibited operations.

## Evidence and finding integrity

1. Successful tool results are eligible for automatic evidence indexing only after the Execution Gateway marks the result authorized.
2. Stored evidence is bounded and common credential-bearing fields are redacted before it is shown to the model or persisted.
3. A finding must reference an evidence record from the active assessment and include an exact excerpt from that record.
4. The evidence record's SHA-256 digest is checked before a finding is accepted.
5. A model hypothesis, scanner alert, HTTP status, version banner, reflected string, error page, or exit code is not by itself proof of exploitability.
6. Findings without adequate evidence remain potential or validating. A finding can be marked confirmed only when the finding validator has a successful reproduction record.
7. Never invent evidence IDs, outputs, affected versions, endpoints, CVEs, reproduction outcomes, or impact.

If evidence capture fails, Loki must state that it could not persist or verify the evidence; it must not fabricate an evidence reference.

## Attack-chain analysis

Loki correlates findings only when each finding:

- Belongs to the active assessment and affects an in-scope asset.
- Has a gateway-authorized evidence record with a matching integrity hash.
- Has an evidence excerpt that matches the recorded tool output.
- Has sufficient confidence and is not marked as a likely false positive.
- Declares supported `requires` and/or `enables` capability labels grounded in that evidence.

A matching capability relationship produces a **potential chain candidate**, not a verified exploit path. Loki must identify the missing preconditions and use scoped, non-destructive follow-up checks where supported. It must not add together the severities of separate findings or label a chain critical solely because its individual findings look serious.

A chain may be described as verified only after a separately scoped, controlled end-to-end reproduction directly demonstrates the combined impact and that result is captured as evidence. Proof-of-access checks must use disposable labs and seeded canary records. No real customer or user data should be retrieved to prove impact.

## Reporting requirements

Every finding and chain must distinguish:

- **Observed** — directly present in a tool result or reproduction record.
- **Inferred** — a reasoned interpretation that is not directly demonstrated.
- **Potential** — a plausible issue or chain that needs further validation.
- **Confirmed** — a finding whose reproduction record demonstrates the behavior.
- **Blocked / not tested** — a check that could not run due to scope, policy, missing capability, or execution constraints.

Include the affected asset, evidence record IDs, verification method, confidence, actual impact demonstrated, remediation, and any missing chain links. Do not present guesses as results. If the evidence does not support a conclusion, say that it is unknown or unverified.

## Reporting a vulnerability in Loki

Please open a private security advisory or contact the repository owner with reproduction steps, affected commit/version, environment details, and evidence that does not contain real credentials or personal data. Avoid publishing an unpatched vulnerability before maintainers have had a reasonable opportunity to investigate.
