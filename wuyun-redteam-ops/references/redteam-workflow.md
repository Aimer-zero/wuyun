# Wuyun Red Team Workflow

Use this reference when a request asks for red-team, purple-team, adversary-emulation, attack-path, or operation planning.

## Required framing

Record these before active work:

| Field | Notes |
|---|---|
| Objective | What business/security question the exercise answers |
| Scope | Assets, accounts, environments, networks, APIs, repositories |
| Rules of engagement | Allowed techniques, windows, rate limits, contacts, stop conditions |
| Assumptions | Credentials provided, test data, owner instrumentation, known constraints |
| Success criteria | Evidence that validates or falsifies each path |
| Safety exclusions | Destructive actions, persistence, malware, unrelated data, credential theft |

If the target is production-like and scope/authorization is unclear, ask one short clarification before impactful traffic.

## Phase gates

1. **Scope and ROE gate**: no active testing until scope and stop conditions are clear.
2. **Passive map gate**: build an asset and trust-boundary map from local artifacts, docs, HAR, source, or low-impact discovery.
3. **Hypothesis gate**: define at least three distinct paths when the engagement is broad.
4. **Validation gate**: choose the smallest safe proof for each path; use canaries, synthetic data, or owner-assisted logs.
5. **Impact gate**: separate confirmed impact from plausible impact; do not access unrelated data to prove severity.
6. **Remediation gate**: map each issue to owner, control, test, and detection opportunity.
7. **Learning gate**: capture reusable patterns after redaction.

## Evidence ledger template

```text
- Path ID:
- Objective:
- In-scope asset:
- Source artifact / request / file:
- Trust boundary:
- Hypothesis:
- Safe validation performed:
- Result: confirmed | likely | speculative | ruled-out | deferred
- Sensitive data handling:
- Detection opportunity:
- Remediation owner:
- Follow-up skill:
```

## Safe validation ladder

Prefer the first rung that proves or falsifies the claim:

1. Static/source/config evidence.
2. Local reproduction or offline parser/signature proof.
3. Dry-run generated request or replay plan.
4. Metadata-only online check.
5. Controlled canary marker with owner monitoring.
6. Owned test account or synthetic record.
7. Owner-assisted log/database confirmation.

Stop before rungs that require destructive effects, persistence, credential theft, or unrelated data exposure.
