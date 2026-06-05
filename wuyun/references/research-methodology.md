# Wuyun Research Methodology

## Table of Contents

1. Developer mental model
2. Stage checklists
3. Vulnerability hypothesis prompts
4. Validation patterns
5. False-positive reducers
6. Report template
7. Knowledge extraction template

## 1. Developer Mental Model

Before attacking, infer how the system is likely designed:

- Which component owns the sensitive state or secret?
- Which layer enforces authentication and authorization?
- Which client-visible data is authoritative, and which is only display state?
- What data should never be present in the frontend, logs, caches, or client-side storage?
- What invariants does the server assume about role, ownership, tenant, workflow state, price, quantity, signature, nonce, or timestamp?
- Which operations are asynchronous, retried, cached, or eventually consistent?
- What would a careful developer validate, and where might they forget to validate it?

Use this model to prioritize attack surfaces that can actually affect the protected asset.

## 2. Stage Checklists

### Stage 1 — Understand

Collect:

- Architecture and component boundaries
- Dependency list and versions
- Route/API map
- Authn/authz model and role matrix
- Data stores, schemas, object ownership fields, tenant fields
- Background jobs, queues, webhooks, schedulers
- File handling, parsers, template engines, serializers
- Crypto/signature/key management paths
- Logging, monitoring, cache, and backup behavior

Deliverable: architecture summary plus trust-boundary map.

### Stage 2 — Attack Surface Discovery

Map every controllable input:

- HTTP method, path, params, JSON fields, multipart fields
- Headers, cookies, tokens, JWT claims, session IDs
- File uploads, archive extraction, image/document parsers
- WebSocket messages and event names
- CLI flags, environment variables, config files
- Template expressions, markdown/HTML renderers, rich text
- Database filters, sort keys, aggregation parameters
- Webhooks and third-party callbacks
- Admin-only functions and internal endpoints

Deliverable: attack surface table with status `untested`, `interesting`, `ruled-out`, `confirmed`.

### Stage 3 — Hypothesis Generation

For each surface, generate multiple hypotheses:

- Access control: missing object ownership, tenant isolation, role checks, workflow-state checks
- Auth: weak session invalidation, token confusion, JWT algorithm/key misuse, password reset flaws
- Injection: SQL/NoSQL/LDAP/XPath/template/command/header/log injection
- SSRF: URL fetchers, webhooks, importers, previewers, metadata endpoints
- File handling: traversal, zip slip, content-type confusion, unsafe extraction, unrestricted upload
- Deserialization: unsafe object creation, gadget chains, polymorphic parsers
- XSS: reflected/stored/DOM sinks, sanitizer bypass, markdown/rich text transforms
- Crypto: static keys, predictable nonces, missing authentication, confused signing/encryption
- Race/logic: double spend, replay, idempotency gaps, concurrent state transitions
- Data exposure: verbose errors, debug endpoints, logs, backups, cache poisoning

Deliverable: hypothesis table with evidence to seek and validation method.

### Stage 4 — Deep Analysis

For each hypothesis:

- Trace input source to security sink or decision branch.
- Identify exact validation and authorization checks.
- Look for bypasses through alternate routes, encodings, aliases, case differences, arrays vs scalars, duplicate keys, content-type changes, and parser differentials.
- Identify environmental preconditions and privileges required.
- Record contradictions and why they do or do not eliminate the hypothesis.

Deliverable: one narrow, evidence-backed path per promising hypothesis.

### Stage 5 — Validation

Validation should be safe, scoped, and reproducible:

- Use the smallest payload or request that proves the behavior.
- Change one variable at a time.
- Prefer local reproduction when source or a dev environment exists.
- Capture exact command/request/response, status code, side effect, and cleanup steps.
- Confirm impact with in-scope data only.
- Re-run from a clean baseline when possible.

Deliverable: confirmed/likely/speculative classification with reproduction evidence.

### Stage 6 — Knowledge Extraction

After the investigation, extract:

- Root cause pattern
- Framework or language behavior that mattered
- Signals that increased confidence
- Signals that reduced confidence or prevented false positives
- Tools, queries, payloads, or traces that were most useful
- What to try earlier next time

Deliverable: concise lessons learned.

## 3. Vulnerability Hypothesis Prompts

Ask these questions repeatedly:

- Can I act on an object I do not own by changing an ID, slug, path, tenant, or account field?
- Can I skip a required workflow state or repeat a one-time action?
- Can two parsers disagree about the same input?
- Can encoding, normalization, duplicate parameters, arrays, nulls, or type confusion bypass a check?
- Does the server trust client-supplied role, price, balance, status, callback URL, redirect URL, or file metadata?
- Does a background job process data with higher privilege than the request that created it?
- Can cached data cross users, tenants, roles, locales, or content types?
- Are secrets exposed in source maps, build artifacts, logs, environment dumps, configs, or error pages?

## 4. Validation Patterns

- **Authorization**: compare same request as owner vs non-owner vs unauthenticated; preserve all fields except identity/object reference.
- **Injection**: prove parser influence first, then safely demonstrate data extraction or control effect within scope.
- **XSS**: identify source, sanitizer, sink, and execution context; validate with benign proof payload.
- **SSRF**: confirm outbound fetch behavior with controlled in-scope listener or sandbox endpoint; test scheme, redirect, DNS, and IP filtering assumptions.
- **File handling**: test filename normalization, archive paths, magic bytes vs content type, storage path, execution path, and retrieval authorization.
- **Race**: script concurrent requests, record success counts, repeat against clean state, and verify final invariant violation.
- **Crypto**: prove key/nonce/signature misuse with minimal forge/decrypt/replay example; avoid relying only on weak-code smell.

## 5. False-Positive Reducers

Before reporting, check:

- Is the vulnerable branch reachable in the deployed/runtime configuration?
- Is the input truly user-controlled by the attacker role?
- Does a later middleware, database constraint, sanitizer, or authorization check neutralize the issue?
- Is the observed behavior intended business logic or documented admin capability?
- Does exploitation require privileges already equivalent to the impact?
- Is sensitive data actually exposed, modified, or reachable, not merely present in unreachable code?
- Can the result be reproduced after clearing cache/session/state?

## 6. Report Template

```markdown
## Summary
<One-paragraph impact and affected component.>

## Technical Analysis
<End-to-end flow from input to vulnerable decision/sink.>

## Supporting Evidence
- File/route/request: <path or endpoint>
- Relevant condition: <branch/check/sink>
- Reproduction: <compact commands or steps>
- Observed result: <decisive output>

## Root Cause
<Failed assumption and missing/incorrect control.>

## Confidence Level
High | Medium | Low — <why>

## Validation Suggestions
<How to reproduce further or close remaining uncertainty.>

## Remediation Guidance
<Specific code/design fixes and tests to add.>

## Lessons Learned
<Reusable pattern, false-positive signal, or future heuristic.>
```

## 7. Knowledge Extraction Template

```markdown
### Pattern
<Name the recurring vulnerability pattern.>

### Context
<Framework, component type, trust boundary, data flow.>

### Signals
- Positive indicators:
- Contradictory indicators:
- Fast validation method:

### Root Cause
<Which assumption failed.>

### Prevention
<Design rule, code pattern, test, or monitoring.>

### Reuse
<When to look for this pattern in future investigations.>
```
