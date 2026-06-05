# Wuyun Vulnerability Hypothesis Engine

Use this reference when generating, prioritizing, testing, and retiring vulnerability hypotheses. The engine is designed to avoid anchoring, improve coverage, and reduce false positives.

## Hypothesis Lifecycle

1. **Seed**: derive leads from architecture, attack surface, code patterns, runtime behavior, dependency versions, or memory entries.
2. **Frame**: express each hypothesis as a falsifiable statement.
3. **Score**: prioritize by impact, reachability, controllability, evidence strength, and validation cost.
4. **Test**: collect supporting and contradictory evidence with the smallest safe experiment.
5. **Decide**: mark as confirmed, likely, speculative, ruled-out, or deferred.
6. **Learn**: convert outcomes into memory entries when reusable.

## Falsifiable Hypothesis Format

```markdown
### H-<number>: <short title>

- Status: untested | testing | confirmed | likely | speculative | ruled-out | deferred
- Component:
- Asset at risk:
- Attacker capability:
- Trust boundary:
- Vulnerability class:
- Impact if true:
- Confidence:
- Priority:

#### Claim
If <attacker-controlled input/condition>, then <security control fails>, causing <impact>.

#### Why Plausible
- <evidence or design assumption>

#### Evidence Needed
- Supporting:
- Contradictory:

#### Validation Plan
1. <safe, minimal test>
2. <follow-up test if needed>

#### Result
<observations and decision>
```

## Seed Sources

### Architecture Seeds

- Client controls data that should be server-authoritative.
- Background job processes user-created objects with elevated privilege.
- Multiple services disagree on identity, tenant, role, or object ownership.
- Cache key omits user, tenant, locale, content type, or authorization state.
- Webhook/callback accepts externally supplied URL, status, signature, or event type.

### Code Pattern Seeds

- Authorization after object fetch but before tenant/owner check is unclear.
- Raw query/string concatenation reaches SQL/NoSQL/LDAP/template/command sinks.
- File path joins use user-controlled names without canonicalization.
- Deserialization or polymorphic parsing accepts untrusted types.
- Crypto uses static keys, predictable nonces, unauthenticated encryption, or homegrown signing.
- Sanitization occurs before a later transform that can reintroduce executable content.

### Runtime Behavior Seeds

- Different status codes, timings, errors, or response shapes leak control-flow decisions.
- Same request differs across roles only in client UI, not server response.
- Duplicate parameters, arrays, nulls, or content-type changes alter validation behavior.
- Retried or concurrent requests violate state invariants.

### Memory Seeds

- Known framework behavior from long-term memory applies to the current stack.
- Prior false-positive reducer warns that a suspicious pattern is neutralized by runtime behavior.
- Prior confirmed pattern appears with the same source → boundary → sink shape.

## Prioritization Score

Score each dimension 0–3, then prioritize high total with low validation cost.

| Dimension | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Impact | none | low | sensitive read/write | auth bypass/RCE/critical asset |
| Reachability | unreachable | privileged/admin | authenticated user | unauthenticated/low privilege |
| Controllability | none | indirect | partial | direct attacker control |
| Evidence | weak smell | one signal | multiple signals | traced path/runtime proof |
| Validation cost | destructive/blocked | high | moderate | simple safe test |

Recommended priority:

- **P1**: high impact, reachable, controllable, simple validation.
- **P2**: meaningful impact with partial evidence or moderate validation.
- **P3**: speculative, hard to reach, or low impact.
- **Defer**: requires missing environment/tooling or unclear task boundary.

## Decision Rules

- Confirm only when the path is reachable and impact is demonstrated or logically unavoidable from decisive evidence.
- Mark likely when code/runtime evidence is strong but one environmental condition remains unverified.
- Mark speculative when the idea is plausible but evidence is weak.
- Rule out when a specific control, configuration, or runtime behavior invalidates the exploit path.
- Defer when validation requires missing scope details, data, credentials, tooling, or destructive testing.

## Anti-Anchoring Rules

- Generate at least three distinct hypotheses before deep-diving one path on broad reviews.
- For every promising hypothesis, identify what evidence would disprove it.
- Re-evaluate from the developer perspective after 2–3 failed attempts.
- Do not retry an architecturally impossible path unless new evidence changes the model.
- Keep a tried/ruled-out list to avoid circular testing.

## Hypothesis Table Template

```markdown
| ID | Hypothesis | Surface | Impact | Evidence For | Evidence Against | Next Test | Status | Priority |
|---|---|---|---|---|---|---|---|---|
| H-1 |  |  |  |  |  |  | untested | P2 |
```
