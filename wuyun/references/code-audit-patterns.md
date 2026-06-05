# Wuyun Code Audit Patterns

Use this reference during local code review.

## Source → Boundary → Sink Trace

For every lead, trace:

```text
attacker-controlled source → parser/normalizer → authn/authz boundary → business rule → sink/state change/output
```

A finding is weak until the source is reachable and the boundary/sink is decisive.

## High-Value Patterns

| Pattern | Source | Boundary | Sink / impact | Fast reducer |
|---|---|---|---|---|
| IDOR / broken object authorization | path ID, JSON ID | owner/tenant check | read/update/delete another object | find server-side ownership check after fetch and before response/mutation |
| Mass assignment | JSON body | DTO/model binding | role, price, status, owner mutation | allowlist fields or serializer config |
| SQL/NoSQL injection | params, filters, sort | query builder | raw query execution | parameter binding and allowlisted operators |
| SSRF | URL, webhook, import | URL validation | server-side fetch | deny private ranges, redirect handling, scheme allowlist |
| Path traversal | filename, archive entry | canonicalization | file read/write/extract | `resolve()` under base path check after decoding |
| Unsafe deserialization | cookie, queue, upload | type allowlist | object creation/RCE | safe format, type restrictions, no polymorphic untrusted types |
| SSTI/XSS | template/HTML/markdown input | escaping/sanitizer | server/client code execution | context-aware escaping after transforms |
| Command injection | CLI arg, filename, URL | shell boundary | `exec`/`spawn` | array argv, no shell, allowlist |
| Auth bypass | headers, cookies, JWT claims | auth middleware | privileged route/action | server-side session/claims validation |
| Race/business logic | retries, concurrent requests | state transition | double spend, duplicate claim | transaction/idempotency lock |
| Cache confusion | request headers, user/tenant/role | cache key | cross-user or stale protected data | cache key includes auth state and tenant |

## Audit Moves That Reduce False Positives

- Identify the deployed entry point and route registration before tracing a sink.
- Confirm the attacker role can control the source value.
- Follow middleware order, guards, decorators, interceptors, and feature flags.
- Check whether suspicious code is test-only, docs-only, generated, dead, or unreachable.
- Look for neutralizing controls after the suspicious line: sanitizer, parameter binding, canonicalization, database constraint, policy check.
- Compare impact to existing privileges; do not report admin-only behavior as privilege escalation unless it crosses an intended boundary.
- Prefer a minimal local test or framework behavior proof when runtime is unavailable.

## Report Pattern

```markdown
### Finding: <title>
- Source: `<file:function>` / `<route>`
- Boundary: `<authz/parser/normalizer>`
- Sink: `<query/file/template/command/state change>`
- Control missing or flawed: <one sentence>
- Evidence: <decisive line/request/result>
- Confidence: high | medium | low
```
