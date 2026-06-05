# Wuyun Web Vulnerability Patterns

Use this reference for web/API hypotheses and safe validation planning.

## Access Control

Hypotheses:

- User can access another user's object by changing `id`, `uuid`, `slug`, tenant, or account parameter.
- Role enforcement exists only in the UI and not in the API.
- Workflow state can be skipped by calling later endpoints directly.

Safe validation:

- Use two owned test accounts or synthetic fixtures.
- Compare status codes and response shapes without reading private content.
- Confirm the server-side ownership/tenant check in code when possible.

## Injection

Hypotheses:

- Sort/filter/search fields reach SQL/NoSQL/LDAP/template/command sinks.
- Content-type changes, duplicate parameters, arrays, nulls, or encoding alter validation.

Safe validation:

- Prefer code-level sink tracing.
- Use harmless syntax errors, boolean differences, or timing markers in lab or scoped validation contexts.
- Never dump data to prove injection.

## SSRF and URL Fetchers

Hypotheses:

- Preview/import/webhook features fetch attacker-supplied URLs.
- Redirects, DNS rebinding, IPv6, decimal/octal IPs, or userinfo bypass URL filters.

Safe validation:

- Use a controlled callback server or local mock in lab scope.
- Do not target cloud metadata endpoints in production.
- Prove egress path with request metadata only.

## File Handling

Hypotheses:

- Uploads trust extension or content type.
- Archive extraction permits zip slip.
- Download endpoints accept raw paths.

Safe validation:

- Use benign text files and synthetic filenames.
- Validate canonical path checks in code.
- Avoid uploading executable artifacts or webshells.

## XSS and Template Rendering

Hypotheses:

- Stored/reflected input reaches HTML, JS, URL, CSS, Markdown, or template contexts.
- Sanitization occurs before a later transform that reintroduces HTML/script.

Safe validation:

- Use inert markers first, then non-executing payloads if needed.
- Prefer local reproduction or screenshots with sensitive content redacted.
- Avoid payloads that exfiltrate cookies or data.

## API Logic

Hypotheses:

- Client-controlled price, quantity, role, status, discount, or owner is trusted.
- Idempotency keys, retries, and concurrent requests violate invariants.

Safe validation:

- Use test records only.
- Prefer invariant proof from code/transactions.
- For races, keep concurrency low and scoped to disposable lab state.
