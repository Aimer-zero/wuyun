---
name: wuyun-web-api-audit
description: Web and API vulnerability research companion for Wuyun. Use for online URL/domain/IP/API audits, source-code or black-box Web/API audits, OWASP API Top 10 triage, BOLA/IDOR, BFLA/authz bypass, SSRF, SQL/NoSQL injection, XSS/SSTI, file upload/path traversal, business logic, OpenAPI analysis, request diffing, and remediation-focused reporting.
---

# Wuyun Web/API Audit

Use this companion with `$wuyun` for Web/API vulnerability research. It supports online targets such as URLs, domains, IPs, API base paths, Swagger/OpenAPI endpoints, and login/API flows, as well as source-assisted audits, bug-bounty triage, and CTF/lab web challenges.

## Safety Boundary

- Work from the task target and mode: `online-web-api`, `code-audit`, `production-safe-review`, `bug-bounty`, or `ctf-lab`.
- For online targets, start with low-impact fingerprinting, crawling, endpoint discovery, headers/cookies review, robots/sitemap/OpenAPI checks, and request/response mapping. Use source/config/OpenAPI review when available.
- If Cloudflare/CDN/WAF/Bot Management changes results, preserve Ray IDs and classify CDN/WAF/challenge/origin behavior before attempting more tests.
- Avoid credential brute force, unrelated tenant enumeration, data dumping, webshell uploads, CAPTCHA/Turnstile automation, proxy rotation, generic WAF-evasion payload packs, and high-volume scanning in production-like contexts.
- Active validation requires explicit scope and authorization. Use `scripts/active_http_validator.py` only for a single in-scope endpoint, low request counts, one-variable-at-a-time probes, and inert/synthetic values unless the user provides a reviewed authorized payload set. Use `scripts/idor_case_generator.py` to turn route inventories into reviewed BOLA/IDOR case plans before execution.
- Use synthetic IDs, owned accounts, inert markers, and complete in-scope request/response evidence for authorized private reports.
- CTF/lab mode may exploit the intended challenge artifact, but keep replay steps minimal and scoped.
- The user is responsible for permission and acceptable use; Wuyun focuses on bounded research, evidence quality, and remediation. Do not automatically mask in-scope evidence needed for the report.

## Workflow

1. **Inventory**: online hosts, routes, OpenAPI/Swagger, auth middleware, roles, object IDs, tenants, file handlers, outbound fetchers, templates, DB queries, background jobs.
2. **Developer model**: identify which server layer owns identity, authorization, tenant isolation, workflow state, pricing, and resource ownership.
3. **Extract attack surface**:
   - Online: crawl reachable paths, inspect HTML/JS bundles, collect API calls, parse Swagger/OpenAPI, compare headers/cookies, and build a request inventory.
   - Source: `scripts/extract_routes.py <repo>` for route leads.
   - Spec: `scripts/analyze_openapi.py openapi.yaml` for auth and parameter leads.
4. **Generate hypotheses** across access control, authn/authz, injection, SSRF, file handling, XSS/SSTI, business logic, and Cloudflare/WAF interference when observed.
5. **Validate with minimal impact**: replay requests, compare roles/accounts with `scripts/request_diff.py --complete` outputs or captured HTTP messages, generate BOLA/IDOR case plans with `scripts/idor_case_generator.py`, change one variable at a time, keep fuzzing low-rate and targeted, and use `scripts/cloudflare_triage.py` for captured Cloudflare blocks/challenges.
   - For authorized active checks, run `scripts/active_http_validator.py` in dry-run first; execute only with `--authorize-active-testing` and matching `--scope-host`.
6. **Report**: separate confirmed/likely/speculative leads; include source → boundary → sink traces, complete in-scope evidence, confidence, remediation, and regression tests.

## References

Load only the relevant reference:

- `references/bola-idor.md`: object-level authorization and tenant isolation.
- `references/authz-bfla.md`: function-level authorization, role guards, and admin endpoint exposure.
- `references/injection.md`: SQL/NoSQL/LDAP/template/command injection triage.
- `references/ssrf.md`: URL fetchers and private-network validation.
- `references/file-upload-path.md`: uploads, path traversal, archive extraction, and content-type confusion.
- `references/xss-ssti.md`: reflected/stored/DOM XSS and server-side template injection.
- `references/business-logic.md`: workflow, race, replay, pricing, quota, and state-machine bugs.
- `references/openapi-review.md`: OpenAPI/Swagger review checklist.
- `references/cloudflare-waf.md`: Cloudflare CDN/WAF/Bot Management/Turnstile-aware validation workflow.
- `references/reporting.md`: compact Web/API finding template.

## Output Shape

```markdown
## Web/API Audit Outcome
- Status: confirmed | likely | speculative | ruled-out
- Mode: online-web-api | code-audit | production-safe-review | bug-bounty | ctf-lab
- Affected endpoint/component:
- Vulnerability class:

## Evidence
- Source/input:
- Boundary/control:
- Sink/decision/state change:
- Complete in-scope proof:

## Confidence
- Level:
- What would raise/lower confidence:

## Remediation
- Code/config fix:
- Regression test:
```
