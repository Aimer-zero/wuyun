# Cloud SSRF Workflow

Use for cloud SSRF research where a server-side fetcher may reach internal metadata services or private cloud endpoints.

## Developer Model

Cloud SSRF usually appears when a backend accepts a user-controlled URL and fetches it from a privileged network position. High-value fetchers include:

- URL preview, screenshot, link unfurl, webhook delivery, callback registration.
- Image/PDF/document import, avatar upload by URL, RSS/Atom import, XML external references.
- Admin diagnostics, proxy endpoints, CI/CD integrations, artifact scanners, async workers.

Trace:

```text
user URL → parser/normalizer → allow/deny decision → DNS resolution → redirect handling → server-side HTTP client → response reflection/storage/log
```

## Attack Surface Fields

Record each surface:

| Field | What to capture |
|---|---|
| Source | route, parameter, body field, header, file field |
| Fetcher | sync handler, queue worker, headless browser, image library |
| Network position | public egress, VPC, container, cloud function, pod |
| Validation | scheme allowlist, host allowlist, private IP deny, redirect policy |
| Reflection | full response, status only, timing, callback-only, stored artifact |
| Auth context | unauthenticated, user, admin, service account role |

## Safe Validation Ladder

1. **Code/config proof**: unsafe URL fetch path, missing private-range validation, redirect follow after validation.
2. **Controlled callback proof**: use a domain/server you control and verify server-side fetch metadata only.
3. **Local lab proof**: reproduce the URL parser and redirect behavior in a local container or fixture.
4. **Metadata indicator proof**: in lab/CTF or clearly defined validation, prove metadata reachability with harmless metadata fields.
5. **Credential impact proof**: production/bounty default is complete in-scope private-report evidence plus offline impact inference; do not use credentials to enumerate resources.

## Common Validation Bypass Classes

Use only within scope and one variable at a time:

- Redirect after validation: public URL redirects to private address.
- DNS resolution mismatch: validator and fetcher resolve at different times or resolvers.
- Alternate IP notation: IPv6, IPv4-mapped IPv6, integer, octal, hex, dotted-short forms.
- Userinfo/fragment confusion: `http://allowed.example@host/`, parser disagreements.
- Scheme confusion: `gopher`, `file`, `dict`, `ftp`, `jar`, `http+unix` if client supports them.
- Host normalization: trailing dots, mixed case, punycode, encoded separators.

## Evidence That Is Enough

- Controlled callback logs showing the server made the outbound request from in-scope infrastructure.
- Code path proving user input reaches a server-side fetch without private-range/redirect protections.
- In a lab, complete in-scope metadata/temporary credential-shaped response parsed by `detect_cloud_tokens.py`.

## Stop Conditions

Stop and report if any test returns real credentials, private metadata, account identifiers, resource names, or business data. Include complete in-scope evidence needed for the authorized private report, exclude unrelated data, and continue only with offline impact inference.
