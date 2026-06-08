---
name: wuyun-auth-audit
description: Authentication and authorization audit companion for Wuyun. Use for JWT/OAuth/OIDC/SAML/session/cookie/multi-tenant authorization reviews, redirect_uri/state/nonce triage, SAML XSW risk analysis, session fixation and cookie flag checks, tenant isolation hypotheses, and safe authorization validation planning without brute force or credential theft.
---

# Wuyun Auth Audit

Use this companion with `$wuyun` and `$wuyun-web-api-audit` when authentication, session, identity federation, or authorization boundaries are central to the task.

## Safety Boundary

- Passive first: inspect local requests, HARs, configs, tokens supplied by the user, and source code.
- Do not steal credentials, brute force JWT secrets, bypass MFA, enumerate users, or attack unrelated tenants.
- Active authz validation must use owned accounts, synthetic records, low request counts, and explicit scope.
- JWT analysis is offline structure/risk triage by default; do not run weak-key cracking unless explicitly authorized for a lab/test token.

## Workflow

1. **Inventory identity surfaces**:
   - Run `scripts/auth_surface_audit.py <path>` on HAR/HTTP messages/source/configs.
   - Identify JWTs, cookies, OAuth/OIDC redirects, SAML markers, session headers, tenant IDs, and role/permission fields.
2. **Analyze token/session controls**:
   - Run `scripts/jwt_audit.py <jwt-or-file>` for offline JWT header/payload risk triage.
   - Check cookie flags, session rotation, CSRF boundaries, SameSite, Secure, HttpOnly, and domain/path scope.
3. **Generate hypotheses**:
   - OAuth redirect_uri/state/nonce misuse.
   - JWT alg/kid/jku/x5u/jwks_uri trust mistakes.
   - SAML XML Signature Wrapping or unsigned assertion risk.
   - Session fixation, missing cookie flags, weak logout, cross-subdomain cookie scope.
   - Tenant/object authorization gaps.
4. **Validate safely**:
   - Use owned accounts and synthetic tenants.
   - Prefer request diffs, server logs, and metadata-only proof.
   - Use `$wuyun-web-api-audit` active validation only with explicit authorization.

## References

- `references/oauth-oidc-saml.md`: OAuth/OIDC/SAML review workflow and false-positive reducers.
- `references/session-tenant-authz.md`: session, cookie, CSRF, tenant isolation, BOLA/BFLA validation.

## Output Shape

```markdown
## Auth Audit Outcome
- Status: inventory | hypothesis | confirmed | ruled-out
- Surface: JWT | OAuth/OIDC | SAML | session | tenant authz
- Affected component:

## Evidence
- Token/session/cookie/request:
- Boundary/control:
- Server-side decision:

## Validation
- Safe check:
- Required accounts/roles:
- High-risk actions intentionally not performed:
```
