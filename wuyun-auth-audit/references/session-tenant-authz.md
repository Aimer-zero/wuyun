# Session And Tenant Authorization

## Cookie / Session Checks

- Secure, HttpOnly, SameSite, Domain, Path, Max-Age/Expires.
- session rotation after login and privilege elevation.
- logout invalidation and refresh token revocation.
- CSRF token binding to session and request origin.
- cross-subdomain cookie scope.

## Tenant Authorization

- object IDs, tenant IDs, org IDs, workspace IDs, role IDs.
- server-side ownership checks before reads/writes.
- admin/function-level guards.
- background jobs and exports scoped to tenant.
- WebSocket/channel subscription authorization.

## Safe Validation

- two owned accounts or tenants.
- synthetic records only.
- one object/tenant ID changed at a time.
- compare status, length, hash, and semantic authorization result.
