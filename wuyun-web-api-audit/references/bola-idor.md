# BOLA / IDOR Review

Trace every object identifier that crosses a trust boundary.

## High-Value Sources

- Path IDs: `/users/{id}`, `/orders/{orderId}`, `/tenants/{tenantId}`.
- JSON fields: `userId`, `ownerId`, `accountId`, `organizationId`, `tenant`, `projectId`.
- Query filters and sort keys that reference owner/tenant fields.
- Batch APIs that accept arrays of IDs.

## Source → Boundary → Sink

```text
attacker-controlled object id → object fetch/query → owner/tenant/role check → response or mutation
```

A real finding needs evidence that the check is missing, late, bypassable, or based on client-controlled data.

## False-Positive Reducers

- Middleware or ORM scopes may inject tenant/owner filters invisibly.
- Admin-only routes are not IDOR unless a lower-privileged actor can reach them.
- Public objects may intentionally be readable; check write/update/delete separately.
- UUIDs are not authorization.

## Safe Validation

- Use two owned test accounts or local fixtures.
- Compare status codes/response shapes without reading private content.
- For code audit, identify where ownership is checked before response/mutation.
