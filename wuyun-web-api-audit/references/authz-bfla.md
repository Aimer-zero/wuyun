# Authorization and BFLA Review

Broken Function Level Authorization happens when a lower-privileged user can directly invoke privileged functionality.

## Surfaces

- Admin routes hidden only by the UI.
- Different HTTP methods on the same path.
- Bulk, export, import, impersonation, approval, refund, role-management, and debug endpoints.
- GraphQL mutations and internal RPC method names.
- Feature flags or environment gates that are client-controlled.

## Evidence to Seek

- Route registered without auth middleware/guard/decorator.
- Guard exists but checks only authentication, not role or tenant.
- API gateway protects a path pattern, but backend exposes alternate method/path.
- Client role claim is trusted without server-side verification.

## Safe Validation

- Use owned low-privileged and privileged accounts.
- Call only harmless read-only or synthetic test actions unless the task explicitly permits that exact action.
- For mutating endpoints, prove missing authorization via code path or dry-run/test fixture when possible.
