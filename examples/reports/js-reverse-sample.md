# Sample Report: JS Reverse API Surface

## Summary
- Status: extracted-leads
- Artifact: `dist/app.bundle.js`
- Affected component: frontend request wrapper and API route inventory
- Vulnerability class: attack-surface expansion; follow-up Web/API authorization review required

## Technical Analysis
- Source/input: static JavaScript bundle review.
- Boundary/control: client code builds API requests and attaches bearer tokens from browser storage.
- Sink/decision/state change: server API endpoints discovered from client routes; no server-side behavior validated in this sample.

## Supporting Evidence
- `app.bundle.js:1208`: request wrapper references `Authorization`.
- `app.bundle.js:1492`: API path `/api/admin/users`.
- `app.bundle.js:2110`: GraphQL mutation name `UpdateUserRole`.
- `app.bundle.js:3102`: `sourceMappingURL=app.bundle.js.map`.

## Root Cause
Frontend bundles expose server attack surface and client-side assumptions. This is not automatically a vulnerability, but it can reveal routes and logic that require server-side authorization validation.

## Confidence Level
- Level: medium for attack-surface exposure.
- Rationale: static evidence is clear, but server reachability and authorization behavior are not yet validated.

## Validation Suggestions
- Use owned low-privilege and admin accounts to compare `/api/admin/users` behavior.
- Confirm whether `UpdateUserRole` requires server-side role checks.
- Check sourcemap availability and whether it exposes sensitive source, comments, or secrets.

## Remediation Guidance
- Enforce all authorization server-side.
- Remove production sourcemaps unless intentionally published and reviewed.
- Avoid shipping unused admin/debug endpoints in production bundles.

## Lessons Learned
- Client-only hiding is not a security control.
- Static JS extraction should feed Web/API testing, not replace it.
