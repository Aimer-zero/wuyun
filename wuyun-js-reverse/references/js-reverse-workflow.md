# JS Reverse Workflow

Use this reference when reviewing frontend bundles, sourcemaps, HAR exports, SPA/H5 assets, or browser-captured scripts.

## Artifact Classification

- **Bundle**: minified `.js`, chunk files, webpack/vite/rollup output.
- **Sourcemap**: `.map` files or `sourceMappingURL` references that may disclose original source paths and code.
- **Source tree**: local frontend repository with route definitions, request wrappers, stores, and build config.
- **Runtime capture**: scripts and requests observed in a browser, HAR, proxy, or DevTools export.

## Static Extraction Checklist

- Absolute API URLs and relative API paths.
- Base URL variables, environment prefixes, feature flags, tenant/account route segments.
- Request wrappers and interceptors: `fetch`, `axios`, `XMLHttpRequest`, GraphQL clients, WebSocket constructors.
- Auth sources: `Authorization`, bearer tokens, cookies, local/session storage, CSRF headers.
- Client-side routing: hidden admin panels, feature-gated paths, debug screens.
- Signing logic: HMAC/hash calls, nonce/timestamp construction, canonical request strings, app keys.
- Sourcemap references and original source names.
- Secret-like values: report only complete in-scope evidence in authorized private reports.

## High-Value Hypotheses

- UI hides a route but server lacks function-level authorization.
- Object IDs, tenant IDs, org IDs, or account IDs are client-controlled and not checked server-side.
- Request signatures are replayable, predictable, or use client-exposed secrets.
- Debug, staging, admin, or internal API hosts are shipped to production clients.
- GraphQL operations expose sensitive fields or mutation paths not visible in the UI.
- WebSocket channels rely on client-side room/user identifiers.
- Sourcemaps disclose source code, internal paths, or comments that change risk.

## False-Positive Reducers

- A frontend route is not a vulnerability unless the server trusts the client-side control.
- A hardcoded public key, analytics token, or publishable payment key may be intended; check provider semantics.
- A URL in a bundle may be dead code, test fixture, or documentation; validate reachability only in scope.
- Obfuscation is not itself a finding; identify the protected logic and security assumption.
- Sourcemap exposure is higher impact when it reveals secrets, internal endpoints, auth logic, or exploitable source.

## Evidence Format

Record:

- Artifact path and line/offset.
- Extracted value or compact redacted value.
- Surrounding request wrapper or config owner.
- Why it matters to a server-side trust boundary.
- Safe validation step and confidence level.
