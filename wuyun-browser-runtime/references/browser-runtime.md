# Browser Runtime Workflow

Use this reference for authorized browser-environment reproduction and evidence capture.

## Environment Model

Record:

- browser and version,
- isolated profile path,
- target scope,
- test account/role,
- proxy/certificate state,
- capture type: HAR, Playwright trace, proxy export, screenshot, console log,
- stop conditions.

## Observation Targets

- network requests: method, URL, status, content type, redirect chain,
- auth state: cookies, CSRF headers, bearer header presence,
- storage: localStorage, sessionStorage, IndexedDB presence,
- Service Worker: registration, cached routes, offline behavior,
- runtime wrappers: fetch, XHR, WebSocket, GraphQL client,
- CSP and mixed-content behavior,
- lazy-loaded chunks and sourcemap references.

## Safe Runtime Controls

- Isolated browser profile per investigation.
- Clear cache and Service Workers before baseline captures.
- Keep one variable changed at a time.
- Use owned test accounts and synthetic records.
- Preserve request IDs, trace IDs, and timestamps.

## Evidence Hygiene

- Store HAR/trace files only in the approved project channel.
- Redact unrelated cookies, tokens, private bodies, and user data for general sharing.
- For authorized private reports, include complete in-scope values only when needed for remediation.
- Summarize decisive headers and request metadata instead of dumping full traffic.

## False-Positive Reducers

- Browser-only failures may be CSP, cache, extension, Service Worker, or third-party script issues rather than server vulnerability.
- Curl/browser differences may reflect missing cookies, headers, HTTP/2, TLS, redirect handling, or bot-defense policy.
- A blocked request proves protection behavior, not necessarily application security.
