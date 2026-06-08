# Safe Runtime Observation

Use runtime hooks only when static evidence cannot explain decisive behavior. Keep hooks observational and scoped to an owned browser profile, local lab, or explicitly authorized target.

## Safe Observations

- Browser DevTools network capture.
- HAR export analysis.
- Breakpoints on request wrappers, token readers, route guards, and signing functions.
- Console snippets that log arguments/return values without changing requests.
- Local override of non-sensitive test values in a lab or owned account.

## Avoid

- CAPTCHA/Turnstile automation.
- Credential theft or session hijacking.
- Hooking unrelated third-party pages or user sessions.
- Proxy rotation, high-rate replay, or broad endpoint fuzzing.
- Persisting raw tokens, cookies, user data, or private response bodies.

## Hook Planning Template

```markdown
## Runtime Hook Plan
- Target runtime:
- Function/API to observe:
- Data expected:
- Why static analysis is insufficient:
- Safety boundary:
- Sensitive data handling:
- Stop condition:
```

## Generated Hook Artifacts

Use `scripts/runtime_hook_capture.py generate` when the task needs reusable code instead of a prose plan:

- `--target browser-js`: emits the raw browser init script for DevTools snippets, Playwright, Puppeteer, or browser extension injection.
- `--target playwright-python`: emits a standalone Python Playwright runner. The main script can also execute this path directly with `run --authorize-runtime-observation --scope-host <host> --url <url>`.
- `--target puppeteer`: emits a standalone Node/Puppeteer runner with the same metadata-only event collection.
- `--target frida-android-webview --scope-host <host>`: emits a Frida Android WebView template for authorized mobile-hybrid labs. Empty scope host lists do not inject.

All generated artifacts preserve the same safety boundary: scoped host allowlists, metadata-only observations, redacted sensitive headers, summarized request bodies, and no stealth or CAPTCHA bypass behavior.

## Useful Hook Targets

- `window.fetch`
- `XMLHttpRequest.prototype.open/send`
- Axios request/response interceptors
- GraphQL client `query` / `mutate`
- WebSocket constructor and `send`
- Token storage getters
- Signature, nonce, timestamp, and canonicalization helpers

## Reporting

Report only what the hook proves:

- request construction,
- auth source,
- signing input/output shape,
- endpoint reachability,
- client/server boundary assumption.

Do not claim authorization bypass, injection, SSRF, or data exposure without separate server-side validation.
