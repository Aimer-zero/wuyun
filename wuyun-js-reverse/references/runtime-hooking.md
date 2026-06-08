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
