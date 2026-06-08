# Risk-Control And Bot-Defense Triage

This workflow classifies protection behavior and supports owner-assisted validation. It does not provide evasion guidance.

## Signals

- CDN/WAF headers: Cloudflare, Akamai, Fastly, Imperva, Sucuri, AWS WAF, Azure Front Door.
- Challenge markers: CAPTCHA, Turnstile, JavaScript challenge, device verification.
- Bot/risk cookies: `__cf_bm`, `cf_clearance`, Akamai bot cookies, device/session binding cookies.
- Status patterns: 401, 403, 429, 503 challenge pages, repeated redirects.
- Rate-limit headers: `Retry-After`, `X-RateLimit-*`.
- Trace IDs: `cf-ray`, `x-request-id`, `x-amzn-trace-id`, Akamai request IDs.

## Classification

- **Challenge**: user/browser must complete a verification.
- **Block**: policy denies request before origin.
- **Rate limit**: request volume, path, IP, user, or account threshold.
- **Device/session binding**: token/cookie bound to browser/device state.
- **Origin auth failure**: application denies request after CDN.
- **Origin error**: application/server failure unrelated to WAF.
- **Cache/CDN behavior**: edge response differs from origin due cache or routing.

## Owner-Assisted Validation

Ask for:

- staging environment,
- allowlisted test account/IP,
- temporary lower-sensitivity policy,
- WAF/CDN logs for captured Ray/request IDs,
- server logs for matching request IDs,
- synthetic tenant/user records,
- written scope for any active replay.

## Avoid

- CAPTCHA/Turnstile automation,
- stealth fingerprint patching,
- proxy rotation,
- high-volume retries,
- account lockout experiments,
- bypass payload packs,
- testing unrelated tenants or users.

## Reporting

Separate:

- protection behavior observed,
- origin behavior inferred,
- application vulnerability confirmed,
- validation blocked by policy,
- owner support needed.
