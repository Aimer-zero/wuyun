# Cloudflare WAF-Aware Workflow

Use this reference when online Web/API testing is blocked, challenged, rate-limited, or distorted by Cloudflare CDN/WAF/Bot Management/Turnstile. The goal is to preserve evidence quality and restore authorized validation paths, not to provide a generic public WAF-bypass payload pack.

## What to Determine First

Classify the blocking layer before changing payloads:

- **CDN/cache only**: `server: cloudflare`, `cf-cache-status`, cache headers, but normal application responses continue.
- **WAF/security rule**: HTTP 403, Cloudflare error 1020, `cf-ray`, rule/action in Cloudflare Security Events, or request blocked only for suspicious input.
- **Rate limit/bot challenge**: HTTP 429/403/503, `cf-mitigated: challenge`, challenge page, Turnstile, “Just a moment...” page, or browser verification.
- **Origin/app rejection**: no Cloudflare block indicators; application returns its own validation/auth error.

Record Cloudflare Ray IDs, timestamps, host/path, request method, status, and complete in-scope payload shape. Ray IDs are often the fastest way for an owner to find the matching Security Event.

## Passive Triage Helper

Prefer local analysis of captured responses or HAR files:

```bash
python3 wuyun/scripts/cloudflare_triage.py --headers response-headers.txt --body response-body.html
python3 wuyun/scripts/cloudflare_triage.py --har capture.har --json
```

The helper does not contact targets. It detects Cloudflare/CDN/WAF/challenge indicators and suggests safe next steps.

## Authorized Owner / Internal Assessment Path

When the user controls the Cloudflare zone or is working with the owner, prefer configuration-based validation instead of evasion:

1. Ask for or collect Cloudflare Security Events by Ray ID.
2. Create a staging/test hostname or path dedicated to validation.
3. Use a scoped WAF skip/allow rule for tester IP, authenticated test account, test hostname, or test path.
4. Put candidate rules in log/simulate mode when the goal is application validation.
5. Preserve rate limits and bot controls for unrelated paths/users.
6. Re-run the minimal request and compare WAF-blocked vs WAF-skipped behavior.
7. Report both layers separately: “WAF blocks this payload” is not proof the origin is safe.

## Production-Safe External Review Path

When Cloudflare blocks validation and the user has not provided owner-level controls:

- Do not escalate into high-volume fuzzing, CAPTCHA/Turnstile automation, residential proxy rotation, or bot-evasion behavior.
- Downgrade confidence honestly: “origin behavior could not be validated because Cloudflare blocked the test.”
- Prefer source review, OpenAPI review, provided logs, controlled test accounts, harmless markers, and owner-assisted replay.
- Provide the exact Ray ID and minimal request shape so the owner can validate from logs.

## CTF / Lab Path

For declared CTF/lab/sandbox targets:

- Keep attempts scoped, low-rate, and one-variable-at-a-time.
- First map which request feature triggers Cloudflare: path, method, content type, parameter name, encoding, payload class, request rate, or missing browser state.
- Use browser/runtime tooling when the challenge requires JavaScript execution or session cookies.
- Prefer architectural pivots that avoid WAF-heavy parser payloads: authz/logic/API state, source leaks, cache behavior, file paths, WebSocket/API flows, or signed client-state mistakes.
- Record tried/ruled-out WAF blockers with Ray IDs and pivot after 2-3 meaningful failures.

## Reporting Language

Use separate confidence for WAF and origin:

```text
Cloudflare WAF behavior: confirmed block/challenge, Ray ID <complete in-scope Ray ID>, status 403.
Origin vulnerability status: likely/speculative/unknown because the request did not reach or could not be proven to reach origin.
Next safe validation: owner should replay from Cloudflare logs or temporarily skip WAF on a test path/IP.
```

## Prohibited / Avoided Patterns for Public Distribution

Do not add generic payload mutation packs, CAPTCHA/Turnstile solvers, anti-bot evasion, proxy rotation, or instructions to bypass Cloudflare on third-party systems. For authorized labs, keep payload construction task-specific and evidence-minimal.
