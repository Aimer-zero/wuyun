# Cloudflare WAF-Aware Web/API Audit

Use this when Cloudflare CDN/WAF/Bot Management/Turnstile changes Web/API test results. Treat Cloudflare as a separate control plane from the origin application.

## Classify the Layer

- **CDN/cache present**: `server: cloudflare`, `cf-cache-status`, normal application response.
- **WAF/security block**: 403, Cloudflare error 1020, `cf-ray`, Security Event rule/action, suspicious input blocked.
- **Bot/rate challenge**: 429/403/503, `cf-mitigated: challenge`, Turnstile, browser challenge page.
- **Origin rejection**: application-specific error with no Cloudflare block/challenge indicator.

Always record method, path, status, timestamp, complete in-scope payload shape, and Cloudflare Ray ID when present.

## Passive Helper

Use captured artifacts instead of pushing more traffic:

```bash
python3 wuyun-web-api-audit/scripts/cloudflare_triage.py --headers response-headers.txt --body response-body.html
python3 wuyun-web-api-audit/scripts/cloudflare_triage.py --har capture.har
```

The helper is local-only and does not send requests.

## How to Continue When WAF Blocks You

### Owner-authorized assessment

- Ask the zone owner to look up Ray IDs in Cloudflare Security Events.
- Use a staging hostname/path or scoped WAF skip rule for tester IP/account/test route.
- Use log/simulate mode when the goal is origin vulnerability validation.
- Re-run one minimal request and compare WAF-blocked vs WAF-skipped behavior.
- Report WAF behavior and origin behavior separately.

### Production-safe review without owner controls

- Do not increase volume, automate challenges, rotate proxies, or add generic WAF-evasion payload mutation.
- Prefer source review, OpenAPI review, owner-provided logs, HAR/browser traces, and minimal inert markers.
- Mark origin behavior as unknown/likely/speculative when Cloudflare prevents decisive validation.

### CTF/lab

- Keep tests low-rate and one-variable-at-a-time.
- Identify which request property triggers Cloudflare: path, parameter, content type, encoding, payload class, rate, or missing browser state.
- Use browser/runtime tooling for JavaScript/session-dependent flows.
- Pivot to logic/authz/API/cache/source-leak paths when parser payloads are repeatedly blocked.

## Report Template

```markdown
## Cloudflare/WAF Interference
- Classification: CDN only | WAF block | bot challenge | origin rejection | unknown
- Evidence: status, headers/body marker, Ray ID, timestamp
- Effect on validation: what could not be proven at origin
- Safe next step: owner log lookup, scoped skip/staging replay, source review, or CTF pivot
```
