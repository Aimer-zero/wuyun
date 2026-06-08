---
name: wuyun-evasion
description: Defensive canonicalization and detection-behavior analysis companion for Wuyun. Use for owned-lab parser mismatch review, benign encoding normalization matrices, HTTP parameter pollution risk analysis, CDN/origin exposure planning, and WAF/CDN behavior attribution without stealth automation, CAPTCHA bypass, proxy rotation, or public-target bypass execution.
---

# Wuyun Evasion Analysis

Use this companion with `$wuyun`, `$wuyun-browser-runtime`, and `$wuyun-web-api-audit` when the task is to understand parser normalization, WAF/CDN/application mismatch, or possible origin exposure in an authorized environment.

## Safety Boundary

- This skill does not provide an automated WAF bypass engine.
- Use benign markers and owned lab endpoints. Do not run bypass payloads against public or third-party targets.
- Do not automate CAPTCHA/Turnstile, stealth fingerprints, proxy rotation, high-rate probing, or origin brute forcing.
- Origin analysis is a dry-run checklist unless the asset owner explicitly authorizes validation.

## Workflow

1. **Classify behavior**:
   - Use `$wuyun-browser-runtime` and HAR/headers to separate CDN/WAF/risk-control behavior from application behavior.
2. **Review canonicalization locally**:
   - Run `scripts/canonicalization_lab.py --literal WUYUN_CANONICALIZATION_TEST`.
   - Compare how client, proxy, WAF, framework, router, and app decode the same benign marker.
3. **Plan origin exposure checks**:
   - Run `scripts/origin_exposure_plan.py --domain example.com`.
   - Review SPF, MX, cert SANs, historical DNS, CDN headers, and owner-side logs before any validation.
4. **Feed findings back**:
   - Convert confirmed parser mismatch or origin exposure patterns into `$wuyun` knowledge base entries.

## References

- `references/canonicalization.md`: local normalization and parser mismatch workflow.
- `references/origin-exposure.md`: source-origin exposure review without brute forcing.

## Output Shape

```markdown
## Evasion Analysis Outcome
- Status: local-lab | hypothesis | confirmed | ruled-out
- Boundary: CDN/WAF | proxy | framework | router | app
- Marker:

## Evidence
- Normalization difference:
- Affected parser/decoder:
- Business impact:

## Safety
- Active bypass not performed:
- Owner-assisted validation needed:
```
