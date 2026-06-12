# Chain Mode

Use chain mode when multiple Wuyun companion outputs need to become one
evidence-driven investigation path.

## Purpose

Chain mode connects local artifacts such as recon plans, JS extraction, HAR
analysis, OpenAPI review, auth audits, protocol inventories, cloud triage, and
evasion-analysis notes.

It should answer:

- Which skill should run next?
- Which findings may combine into one risk story?
- Which link is confirmed, likely, speculative, ruled out, or deferred?
- What is the smallest safe validation for the next link?
- What remediation would break the chain?

## Boundaries

- Planning and evidence synthesis only.
- Do not convert evasion-analysis into WAF bypass payload generation.
- Do not provide stealth fingerprint spoofing, JA3/HTTP2 manipulation, proxy
  rotation, CAPTCHA automation, or AI filter bypass libraries.
- Keep validation one link at a time with synthetic data, owned accounts, and
  low request counts.

## Workflow

1. Gather local artifacts from relevant helpers:
   - recon: `wuyun-recon/scripts/recon_plan.py`
   - routes: `wuyun-recon/scripts/route_wordlist.py`
   - JS: `wuyun-js-reverse/scripts/extract_js_surface.py`
   - browser/HAR: `wuyun-browser-runtime/scripts/analyze_har.py`
   - Web/API: `wuyun-web-api-audit/scripts/analyze_openapi.py`
   - PoC assist: `wuyun-exploit-assist/scripts/ssti_probe.py`, `sqli_payload_gen.py`, or `deser_chain_builder.py`
   - auth: `wuyun-auth-audit/scripts/auth_surface_audit.py`
   - protocol: `wuyun-protocol-analysis/scripts/protocol_inventory.py`
   - cloud: `wuyun-cloud-vuln/scripts/detect_cloud_tokens.py`
   - evasion-analysis: `wuyun-evasion/scripts/detection_resilience_plan.py`
2. Run `scripts/chain_planner.py <artifact...>`.
3. Review the recommended chain nodes and load only the next required
   companion skill.
4. Validate the highest-value unresolved link with the safest available method.
5. Report chain status by link, not as a single overconfident claim.

## Output Shape

```markdown
## Chain Mode Outcome
- Chain status: confirmed | likely | speculative | mixed | deferred
- Primary next skill:
- Highest-risk link:

## Chain Nodes
- Stage:
- Evidence:
- Recommended skill:
- Confidence:
- Safe next validation:

## Chain Breakers
- Control that would break the chain:
- Regression test:

## Deferred / Not Performed
- High-risk action intentionally not performed:
- Owner-assisted evidence needed:
```
