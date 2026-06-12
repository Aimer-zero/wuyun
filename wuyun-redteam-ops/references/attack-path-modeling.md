# Attack Path Modeling

Use attack paths to connect surface signals into testable hypotheses. A path is only useful when it has evidence, a trust boundary, a safe validation step, and a remediation/detection owner.

## Profiles and likely handoffs

| Profile | Common surfaces | Wuyun handoff |
|---|---|---|
| web | APIs, sessions, uploads, SSRF, XSS/SSTI, business logic | `$wuyun-web-api-audit`, `$wuyun-exploit-assist` after a lead exists |
| cloud | metadata, STS/CAM/IAM, object storage, cloud logs, SSRF | `$wuyun-cloud-vuln` |
| identity | JWT, OAuth/OIDC, SAML, cookies, tenant authz | `$wuyun-auth-audit` |
| ai | LLM prompts, RAG, agent tools, output sinks | `$wuyun-ai-audit` |
| internal | admin panels, CI/CD, dependency/config exposure, lateral trust | `$wuyun`, `$wuyun-recon`, specialist skills by surface |
| ctf | challenge service, binary/web/protocol artifact, flag objective | `$wuyun` ctf-lab mode plus specialist skills |

## Scoring model

Score each path with 1-5 points per factor:

- Evidence strength: source/runtime/proxy proof beats keyword-only leads.
- Boundary value: authz, tenant, cloud, identity, or data-integrity boundaries rank higher.
- Validation safety: local/offline/canary checks rank higher than invasive checks.
- Remediation value: clear owner and control improvement rank higher.
- Detection value: produces useful telemetry or a regression test.

Prioritize high score and low validation risk first.

## Safe path schema

```json
{
  "path_id": "web-api-tenant-authz",
  "tactic": "Privilege boundary validation",
  "surface": "REST endpoint with tenantId/userId",
  "evidence": ["OpenAPI path", "HAR request", "source route"],
  "hypothesis": "Object ownership may be enforced inconsistently",
  "safe_validation": "Use two owner-provided test tenants and compare metadata-only 403/404/200 behavior",
  "blocked_actions": ["do not enumerate real tenants", "do not dump records"],
  "next_skill": "$wuyun-web-api-audit",
  "confidence": "medium"
}
```

## Reporting focus

For each path, report:

- What boundary could fail.
- What evidence supports the path.
- What contradictory controls were checked.
- What safe validation was performed or deferred.
- What exact fix, regression test, and detection query would break the path.
