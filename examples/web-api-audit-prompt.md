# Example: Online Web/API Audit Prompt

```text
Use $wuyun and $wuyun-web-api-audit.
Mode: online-web-api.

Target:
- https://example.com or https://api.example.com

Task:
1. Run tool preflight and choose the best online audit workflow.
2. Fingerprint technology, headers, cookies, robots/sitemap, OpenAPI/Swagger, HTML, and JS bundles.
3. Build endpoint, role, tenant, object ID, upload, URL-fetcher, and business-flow inventory.
4. Generate prioritized hypotheses for BOLA/IDOR, BFLA, injection, SSRF, file handling, XSS/SSTI, and business logic.
5. Validate with low-impact request replay, targeted parameter checks, controlled accounts if available, and complete in-scope request diffs.
6. Report confirmed/likely/speculative findings separately with evidence, confidence, remediation, and regression tests.
```
