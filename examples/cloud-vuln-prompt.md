# Example: Online Cloud Security / SSRF Prompt

```text
Use $wuyun and $wuyun-cloud-vuln.
Mode: online-cloud.

Target:
- https://example.com
- or example-bucket.s3.amazonaws.com / OSS / COS / Azure Blob / GCS URL

Task:
1. Fingerprint cloud provider signals, DNS/CNAME, CDN/WAF, storage endpoints, headers, and error pages.
2. Map URL-fetching / SSRF attack surface and trust boundaries.
3. Use controlled callback proof where useful; keep requests low-impact.
4. Check object-storage exposure and cloud metadata/temporary-credential indicators without printing secrets.
5. Infer impact from redacted evidence, role/policy context, and observed cloud behavior.
6. Produce a report with evidence, confidence, high-risk next steps, remediation, and regression tests.
```
