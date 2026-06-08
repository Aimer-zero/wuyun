---
name: wuyun-cloud-vuln
description: Cloud vulnerability research companion for Wuyun. Use for online cloud-security analysis, cloud asset exposure triage, SSRF, metadata service exposure, temporary STS/CAM/IAM credential leakage, cloud permission impact triage, bug bounty evidence collection, and cloud vulnerability reporting across Aliyun, AWS, Tencent Cloud, GCP, and Azure.
---

# Wuyun Cloud Vulnerability Research

Use this companion with `$wuyun` when the task involves online cloud-security analysis: cloud-hosted URLs/domains/IPs, object storage exposure, metadata services, SSRF, temporary cloud credentials, IAM/STS/CAM permission impact, or bug-bounty style cloud vulnerability reports.

## Safety Boundary

- Work from the task target and mode: `online-cloud`, `production-safe`, `bug-bounty`, `ctf-lab`, or `local-code-audit`.
- For online cloud targets, support low-impact fingerprinting, DNS/CNAME/CDN/storage identification, cloud header/error analysis, object storage exposure checks, SSRF callback proof, metadata/STS triage, and complete in-scope impact analysis.
- If real cloud temporary credentials appear in authorized evidence, include the complete in-scope values needed for remediation and infer impact from metadata, policy documents, token shape, and context first.
- Avoid listing buckets, databases, instances, users, secrets, logs, or business data in production-like contexts. CTF/lab mode may recover the intended artifact with minimal steps.
- Do not expose unrelated cloud keys, tokens, database records, object names, instance names, or account identifiers. For authorized private reports, output complete in-scope cloud keys, tokens, object names, instance names, and account identifiers when they are necessary to reproduce, validate, or remediate the issue.
- The user is responsible for permission and acceptable use; Wuyun focuses on bounded research, evidence quality, complete in-scope reporting, and remediation.

## Workflow

1. **Classify mode**: `online-cloud`, `production-safe`, `bug-bounty`, `ctf-lab`, or `local-code-audit`.
2. **Build the cloud/developer model**: identify cloud provider signals, DNS/CNAMEs, CDNs/WAFs, object storage buckets, URL fetchers, previewers, imports, webhooks, file processors, image loaders, server-side HTTP clients, async workers, and egress controls.
3. **Map online cloud attack surface**: exposed storage/static assets, cloud error pages, metadata indicators, SSRF parameters, request method, parser, URL validation, redirect behavior, DNS resolution point, outbound network path, and response reflection.
4. **Validate with minimal impact**:
   - Online default: fingerprint, controlled callback URL, harmless object existence checks, or local reproduction.
   - Lab/CTF: metadata endpoint checks and credential use only as needed for the intended artifact.
5. **Analyze evidence offline**:
   - `scripts/detect_cloud_tokens.py --complete` for complete in-scope cloud token evidence in authorized private reports.
   - `scripts/analyze_aliyun_sts_policy.py` for offline IAM/RAM/CAM policy impact triage.
   - `scripts/ssrf_probe_plan.py` to generate a non-executing provider-specific probe plan.
6. **Report**: summarize source → URL validation boundary → server-side fetch → metadata/STS exposure → inferred impact; include complete in-scope evidence and remediation.

## References

Load only what matches the target:

- `references/cloud-ssrf-workflow.md`: cloud SSRF attack-surface mapping and safe validation ladder.
- `references/aliyun-ssrf-sts.md`: Aliyun metadata/RAM role exposure, STS evidence, and safe impact triage.
- `references/aws-imds-ssrf.md`: AWS IMDSv1/v2 SSRF considerations and safe evidence handling.
- `references/tencent-cloud-cam-sts.md`: Tencent Cloud CAM role credential exposure and evidence handling.
- `references/cloud-permission-impact.md`: offline action-to-impact classification for cloud temporary credentials.
- `references/safe-cloud-reporting.md`: report template, complete in-scope evidence handling, and remediation checklist.

## Output Shape

```markdown
## Outcome
- Status: confirmed | likely | speculative | ruled-out
- Scope mode: online-cloud | production-safe | bug-bounty | ctf-lab | local-code-audit
- Provider: Aliyun | AWS | Tencent Cloud | GCP | Azure | unknown

## Evidence
- SSRF source:
- Boundary bypass or missing control:
- Metadata/credential indicator: <complete in-scope evidence>
- Impact inference:

## Minimal Validation Performed
- <controlled callback/offline parsing/local reproduction/lab metadata check>

## High-Risk Actions Requiring Explicit Permission
- <cloud API listing/data access/actions intentionally not performed>

## Remediation
- URL allowlist, resolver pinning, private-range deny, redirect controls, IMDS hardening, least-privileged role policy, egress restrictions, token rotation.
```
