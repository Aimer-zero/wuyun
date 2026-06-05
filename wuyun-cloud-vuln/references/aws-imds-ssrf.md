# AWS IMDS SSRF Triage

Use for AWS metadata exposure analysis. AWS EC2 instance metadata is normally reachable at the link-local metadata address from the instance network namespace. IMDSv2 adds a session-token requirement that often reduces SSRF exploitability when the vulnerable fetcher cannot issue the required PUT request and preserve headers.

## Evidence Classes

- IMDS reachability indicator: status/timing/body shape from a lab or controlled test.
- IMDSv1 risk: fetcher can retrieve metadata with a simple GET.
- IMDSv2 bypass risk: fetcher supports method override/PUT and custom headers, or the application provides a proxy-like primitive.
- Credential-shaped response: `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`.

Use offline detection:

```bash
python3 wuyun-cloud-vuln/scripts/detect_cloud_tokens.py evidence.txt
```

## Production-Safe Rules

- Do not use exposed credentials to call `ListBuckets`, `DescribeInstances`, `GetObject`, `GetSecretValue`, or equivalent APIs unless the task explicitly permits that exact action.
- Controlled callback proof plus code-level reachability is usually enough for a report.
- If credentials appear, redact and rotate; do not test breadth by enumerating resources.

## Remediation

- Require IMDSv2 and set hop limit defensively.
- Block metadata IP from application fetchers and containers that do not need it.
- Add URL allowlists and deny private/link-local ranges after final resolution.
- Avoid attaching broad instance profiles to internet-facing fetchers.
- Monitor metadata access anomalies and credential use from unexpected sources.
