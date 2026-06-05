# Aliyun SSRF → RAM Role / STS Exposure

Use for Aliyun cloud SSRF triage. Aliyun ECS metadata commonly uses the link-local service at `100.100.100.200`. The sensitive path for RAM role credentials is the RAM security-credentials metadata path.

## What to Look For

Credential-shaped Aliyun evidence usually contains these fields:

- `AccessKeyId` — temporary IDs often start with an STS-style prefix.
- `AccessKeySecret` — secret material; always redact.
- `SecurityToken` — session token; always redact.
- `Expiration` — token validity end time.
- `Code` — success/error indicator.
- role name from the metadata path or response context.

Run offline detection:

```bash
python3 wuyun-cloud-vuln/scripts/detect_cloud_tokens.py evidence.txt
```

## Production-Safe Impact Triage

Do not call OSS/RDS/ECS/RAM APIs with exposed credentials in production-like scope. Infer impact from:

- credential type and provider fields;
- RAM role name or service name, redacted;
- code/config showing the role is attached to the SSRF-capable compute;
- user-provided policy document, if supplied by the program owner;
- offline policy analysis with `analyze_aliyun_sts_policy.py`.

## CTF/Lab Notes

In explicit CTF/lab scope, the intended challenge may require using temporary credentials to retrieve a flag. Keep actions minimal:

1. identify role and expiration;
2. infer service from policy/action names;
3. access only the challenge artifact path or synthetic resource;
4. record replay steps and stop after flag/artifact recovery.

## Remediation

- Block metadata access from URL fetchers using egress policy, container network policy, or host firewall.
- Deny link-local/private ranges after final DNS resolution and after every redirect.
- Disable response reflection for server-side fetchers where possible.
- Use least-privileged RAM roles and short-lived sessions.
- Rotate exposed temporary credentials and review CloudTrail/ActionTrail-equivalent logs for misuse.
