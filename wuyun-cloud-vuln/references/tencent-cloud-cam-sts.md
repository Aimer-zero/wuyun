# Tencent Cloud CAM Role / STS Exposure

Use for Tencent Cloud metadata and CAM temporary credential exposure triage.

## Credential Indicators

Tencent Cloud temporary credentials commonly include:

- `TmpSecretId`
- `TmpSecretKey`
- `Token`
- `ExpiredTime` or expiration-like fields

Run offline detection:

```bash
python3 wuyun-cloud-vuln/scripts/detect_cloud_tokens.py --complete evidence.txt
```

## Safe Impact Triage

Avoid using exposed credentials against COS, CVM, CAM, CDB, TKE, or CLS in production-like scope. Infer impact from:

- role/service name if provided by metadata;
- user-provided CAM policy document;
- application deployment context;
- offline action classification with `analyze_aliyun_sts_policy.py`.

## Remediation

- Prevent untrusted URL fetchers from reaching metadata and private ranges.
- Enforce URL allowlists and redirect revalidation.
- Apply least-privileged CAM roles to compute resources.
- Rotate exposed temporary credentials and inspect audit logs for anomalous use.
