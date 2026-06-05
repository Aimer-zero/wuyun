# Cloud Permission Impact Triage

Use offline. Do not call cloud APIs just to discover impact in production-like scope.

## Impact Categories

| Category | Example services/actions | Typical impact |
|---|---|---|
| Object storage | OSS/COS/S3 get/list/put/delete object or bucket | data read/write, static asset tampering |
| Compute | ECS/CVM/EC2 describe/start/stop/run/user-data | service disruption, code execution path, lateral movement |
| Database | RDS/CDB/DB describe/backup/export/connect | sensitive data exposure or destructive change |
| Identity | RAM/CAM/IAM policy/user/role/token actions | privilege expansion, persistence risk |
| Secrets/KMS | Secret Manager, KMS decrypt/get secret | secret exposure and downstream compromise |
| Logging/monitoring | ActionTrail/CloudTrail/CLS/CloudWatch read/delete | evidence access or tampering |
| Network | VPC/security group/load balancer changes | exposure, traffic redirection, isolation bypass |
| Container | ACK/TKE/EKS cluster/pod/secret actions | cluster compromise or secret access |

## Offline Scoring

Score high when any of these are true:

- wildcard action/resource appears;
- identity, secrets, object storage, or database read/write actions appear;
- compute run/modify/user-data actions appear;
- logging delete/disable actions appear;
- resource scope is wildcard or account-wide.

Score medium when actions are read-only but enumerate sensitive infrastructure. Score low when actions are narrowly scoped to non-sensitive metadata and non-production resources.

## Report Language

Prefer:

```text
The exposed temporary credential appears to have object-storage and compute permissions based on the attached policy document supplied for review. I did not use the credential to list or access cloud resources.
```

Avoid:

```text
I listed buckets/instances to prove impact.
```
