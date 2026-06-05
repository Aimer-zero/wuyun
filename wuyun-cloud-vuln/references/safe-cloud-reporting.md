# Safe Cloud Vulnerability Reporting

## Report Template

```markdown
# Cloud SSRF / Temporary Credential Exposure

## Summary
<Endpoint/function> accepts user-controlled URLs and fetches them server-side without sufficient private-network and redirect protections. In the tested scope this can reach cloud metadata and expose temporary cloud credentials, creating risk to <inferred cloud assets>.

## Scope and Safety
- Scope mode: <production-safe | bug-bounty | ctf-lab>
- Active tests performed: <controlled callback/local reproduction/lab metadata check>
- Tests intentionally not performed: no cloud resource listing, no object/database reads, no credential persistence.

## Technical Flow
1. Source: <route/parameter>
2. Boundary: <URL validation/redirect/DNS control>
3. Sink: <server-side HTTP client>
4. Evidence: <redacted metadata/credential indicator>
5. Impact inference: <policy/action/service evidence>

## Evidence
- Controlled callback: <timestamp/source IP or request metadata, redacted>
- Credential indicator: <redacted fields only>
- Offline analysis command: `python3 wuyun-cloud-vuln/scripts/detect_cloud_tokens.py <file>`

## Remediation
- Enforce scheme/host allowlists for URL fetchers.
- Resolve and re-check private/link-local ranges before connect and after redirects.
- Block metadata service from app network namespaces that do not require it.
- Require provider metadata hardening where available.
- Reduce role permissions and rotate exposed credentials.
- Add regression tests for redirect and IP-encoding bypasses.
```

## Redaction Rules

- Show only key prefixes/suffixes or field presence.
- Do not include raw `AccessKeySecret`, `SecretAccessKey`, `SecurityToken`, `TmpSecretKey`, `Token`, or `access_token` values.
- Replace account IDs, bucket names, instance IDs, database names, and internal hostnames unless the program explicitly allows them in reports.
