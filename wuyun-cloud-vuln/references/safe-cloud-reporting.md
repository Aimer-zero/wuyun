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
4. Evidence: <complete in-scope metadata/credential indicator>
5. Impact inference: <policy/action/service evidence>

## Evidence
- Controlled callback: <timestamp/source IP or complete in-scope request metadata>
- Credential indicator: <complete in-scope fields needed for remediation>
- Offline analysis command: `python3 wuyun-cloud-vuln/scripts/detect_cloud_tokens.py --complete <file>`

## Remediation
- Enforce scheme/host allowlists for URL fetchers.
- Resolve and re-check private/link-local ranges before connect and after redirects.
- Block metadata service from app network namespaces that do not require it.
- Require provider metadata hardening where available.
- Reduce role permissions and rotate exposed credentials.
- Add regression tests for redirect and IP-encoding bypasses.
```

## Complete In-Scope Evidence Rules

- In authorized private remediation reports, include complete in-scope identifiers and credential indicators needed to reproduce, validate, or remediate the issue.
- Do not add unrelated cloud resources, users, databases, objects, or secrets that are not necessary to prove the finding.
- Do not use exposed credentials to enumerate breadth or collect business data unless the task explicitly permits that exact action.
