# Wuyun Vulnerability Report Template

Use this template for confirmed and likely findings. For speculative leads, present them as investigation notes, not vulnerabilities.

## Report Header

```markdown
# Vulnerability Report: <title>

- Target / Component: <service, repo, module, endpoint>
- Assessment Scope: <declared scope>
- Report Date: YYYY-MM-DD
- Researcher / Agent: Wuyun
- Severity: Critical | High | Medium | Low | Informational
- Confidence: High | Medium | Low
- Status: Confirmed | Likely | Needs validation
```

## 1. Summary

Explain the issue in one short paragraph:

- What is vulnerable?
- Who can trigger it?
- What can be accessed, modified, or executed?
- Why does it matter?

```markdown
<Actor> can <action> in <component> because <root cause>. This may allow <impact> affecting <asset/users/tenant/system>.
```

## 2. Technical Analysis

Describe the end-to-end flow:

```markdown
### Affected Flow
1. <Input source / endpoint / function>
2. <Validation or trust boundary>
3. <Security decision / sink>
4. <Impactful result>

### Rooted Code Path or Runtime Path
- Source: `<file:function or endpoint>`
- Boundary: `<authz/parser/sanitizer/cache/job>`
- Sink/Decision: `<query/template/command/file/action>`
```

Include exact decisive details and enough surrounding context for a human reviewer to judge validity. Do not mask in-scope evidence in an authorized private report. Avoid dumping large unrelated logs when a precise excerpt, path, hash, timestamp, or command output proves the point.

## 3. Supporting Evidence

````markdown
### Evidence Summary
- Affected endpoint/file:
- Attacker-controlled input:
- Missing or flawed control:
- Observed impact:
- Complete in-scope evidence:

### Minimal Reproduction
```bash
# commands or steps here
```

### Observed Result
```text
<decisive output, status code, response field, log line, or state change>
```
````

For HTTP findings, prefer this compact shape:

````markdown
### Request
```http
<method> <path> HTTP/1.1
Host: <host>
...
```

### Response / Side Effect
```http
HTTP/1.1 <status>
...
```
````

## 4. Root Cause

Explain the failed assumption:

```markdown
The implementation assumes <assumption>. However, <attacker-controlled condition> violates that assumption because <missing/incorrect control>. The security boundary should be enforced at <server/component>, but currently <actual behavior>.
```

## 5. Impact

Cover practical impact and required conditions:

- Required privilege:
- User interaction required:
- Data exposed or modified:
- Scope across users/tenants/systems:
- Persistence or repeatability:
- Business impact:

## 6. Confidence Level

```markdown
Confidence: High | Medium | Low

Rationale:
- Supporting evidence:
- Remaining uncertainty:
- False-positive checks performed:
```

## 7. Validation Suggestions

For reviewers or maintainers:

- How to reproduce in a safe test environment.
- Which logs, database rows, or state transitions to inspect.
- Which additional roles, tenants, or configurations to test.
- How to confirm fix effectiveness.

## 8. Remediation Guidance

Provide specific fixes:

- Enforce authorization/ownership/tenant checks at the server-side decision point.
- Canonicalize and validate input before security decisions.
- Use parameterized queries or safe APIs.
- Move sensitive logic out of client-controlled state.
- Add rate limits, idempotency keys, locks, or transactions for race-sensitive flows.
- Add regression tests that fail before the fix and pass after it.
- Add monitoring or audit logging for attempted abuse.

## 9. Regression Test Ideas

```markdown
- Test name:
- Setup:
- Malicious or boundary input:
- Expected secure result:
- Negative control:
```

## 10. Lessons Learned

```markdown
- Pattern:
- Signal that found it:
- False-positive reducer:
- Memory update:
```

## Severity Guidance

Use business impact and exploitability, not just vulnerability class names.

- **Critical**: unauthenticated RCE, full tenant/system compromise, mass sensitive data exposure, complete auth bypass.
- **High**: cross-tenant access, privileged action by low-privilege user, stored XSS in privileged context, significant data modification/exfiltration.
- **Medium**: limited unauthorized access, meaningful reflected/DOM XSS, SSRF with constrained impact, exploitable business logic with moderate requirements.
- **Low**: limited information leak, defense-in-depth issue with low practical impact.
- **Informational**: hardening recommendation, unreachable issue, or no demonstrated security impact.

## Compact Finding Format

Use this when the user asks for a concise result:

```markdown
## <Finding Title>
- Severity: <level>
- Confidence: <level>
- Affected: <component>
- Summary: <one sentence>
- Evidence: <decisive path/request/result>
- Root cause: <failed assumption>
- Fix: <specific remediation>
```
