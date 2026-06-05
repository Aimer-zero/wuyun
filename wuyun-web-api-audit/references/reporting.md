# Web/API Finding Report Template

```markdown
# Finding: <title>

## Summary
<Actor> can <unauthorized action> in <endpoint/component> because <missing/flawed control>. This affects <asset/invariant>.

## Technical Analysis
- Endpoint/function:
- Input source:
- Trust boundary:
- Security decision/sink:
- Missing/flawed control:

## Evidence
- Minimal request or code path:
- Observed redacted result:
- Why this crosses intended privilege/tenant/state boundary:

## Confidence
High | Medium | Low, with contradictory evidence considered.

## Remediation
- Add server-side authorization/validation at <location>.
- Enforce allowlists/schema/parameter binding/canonicalization as appropriate.
- Add regression tests for <specific bypass>.

## Safe Validation Notes
Mention tests intentionally not performed, especially data access, brute force, destructive mutations, or high-volume fuzzing.
```
