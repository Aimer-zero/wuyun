# Modular Environment Patching

Use reversible local instrumentation to make browser/runtime behavior observable. Do not patch to evade controls.

## Allowed Patches

- Isolated browser user-data directory.
- DevTools/HAR/trace capture.
- Local request/response logging in an owned browser context.
- Source map association for local artifacts.
- Cache and Service Worker reset.
- Local proxy configuration for an approved proxy.
- Certificate trust setup for a local lab or approved interception workflow.
- Test-only feature flags provided by the system owner.

## Patch Plan Template

```markdown
## Runtime Patch Plan
- Goal:
- Environment:
- Reversible changes:
- Evidence captured:
- Sensitive data handling:
- Rollback:
- Stop condition:
```

## Rollback

- Delete isolated profile directory.
- Disable proxy settings.
- Remove local test certificates if installed.
- Clear generated HAR/trace files when no longer needed.
- Revert local overrides and feature flags.
