# Wuyun CTF/Lab Mode

Use this reference for CTF, lab, sandbox, or deliberately vulnerable targets declared by the user.

## Operating Rules

- Stay inside the challenge scope.
- Do not attack unrelated platform infrastructure, other players, personal accounts, or non-challenge services.
- Prefer minimal exploitation needed to recover the intended artifact.
- Keep exact replay steps and a tried/ruled-out list.

## Standard Loop

1. **Inventory**: files, services, ports, routes, credentials, tokens, versions.
2. **Developer model**: where should the flag/secret/state live? Which layer enforces trust?
3. **Enumerate**: passive first, then active scoped enumeration.
4. **Hypothesize**: generate several attack paths and rank by impact/reachability.
5. **Exploit**: test one variable at a time; pivot after 2-3 meaningful failures.
6. **Recover artifact**: search outputs for flag formats and record replay steps.
7. **Explain**: root cause, exploit path, and how to patch.

## Common Flag Patterns

Search text outputs, decoded content, logs, and files for:

```regex
flag\{.*?\}|FLAG\{.*?\}|CTF\{.*?\}|DASCTF\{.*?\}
```

Also infer competition-specific formats from challenge instructions.

## Tried / Ruled-Out Template

```markdown
| Path | Attempts | Result | Why ruled out / next pivot |
|---|---:|---|---|
| Directory brute force | 2 wordlists | only static files | no dynamic routes discovered |
| JWT none-alg | manual token edit | rejected | server validates alg/key |
```

## Final Output Template

```markdown
## Outcome
- Flag/artifact: `<exact intended CTF artifact>`

## Exploit Path
1. <step>
2. <step>
3. <step>

## Replay
```bash
<minimal commands or script>
```

## Root Cause
<why the challenge was vulnerable>

## Tried / Ruled Out
<table or bullets>
```
