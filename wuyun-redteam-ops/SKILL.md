---
name: wuyun-redteam-ops
description: Authorized red-team and purple-team operations planning companion for Wuyun. Use for engagement scoping, rules-of-engagement checks, adversary-emulation planning, attack-path modeling, ATT&CK-style tactic mapping, detection-and-remediation workstreams, tabletop/lab/CTF operation plans, and cross-skill handoff planning without malware, stealth persistence, credential theft, destructive actions, or unapproved WAF/bot-defense bypass.
---

# Wuyun Red Team Ops

## Mission

Plan authorized red-team and purple-team work as an evidence-driven operation, not as a payload dump. Keep every step tied to declared scope, rules of engagement, low-impact validation, detection opportunities, and remediation outcomes.

Use this companion with `$wuyun` when the task is broader than one vulnerability class and needs an operator-style plan: objectives, assets, assumptions, attack paths, safe validation steps, handoffs to other Wuyun skills, and reporting checkpoints.

## Safety Boundary

- Confirm scope, authorization, timebox, allowed test windows, excluded assets, and stop conditions before active testing.
- Default to passive discovery, local artifacts, dry-runs, canary markers, synthetic data, and owner-assisted validation.
- Do not provide malware, credential theft, persistence, stealth automation, destructive actions, data dumping, WAF bypass payload packs, CAPTCHA automation, or proxy/fingerprint evasion instructions.
- Treat obtained tokens, credentials, business data, and logs as sensitive evidence: redact by default and use owner-approved channels for exact material.
- For CTF/lab/sandbox targets, keep exploitation bounded to the intended challenge objective and record replayable steps.

## Workflow

1. **Frame the engagement**
   - Capture objective, in-scope assets, profiles (`web`, `cloud`, `identity`, `ai`, `internal`, `ctf`, `full`), assumptions, constraints, and success criteria.
   - If any of these are missing for production-like targets, ask one short clarification before impactful traffic.

2. **Build attack paths**
   - Read `references/attack-path-modeling.md` when prioritizing multiple paths.
   - Use `scripts/redteam_plan.py` for a deterministic plan skeleton.
   - Use `scripts/attack_path_matrix.py` on local Wuyun artifacts to cluster signals into tactics, next skills, and safe checks.
   - Use `scripts/purple_team_mapper.py` after a plan or matrix exists to turn paths into telemetry, safe emulation, remediation tests, and retest workstreams.

3. **Route to specialist skills**
   - Web/API → `$wuyun-web-api-audit`
   - Cloud/SSRF/temporary credentials → `$wuyun-cloud-vuln`
   - Identity/JWT/OAuth/SAML/tenant authz → `$wuyun-auth-audit`
   - JS/runtime/protocol → `$wuyun-js-reverse`, `$wuyun-browser-runtime`, `$wuyun-protocol-analysis`
   - AI/RAG/agent workflows → `$wuyun-ai-audit`
   - Canary-safe PoC planning after a lead exists → `$wuyun-exploit-assist`
   - Detection-resilience or WAF/CDN attribution → `$wuyun-browser-runtime` and `$wuyun-evasion` with defensive constraints

4. **Run validation safely**
   - Change one variable at a time.
   - Prefer metadata-only proof, controlled canary strings, owned test accounts, synthetic records, or CTF flags.
   - Stop and document a safe alternative if validation would require credential theft, destructive impact, or access to unrelated data.

5. **Report and learn**
   - Produce an evidence ledger, attack-path confidence, detection gaps, remediation owners, regression tests, and lessons learned.
   - Convert reusable patterns into Wuyun knowledge entries only after redacting secrets and unrelated data.

## Bundled Helpers

- `scripts/redteam_plan.py`: creates a local-only engagement plan with guardrails, phases, attack paths, handoffs, and evidence checkpoints.
- `scripts/attack_path_matrix.py`: clusters local findings/HAR/JSON/text artifacts into ATT&CK-style tactics, Wuyun skill handoffs, safe validation steps, and blocked actions.
- `scripts/purple_team_mapper.py`: converts local plans/matrices/artifacts into purple-team telemetry, detection objectives, safe emulation, remediation tests, and evidence ledger fields.

Examples:

```bash
python3 wuyun-redteam-ops/scripts/redteam_plan.py --profile web --profile cloud --asset api.example.invalid --objective "assess tenant isolation" --json
python3 wuyun-redteam-ops/scripts/attack_path_matrix.py recon.json js-surface.json audit.json --profile web --json
python3 wuyun-redteam-ops/scripts/purple_team_mapper.py attack-matrix.json --owner security --json
```

## References

- `references/redteam-workflow.md`: engagement framing, rules of engagement, evidence ledger, phase gates, and reporting loop.
- `references/attack-path-modeling.md`: profile-to-tactic mapping, prioritization, confidence model, safe validation examples, and handoff schema.
- `references/purple-team-detection.md`: detection/remediation mapping workflow, telemetry categories, safe emulation defaults, and blocked actions.
