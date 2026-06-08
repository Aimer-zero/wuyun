---
name: wuyun-recon
description: Reconnaissance planning companion for Wuyun. Use for scoped recon planning, GitHub/GitLab dork generation, certificate transparency query planning, subdomain enumeration tool plans, route/JS-derived wordlist generation, internal route and feature-flag discovery from local artifacts, and Burp/Caido/ffuf/nuclei/sqlmap integration outputs without mass scanning by default.
---

# Wuyun Recon

Use this companion with `$wuyun` for scoped reconnaissance that supports later evidence-driven vulnerability research.

## Safety Boundary

- Default to dry-run plans, local artifact analysis, and owner-approved scope.
- Do not mass scan, scrape unrelated repositories, collect secrets, or enumerate third-party tenants.
- Active recon commands must be reviewed, rate-limited, and executed only inside written scope.

## Workflow

1. **Plan recon**:
   - Run `scripts/recon_plan.py --domain example.com --org example-org`.
   - Generate GitHub/GitLab dorks, CT URLs, subdomain tool commands, and scope notes.
2. **Local artifact recon**:
   - Use `$wuyun-js-reverse` on bundles.
   - Run `scripts/route_wordlist.py <artifact>` to convert route/API evidence into a wordlist for scoped ffuf/Burp/Caido workflows.
3. **Tool integration**:
   - Run `scripts/tool_artifact_generator.py` to generate Burp/Caido-compatible raw HTTP, custom nuclei templates, sqlmap dry-run plans, or ffuf plans.
   - Generate custom nuclei templates only for owned fingerprints and low-impact checks.
   - Use sqlmap wrappers only for confirmed injection candidates with low concurrency and no data dumping.
4. **Report**:
   - Separate discovered assets, in-scope assets, out-of-scope assets, and validation state.

## References

- `references/recon-workflow.md`: scoped recon planning and false-positive reducers.
- `references/tool-integrations.md`: Burp/Caido/ffuf/nuclei/sqlmap integration guidance.

## Output Shape

```markdown
## Recon Outcome
- Status: plan | local-artifact | owner-approved-active | out-of-scope
- Scope:
- Assets:
- Tools:

## Evidence
- Source:
- Query/command:
- Why in scope:

## Next Step
- Passive/local:
- Active command requiring approval:
```
