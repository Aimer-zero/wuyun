---
name: wuyun-supply-chain-audit
description: Supply-chain, CI/CD, dependency, secret-scanning, and language-pack audit companion for Wuyun. Use for GitHub Actions/GitLab CI/OIDC/runner workflow review, dependency manifest triage, SBOM and scanner-output normalization, Semgrep/Gitleaks/Trivy/npm-audit/pip-audit result import, and selecting focused code-audit packs for Node/Next.js, Python, Java/Spring, Go, Rust, C/C++, mobile, and smart-contract repositories.
---

# Wuyun Supply Chain Audit

## Mission

Review the build, dependency, CI/CD, and language-specific security posture around a repository before deeper vulnerability research. Convert external scanner output into Wuyun finding schema so results can be deduplicated, triaged, and reported consistently.

## Safety Boundary

- Analyze local files and provided scanner outputs by default.
- Do not install packages, run build scripts, or contact package registries unless the user explicitly authorizes that exact action.
- Treat dependency manifests and CI files as untrusted code.
- Redact secrets and credential-shaped strings in evidence.
- Prefer remediation, pinning, least privilege, and reproducible builds over exploitability claims.

## Workflow

1. **Inventory manifests**: package managers, lockfiles, CI workflows, Dockerfiles, IaC, and tool configs.
2. **CI/CD trust boundary**: identify triggers, permissions, secrets, runners, OIDC, artifacts, and untrusted PR paths.
3. **Dependency risk triage**: note missing lockfiles, remote installs, lifecycle scripts, unpinned actions/images, and dependency-confusion leads.
4. **Scanner adapter**: normalize Semgrep, Gitleaks, Trivy, npm-audit, pip-audit, or generic JSON outputs with `tool_output_adapter.py`.
5. **Language routing**: run `language_pack_mapper.py` to pick focused code-audit packs and next checks.
6. **Report**: emit Wuyun JSON/SARIF-ready findings with confidence and remediation.

## Bundled Helpers

- `scripts/supply_chain_audit.py`: passive dependency and CI/CD risk scanner.
- `scripts/tool_output_adapter.py`: converts common scanner JSON into Wuyun finding schema.
- `scripts/language_pack_mapper.py`: maps repository languages/frameworks to focused audit packs.

## References

- `references/supply-chain-cicd.md`: CI/CD and dependency review checklist.
- `references/language-packs.md`: language-specific code-audit pack selection guidance.
- `references/tool-output-adapters.md`: supported external scanner formats and normalization notes.
