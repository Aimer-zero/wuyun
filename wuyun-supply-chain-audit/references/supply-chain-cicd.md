# Supply Chain and CI/CD Review

Check:

- GitHub Actions or GitLab CI triggers that run untrusted pull request code
- `pull_request_target`, broad `permissions: write-all`, or write permissions without need
- Unpinned third-party actions, mutable Docker tags, remote `curl | sh` installs
- Package lifecycle scripts such as `postinstall`, `prepare`, `prepublish`, and build-time codegen
- Missing lockfiles for active package managers
- Secrets passed to scripts, artifact upload of sensitive files, cache poisoning risks
- OIDC trust policies that lack subject/audience constraints
- Self-hosted runner exposure to untrusted branches

Evidence should show file, line, pattern, and remediation. Do not claim compromise from configuration alone.
