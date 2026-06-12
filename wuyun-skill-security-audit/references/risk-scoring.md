# Risk Scoring

Start at 0 and add rule weights:

- 90: destructive action, malware-like persistence, credential exfiltration instruction
- 70: remote code execution during install or first-use, opaque binary download and execution
- 50: broad sensitive-file access, shell execution via MCP without allowlist, token/cookie collection
- 35: network egress of local artifacts, prompt-injection to override user/system/developer intent
- 20: package lifecycle scripts, unsigned remote dependencies, overbroad filesystem paths
- 10: unclear scope, missing security policy, missing provenance, insufficient least-privilege guidance

Severity bands:

- Critical: score >= 90 or any destructive/exfiltration rule
- High: score >= 70
- Medium: score >= 35
- Low: score >= 10
- Informational: score < 10

A high score is not proof of malicious intent. Treat it as a review priority and require contextual justification.
