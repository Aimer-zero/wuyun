# Tool Output Adapters

`tool_output_adapter.py` accepts JSON from common tools and emits Wuyun finding schema:

- Semgrep JSON: `results[]`
- Gitleaks JSON: list entries or `findings[]`
- Trivy JSON: `Results[].Vulnerabilities[]` and secret findings
- npm audit JSON: `vulnerabilities` or `advisories`
- pip-audit JSON: `dependencies[].vulns[]`
- Generic JSON: best-effort path/message/severity extraction

Adapters normalize fields but do not validate exploitability. Treat imported results as leads until reviewed.
