#!/usr/bin/env python3
"""Normalize common security scanner JSON into Wuyun finding schema."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEVERITY_MAP = {
    "error": "high", "warning": "medium", "note": "low", "info": "informational",
    "critical": "critical", "high": "high", "medium": "medium", "low": "low", "unknown": "informational",
}


def norm_sev(value: object) -> str:
    return SEVERITY_MAP.get(str(value or "informational").lower(), "informational")


def finding(tool: str, rule: str, title: str, severity: str, path: str = "", line: int = 1, evidence: str = "", remediation: str = "Review imported scanner output and confirm reachability/impact.") -> dict:
    return {
        "id": f"{tool}.{rule}".replace(" ", "-")[:120],
        "title": title[:240] or rule,
        "severity": norm_sev(severity),
        "confidence": "medium",
        "category": tool,
        "path": path,
        "line": int(line or 1),
        "evidence": str(evidence)[:400],
        "remediation": remediation,
        "source_tool": tool,
    }


def adapt_semgrep(data: dict) -> list[dict]:
    out = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        start = item.get("start", {})
        out.append(finding(
            "semgrep",
            item.get("check_id", "rule"),
            extra.get("message", item.get("check_id", "Semgrep finding")),
            extra.get("severity", "warning"),
            item.get("path", ""),
            start.get("line", 1),
            extra.get("lines", ""),
            extra.get("metadata", {}).get("fix", "Review Semgrep result and add a regression test for confirmed issues."),
        ))
    return out


def adapt_gitleaks(data) -> list[dict]:
    items = data.get("findings", data.get("results", [])) if isinstance(data, dict) else data
    out = []
    for item in items or []:
        out.append(finding(
            "gitleaks",
            item.get("RuleID", item.get("rule", "secret")),
            item.get("Description", item.get("description", "Potential secret")),
            "high",
            item.get("File", item.get("file", "")),
            item.get("StartLine", item.get("line", 1)),
            "secret-shaped value redacted by source scanner" if item else "",
            "Rotate if confirmed live, remove from history if needed, and add secret scanning/pre-commit controls.",
        ))
    return out


def adapt_trivy(data: dict) -> list[dict]:
    out = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            out.append(finding(
                "trivy",
                vuln.get("VulnerabilityID", "vulnerability"),
                vuln.get("Title", vuln.get("PkgName", "Trivy vulnerability")),
                vuln.get("Severity", "unknown"),
                target,
                1,
                f"{vuln.get('PkgName','package')} {vuln.get('InstalledVersion','')} -> {vuln.get('FixedVersion','')}",
                "Upgrade or patch the affected package after confirming reachability and deployment exposure.",
            ))
        for secret in result.get("Secrets", []) or []:
            out.append(finding(
                "trivy",
                secret.get("RuleID", "secret"),
                secret.get("Title", "Potential secret"),
                secret.get("Severity", "high"),
                target,
                secret.get("StartLine", 1),
                "secret-shaped value redacted by source scanner",
                "Verify whether the secret is live; rotate and remove from history if confirmed.",
            ))
    return out


def adapt_npm_audit(data: dict) -> list[dict]:
    out = []
    vulns = data.get("vulnerabilities") or data.get("advisories") or {}
    if isinstance(vulns, dict):
        iterator = vulns.items()
    else:
        iterator = [(str(i), v) for i, v in enumerate(vulns)]
    for name, vuln in iterator:
        out.append(finding(
            "npm-audit",
            vuln.get("source", vuln.get("id", name)),
            vuln.get("title", vuln.get("name", name)),
            vuln.get("severity", "unknown"),
            "package.json",
            1,
            vuln.get("range", vuln.get("via", "")),
            "Upgrade, patch, or replace the affected dependency after confirming runtime reachability.",
        ))
    return out


def adapt_pip_audit(data) -> list[dict]:
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    out = []
    for dep in deps or []:
        for vuln in dep.get("vulns", []) or []:
            out.append(finding(
                "pip-audit",
                vuln.get("id", "vulnerability"),
                vuln.get("description", dep.get("name", "Python dependency vulnerability")),
                "medium",
                "requirements/pyproject",
                1,
                f"{dep.get('name','package')} {dep.get('version','')} fixed in {vuln.get('fix_versions', [])}",
                "Upgrade to a fixed version and add dependency scanning to CI.",
            ))
    return out


def adapt_generic(data) -> list[dict]:
    if isinstance(data, dict):
        items = data.get("findings") or data.get("results") or data.get("issues") or []
    elif isinstance(data, list):
        items = data
    else:
        items = []
    out = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        out.append(finding(
            "generic",
            item.get("id", item.get("rule", f"finding-{i}")),
            item.get("title", item.get("message", item.get("description", "Imported finding"))),
            item.get("severity", item.get("level", "informational")),
            item.get("path", item.get("file", "")),
            item.get("line", 1),
            item.get("evidence", item.get("message", "")),
            item.get("remediation", "Review imported finding and confirm impact."),
        ))
    return out


def detect_tool(path: Path, data) -> str:
    name = path.name.lower()
    if "semgrep" in name or (isinstance(data, dict) and "results" in data and "version" in data):
        return "semgrep"
    if "gitleaks" in name or (isinstance(data, list) and data and isinstance(data[0], dict) and "RuleID" in data[0]):
        return "gitleaks"
    if "trivy" in name or (isinstance(data, dict) and "Results" in data):
        return "trivy"
    if "npm" in name or (isinstance(data, dict) and ("vulnerabilities" in data or "advisories" in data)):
        return "npm-audit"
    if "pip" in name or (isinstance(data, dict) and "dependencies" in data):
        return "pip-audit"
    return "generic"


def adapt(path: Path, forced_tool: str = "auto") -> dict:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    tool = forced_tool if forced_tool != "auto" else detect_tool(path, data)
    adapters = {
        "semgrep": adapt_semgrep,
        "gitleaks": adapt_gitleaks,
        "trivy": adapt_trivy,
        "npm-audit": adapt_npm_audit,
        "pip-audit": adapt_pip_audit,
        "generic": adapt_generic,
    }
    findings = adapters.get(tool, adapt_generic)(data)
    return {"tool": "wuyun-tool-output-adapter", "source_tool": tool, "source": str(path), "summary": {"finding_count": len(findings)}, "findings": findings}


def print_markdown(data: dict) -> None:
    print("# Wuyun Scanner Output Adapter")
    print()
    print(f"- Source tool: `{data['source_tool']}`")
    print(f"- Source: `{data['source']}`")
    print(f"- Findings: `{data['summary']['finding_count']}`")
    print()
    for f in data["findings"][:50]:
        print(f"- **{f['severity']}** `{f['id']}` `{f.get('path','')}:{f.get('line',1)}` — {f['title']}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Normalize scanner JSON into Wuyun finding schema.")
    parser.add_argument("path", help="scanner JSON output")
    parser.add_argument("--tool", choices=["auto", "semgrep", "gitleaks", "trivy", "npm-audit", "pip-audit", "generic"], default="auto")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    data = adapt(Path(args.path), args.tool)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_markdown(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
