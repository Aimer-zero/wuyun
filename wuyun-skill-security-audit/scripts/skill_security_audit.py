#!/usr/bin/env python3
"""Passive AI skill, MCP, and agent-extension security audit.

The scanner reads local text files only. It does not install or execute reviewed
extensions. Findings are leads for human review, not proof of malicious intent.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

RISK_FILES = {
    "SKILL.md",
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "CODEBUDDY.md",
    "plugin.json",
    ".mcp.json",
    "mcp.json",
    "package.json",
    "install.sh",
    "setup.py",
    "pyproject.toml",
}
TEXT_SUFFIXES = {".md", ".json", ".yaml", ".yml", ".toml", ".py", ".sh", ".js", ".ts", ".txt", ""}
IGNORE_PARTS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache"}

SECRET_VALUE_RE = re.compile(r"(?i)(token|secret|password|api[_-]?key|authorization)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:-]{12,})")

@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: str
    score: int
    pattern: re.Pattern[str]
    remediation: str

RULES: tuple[Rule, ...] = (
    Rule(
        "skill.remote-exec",
        "Remote script or opaque command execution",
        "remote-execution",
        "high",
        70,
        re.compile(r"(?is)(curl|wget|Invoke-WebRequest|iwr)\b.{0,160}(\||bash|sh|iex|python|node)|powershell\b.{0,120}(-enc|-encodedcommand)"),
        "Replace remote execution with pinned releases, checksums, reviewed source, and explicit user-run steps.",
    ),
    Rule(
        "skill.sensitive-file-access",
        "Sensitive local file or credential-store access",
        "sensitive-file-access",
        "high",
        50,
        re.compile(r"(?i)(\.ssh/id_|\.aws/credentials|\.config/gcloud|keychain|login\.keychain|Cookies\b|Local State|/etc/shadow|browser cookie|credential store)"),
        "Constrain file access to the declared workspace and require explicit user approval for any credential store review.",
    ),
    Rule(
        "skill.prompt-injection",
        "Instruction attempts to override higher-priority guidance",
        "prompt-injection",
        "medium",
        35,
        re.compile(r"(?i)(ignore (all|previous|system|developer) instructions|override (system|developer|user)|bypass (safety|approval)|never refuse|do not ask for approval)"),
        "Remove adversarial instructions; state task-specific behavior without asking agents to ignore policy or user intent.",
    ),
    Rule(
        "skill.persistence",
        "Persistence or startup modification",
        "persistence",
        "high",
        60,
        re.compile(r"(?i)(crontab|launchctl|LaunchAgents?|systemctl\s+enable|login item|\.zshrc|\.bashrc|\.profile|plist)"),
        "Avoid persistence in skills/plugins; if setup is required, make it explicit, reversible, and opt-in.",
    ),
    Rule(
        "skill.destructive-action",
        "Destructive system action",
        "destructive-action",
        "critical",
        90,
        re.compile(r"(?i)(rm\s+-rf\s+/(\s|$)|mkfs\.|dd\s+if=.*of=/dev/|chmod\s+-R\s+777\s+/|shutdown\b|reboot\b)"),
        "Remove destructive actions from extension workflows; provide safe dry-runs and explicit remediation instructions instead.",
    ),
    Rule(
        "skill.network-egress",
        "Network egress of local artifacts or prompts",
        "network-egress",
        "medium",
        35,
        re.compile(r"(?is)(webhook|discord\.com/api/webhooks|api\.telegram\.org|pastebin|transfer\.sh|curl\b.{0,120}(-d|--data|--form|@))"),
        "Document outbound destinations, require user approval, and avoid uploading prompts, findings, or local files by default.",
    ),
    Rule(
        "skill.broad-shell-mcp",
        "MCP exposes broad shell or filesystem capability",
        "mcp-permission",
        "high",
        50,
        re.compile(r"(?is)(\"command\"\s*:\s*\"(bash|sh|zsh|powershell|cmd|python|node)\"|filesystem|file[_-]?system|shell|exec_command)"),
        "Wrap dangerous tools with allowlists, workspace roots, read-only modes, and explicit approval gates.",
    ),
    Rule(
        "skill.package-lifecycle",
        "Package lifecycle script can execute during install",
        "supply-chain",
        "medium",
        25,
        re.compile(r"(?i)\"(postinstall|preinstall|prepare|prepublish|install)\"\s*:\s*\""),
        "Avoid implicit install-time execution or make lifecycle scripts auditable, minimal, and documented.",
    ),
)


def redact(value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}=<redacted-sensitive-value>"
    text = SECRET_VALUE_RE.sub(repl, value)
    text = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]{10,}", "Bearer <redacted-sensitive-value>", text, flags=re.I)
    return text


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        rel_parts = set(path.relative_to(root).parts)
        if rel_parts & IGNORE_PARTS:
            continue
        if path.name in RISK_FILES or path.suffix in TEXT_SUFFIXES or ".github" in path.parts:
            if path.stat().st_size <= 1_000_000:
                yield path


def line_number(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def classify(score: int, critical: bool) -> str:
    if critical or score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 10:
        return "low"
    return "informational"


def audit(path: Path) -> dict:
    root = path.resolve()
    artifacts = []
    findings = []
    seen_rules: set[str] = set()
    total_score = 0
    critical = False

    for file_path in iter_files(root):
        rel = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        artifact_type = "instruction" if file_path.name in {"SKILL.md", "AGENTS.md", "CLAUDE.md", "GEMINI.md"} else "config-or-code"
        if file_path.name in {".mcp.json", "mcp.json"}:
            artifact_type = "mcp-config"
        elif file_path.name == "plugin.json" or ".plugin" in str(file_path.parent):
            artifact_type = "plugin-manifest"
        artifacts.append({"path": rel, "type": artifact_type})

        for rule in RULES:
            for match in rule.pattern.finditer(text):
                evidence = redact(match.group(0).replace("\n", " ").strip())[:260]
                finding = {
                    "id": rule.rule_id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "confidence": "medium",
                    "category": rule.category,
                    "path": rel,
                    "line": line_number(text, match.start()),
                    "evidence": evidence,
                    "score": rule.score,
                    "remediation": rule.remediation,
                }
                findings.append(finding)
                if rule.rule_id not in seen_rules:
                    total_score += rule.score
                    seen_rules.add(rule.rule_id)
                critical = critical or rule.severity == "critical"

    severity = classify(total_score, critical)
    decision = {
        "critical": "reject-or-quarantine-until-reviewed",
        "high": "review-before-install-and-require-sandbox",
        "medium": "approve-only-with-constraints",
        "low": "low-risk-after-context-review",
        "informational": "no-major-static-risk-detected",
    }[severity]
    return {
        "tool": "wuyun-skill-security-audit",
        "target": str(root),
        "summary": {
            "artifact_count": len(artifacts),
            "finding_count": len(findings),
            "risk_score": total_score,
            "severity": severity,
            "decision": decision,
        },
        "artifacts": artifacts,
        "findings": findings,
        "notes": [
            "Static analysis only; review context before labeling an extension malicious.",
            "No reviewed helper scripts or MCP servers were executed.",
        ],
    }


def print_markdown(data: dict) -> None:
    s = data["summary"]
    print("# Wuyun Skill/MCP Security Audit")
    print()
    print(f"- Target: `{data['target']}`")
    print(f"- Artifacts: `{s['artifact_count']}`")
    print(f"- Findings: `{s['finding_count']}`")
    print(f"- Risk score: `{s['risk_score']}`")
    print(f"- Severity: `{s['severity']}`")
    print(f"- Decision: `{s['decision']}`")
    print()
    if not data["findings"]:
        print("No major static skill/MCP risk indicators detected.")
        return
    print("| Severity | Rule | Path:Line | Evidence | Remediation |")
    print("|---|---|---|---|---|")
    for f in data["findings"]:
        evidence = f["evidence"].replace("|", "\\|")
        remediation = f["remediation"].replace("|", "\\|")
        print(f"| {f['severity']} | `{f['id']}` | `{f['path']}:{f['line']}` | {evidence} | {remediation} |")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively audit AI skills, MCP configs, and agent extensions.")
    parser.add_argument("path", nargs="?", default=".", help="skill/plugin/repository path")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    data = audit(Path(args.path))
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_markdown(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
