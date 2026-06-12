#!/usr/bin/env python3
"""Diff-aware local PR security review helper.

The helper scans changed lines only when git diff is available. It is intended
for CI/PR feedback and emits Wuyun finding schema plus optional SARIF/Markdown.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
EXPORTER = SCRIPT_DIR / "finding_export.py"

RULES = [
    ("pr.command-exec", "Command execution sink added or changed", "high", "command-execution", re.compile(r"\b(os\.system|subprocess\.(Popen|run|call|check_output)|child_process\.(exec|spawn)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\b)"), "Trace user-controlled input to this sink; prefer argument arrays, allowlists, and no shell=True."),
    ("pr.sql-string", "SQL built with string interpolation/concatenation", "high", "injection", re.compile(r"(?i)(select|insert|update|delete)\b.{0,100}(\+|%\s*\(|f['\"]|`\$\{)"), "Use parameterized queries/ORM bind variables and add regression tests."),
    ("pr.secret-literal", "Credential-shaped literal added", "high", "secret", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_./+=:-]{12,}['\"]"), "Remove the secret, rotate if live, and use a managed secret store."),
    ("pr.path-traversal", "Filesystem path uses request/user input shape", "medium", "path-traversal", re.compile(r"(?i)(request\.|req\.|params|query|body).{0,100}(open\(|readFile|writeFile|send_file|File\()"), "Normalize/canonicalize paths and enforce a fixed base directory allowlist."),
    ("pr.ssrfx", "Outbound request sink added or changed", "medium", "ssrf", re.compile(r"(?i)(requests\.(get|post|put)|httpx\.|fetch\(|axios\.|HttpClient|urllib\.request)"), "Validate URL schemes/hosts, block metadata/internal ranges, and add SSRF regression tests."),
    ("pr.unsafe-deser", "Unsafe deserialization sink added or changed", "high", "deserialization", re.compile(r"(?i)(pickle\.loads|yaml\.load\(|ObjectInputStream|readObject\(|JSON\.parse\(|eval\(|Function\()"), "Use safe parsers and schema validation; never deserialize untrusted objects."),
]


def run_git(args: list[str], cwd: Path) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def diff_text(repo: Path, base: str, head: str | None, diff_file: str | None) -> str:
    if diff_file:
        return Path(diff_file).read_text(encoding="utf-8", errors="replace")
    rev = f"{base}...{head}" if head else base
    return run_git(["diff", "--unified=0", rev], repo)


def parse_added_lines(diff: str):
    current_file = ""
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            new_line = int(match.group(1)) if match else 0
            continue
        if line.startswith("+") and not line.startswith("+++"):
            yield current_file, max(new_line, 1), line[1:]
            new_line += 1
        elif not line.startswith("-"):
            new_line += 1


def redact(text: str) -> str:
    return re.sub(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{8,}", r"\1=<redacted-sensitive-value>", text)


def review(repo: Path, base: str, head: str | None, diff_file: str | None) -> dict:
    diff = diff_text(repo, base, head, diff_file)
    findings = []
    for path, line_no, text in parse_added_lines(diff):
        for rule_id, title, severity, category, pattern, remediation in RULES:
            if pattern.search(text):
                findings.append({
                    "id": rule_id,
                    "title": title,
                    "severity": severity,
                    "confidence": "medium",
                    "category": category,
                    "path": path,
                    "line": line_no,
                    "evidence": redact(text.strip())[:300],
                    "remediation": remediation,
                    "source_tool": "wuyun-pr-review",
                })
    return {
        "tool": "wuyun-pr-security-review",
        "source": str(repo),
        "summary": {"finding_count": len(findings), "base": base, "head": head or "working-tree", "mode": "diff"},
        "findings": findings,
        "notes": ["Diff-aware heuristic review; confirm reachability and trust boundaries before filing final findings."],
    }


def export(bundle: dict, fmt: str, output: str) -> None:
    proc = subprocess.run([sys.executable, str(EXPORTER), "-", "--format", fmt, "--output", output], input=json.dumps(bundle), text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def print_markdown(bundle: dict) -> None:
    print("# Wuyun PR Security Review")
    print()
    print(f"- Findings: `{bundle['summary']['finding_count']}`")
    print(f"- Base: `{bundle['summary']['base']}`")
    print(f"- Head: `{bundle['summary']['head']}`")
    print()
    for f in bundle["findings"]:
        print(f"- **{f['severity']}** `{f['id']}` `{f['path']}:{f['line']}` — {f['title']}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run a local diff-aware PR security review.")
    parser.add_argument("--path", default=".", help="git repository path")
    parser.add_argument("--base", default="HEAD", help="base revision or range; default HEAD for working tree diff")
    parser.add_argument("--head", help="head revision for base...head diff")
    parser.add_argument("--diff", help="read unified diff from file instead of git")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--sarif", help="write SARIF file")
    parser.add_argument("--markdown", help="write Markdown file")
    args = parser.parse_args(argv)
    bundle = review(Path(args.path).resolve(), args.base, args.head, args.diff)
    if args.sarif:
        export(bundle, "sarif", args.sarif)
    if args.markdown:
        export(bundle, "markdown", args.markdown)
    if args.json:
        print(json.dumps(bundle, ensure_ascii=False, indent=2))
    else:
        print_markdown(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
