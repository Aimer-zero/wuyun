#!/usr/bin/env python3
"""Passive dependency and CI/CD security triage for local repositories."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

IGNORE_PARTS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
CI_NAMES = {".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml", "bitbucket-pipelines.yml"}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml",
    "poetry.lock", "Pipfile", "Pipfile.lock", "go.mod", "go.sum", "pom.xml", "build.gradle", "Cargo.toml",
    "Cargo.lock", "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Gemfile", "Gemfile.lock",
}

RULES = [
    {
        "id": "cicd.pull-request-target",
        "title": "Workflow uses pull_request_target",
        "severity": "high",
        "category": "ci-cd",
        "score": 60,
        "pattern": re.compile(r"\bpull_request_target\b"),
        "remediation": "Avoid running untrusted pull request code with target-repository privileges; split label/comment automation from build execution.",
    },
    {
        "id": "cicd.write-all-permissions",
        "title": "Broad GitHub Actions write permissions",
        "severity": "medium",
        "category": "ci-cd",
        "score": 35,
        "pattern": re.compile(r"(?im)^\s*permissions\s*:\s*write-all\s*$|contents\s*:\s*write|id-token\s*:\s*write"),
        "remediation": "Use least-privilege permissions per job and document why write or OIDC access is required.",
    },
    {
        "id": "cicd.unpinned-action",
        "title": "Third-party action is not pinned to a commit SHA",
        "severity": "medium",
        "category": "ci-cd",
        "score": 25,
        "pattern": re.compile(r"uses:\s*[^\s#]+@(?:main|master|latest|v?\d+(?:\.\d+){0,2})\b"),
        "remediation": "Pin third-party actions to a full commit SHA or enforce an organization allowlist.",
    },
    {
        "id": "supply.remote-install",
        "title": "Remote install command executes downloaded content",
        "severity": "high",
        "category": "supply-chain",
        "score": 60,
        "pattern": re.compile(r"(?is)(curl|wget)\b.{0,160}\|\s*(bash|sh|python|node)"),
        "remediation": "Replace pipe-to-shell installs with pinned artifacts, checksums, and reviewed install scripts.",
    },
    {
        "id": "container.mutable-latest",
        "title": "Mutable container tag used",
        "severity": "low",
        "category": "container",
        "score": 15,
        "pattern": re.compile(r"(?im)^\s*FROM\s+[^\s:]+(?::latest)?\s*$|image:\s*[^\s]+:latest\b"),
        "remediation": "Pin images to immutable digests or reviewed version tags and enable image scanning.",
    },
    {
        "id": "npm.lifecycle-script",
        "title": "Package lifecycle script can run during install/publish",
        "severity": "medium",
        "category": "dependency",
        "score": 30,
        "pattern": re.compile(r"\"(preinstall|install|postinstall|prepare|prepublish|prepublishOnly)\"\s*:\s*\""),
        "remediation": "Review lifecycle scripts, avoid implicit network/file operations, and require lockfile integrity.",
    },
    {
        "id": "dependency.unpinned-http",
        "title": "Dependency or installer references mutable HTTP/Git source",
        "severity": "medium",
        "category": "dependency",
        "score": 25,
        "pattern": re.compile(r"(?i)(git\+https?://|https?://[^\s'\"]+\.(?:tgz|zip|sh)|pip\s+install\s+https?://)"),
        "remediation": "Prefer registry dependencies with lockfiles, checksums, and provenance; pin commits when Git sources are unavoidable.",
    },
]


def iter_interesting_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        rel = path.relative_to(root)
        if set(rel.parts) & IGNORE_PARTS:
            continue
        if path.name in MANIFEST_NAMES or path.name in CI_NAMES or ".github/workflows" in str(rel):
            if path.stat().st_size <= 1_000_000:
                yield path


def line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def classify(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def detect_manifest_gaps(root: Path, findings: list[dict]) -> None:
    pkg = root / "package.json"
    if pkg.exists() and not any((root / name).exists() for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        findings.append({
            "id": "dependency.missing-node-lockfile",
            "title": "Node manifest has no lockfile",
            "severity": "medium",
            "confidence": "medium",
            "category": "dependency",
            "path": "package.json",
            "line": 1,
            "evidence": "package.json exists without package-lock.json, yarn.lock, or pnpm-lock.yaml at repository root",
            "score": 20,
            "remediation": "Commit the active package-manager lockfile and enforce deterministic installs in CI.",
        })
    py = root / "pyproject.toml"
    req = root / "requirements.txt"
    if py.exists() and not any((root / name).exists() for name in ("poetry.lock", "uv.lock", "requirements.txt")):
        findings.append({
            "id": "dependency.missing-python-lockfile",
            "title": "Python project has no lock or frozen requirements file",
            "severity": "low",
            "confidence": "medium",
            "category": "dependency",
            "path": "pyproject.toml",
            "line": 1,
            "evidence": "pyproject.toml exists without poetry.lock, uv.lock, or requirements.txt at repository root",
            "score": 15,
            "remediation": "Use a lockfile or frozen requirements process for production builds.",
        })
    if req.exists():
        for idx, line in enumerate(req.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "==" not in stripped and " @ " not in stripped:
                findings.append({
                    "id": "dependency.unpinned-python-requirement",
                    "title": "Python requirement is not version pinned",
                    "severity": "low",
                    "confidence": "medium",
                    "category": "dependency",
                    "path": "requirements.txt",
                    "line": idx,
                    "evidence": stripped[:180],
                    "score": 10,
                    "remediation": "Pin production dependencies or use a lockfile with hashes.",
                })


def audit(root: Path) -> dict:
    base = root.resolve()
    findings: list[dict] = []
    files = []
    for path in iter_interesting_files(base):
        rel = str(path.relative_to(base)) if base.is_dir() else path.name
        files.append(rel)
        text = path.read_text(encoding="utf-8", errors="replace")
        for rule in RULES:
            for match in rule["pattern"].finditer(text):
                findings.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": "medium",
                    "category": rule["category"],
                    "path": rel,
                    "line": line_number(text, match.start()),
                    "evidence": match.group(0).replace("\n", " ").strip()[:240],
                    "score": rule["score"],
                    "remediation": rule["remediation"],
                })
    if base.is_dir():
        detect_manifest_gaps(base, findings)
    unique_scores = {}
    for finding in findings:
        unique_scores.setdefault(finding["id"], finding.get("score", 0))
    score = sum(unique_scores.values())
    return {
        "tool": "wuyun-supply-chain-audit",
        "target": str(base),
        "summary": {
            "files_reviewed": len(files),
            "finding_count": len(findings),
            "risk_score": score,
            "severity": classify(score),
        },
        "files": files,
        "findings": findings,
        "tool_suggestions": [
            {"tool": "gitleaks", "purpose": "secret scanning", "command": "gitleaks detect --source . --report-format json --report-path gitleaks.json"},
            {"tool": "semgrep", "purpose": "static application security testing", "command": "semgrep scan --config auto --json --output semgrep.json"},
            {"tool": "trivy", "purpose": "dependency/container/IaC scanning", "command": "trivy fs --format json --output trivy.json ."},
        ],
    }


def print_markdown(data: dict) -> None:
    s = data["summary"]
    print("# Wuyun Supply Chain / CI-CD Audit")
    print()
    print(f"- Target: `{data['target']}`")
    print(f"- Files reviewed: `{s['files_reviewed']}`")
    print(f"- Findings: `{s['finding_count']}`")
    print(f"- Risk score: `{s['risk_score']}`")
    print(f"- Severity: `{s['severity']}`")
    print()
    if data["findings"]:
        print("| Severity | Rule | Path:Line | Evidence | Remediation |")
        print("|---|---|---|---|---|")
        for f in data["findings"]:
            evidence = f["evidence"].replace("|", "\\|")
            remediation = f["remediation"].replace("|", "\\|")
            print(f"| {f['severity']} | `{f['id']}` | `{f['path']}:{f['line']}` | {evidence} | {remediation} |")
    else:
        print("No major static supply-chain or CI/CD indicators detected.")
    print()
    print("## Suggested External Tool Runs")
    for suggestion in data["tool_suggestions"]:
        print(f"- `{suggestion['tool']}`: {suggestion['purpose']} — `{suggestion['command']}`")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively audit local supply-chain and CI/CD risk.")
    parser.add_argument("path", nargs="?", default=".", help="repository path")
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
