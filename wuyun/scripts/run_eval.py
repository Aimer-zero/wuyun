#!/usr/bin/env python3
"""Run deterministic offline regression evals for Wuyun helpers.

The eval suite is local-only: it creates or reads small fixtures, runs bundled
helper scripts as subprocesses, and checks for expected non-secret signals. It
never contacts targets, solves challenges, validates credentials online, or
executes fixture application code.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EvalCase:
    name: str
    passed: bool
    detail: str


def resolve_layout(raw: str | None) -> tuple[Path, Path, Path]:
    """Return (root, core_skill_dir, skills_parent)."""
    if raw:
        candidate = Path(raw).resolve()
    else:
        candidate = Path(__file__).resolve().parents[2]

    if (candidate / "wuyun" / "SKILL.md").exists():
        root = candidate
        skill = root / "wuyun"
        return root, skill, root
    if (candidate / "SKILL.md").exists() and candidate.name == "wuyun":
        skill = candidate
        parent = skill.parent
        root = parent if (parent / "wuyun").resolve() == skill else skill
        return root, skill, parent

    root = candidate
    return root, root / "wuyun", root


def run_cmd(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=30)


def record(name: str, condition: bool, detail: str) -> EvalCase:
    return EvalCase(name=name, passed=condition, detail=detail)


def ensure_fixture_dir(root: Path, tmp: Path) -> Path:
    fixture = root / "eval" / "fixtures" / "passive_repo"
    if fixture.exists():
        return fixture
    fixture = tmp / "passive_repo"
    fixture.mkdir(parents=True, exist_ok=True)
    (fixture / "sample_app.py").write_text(
        '\n'.join([
            'from flask import Flask, request',
            'import subprocess',
            'app = Flask(__name__)',
            'API_KEY = "demo12345"',
            '@app.route("/api/run")',
            'def run_command():',
            '    value = request.args.get("value", "offline-canary")',
            '    return subprocess.check_output(["echo", value], text=True)',
            '',
        ]),
        encoding="utf-8",
    )
    return fixture


def ensure_cloudflare_files(root: Path, tmp: Path) -> tuple[Path, Path]:
    fixture = root / "eval" / "fixtures" / "cloudflare"
    headers = fixture / "headers.txt"
    body = fixture / "body.html"
    if headers.exists() and body.exists():
        return headers, body
    fixture = tmp / "cloudflare"
    fixture.mkdir(parents=True, exist_ok=True)
    headers = fixture / "headers.txt"
    body = fixture / "body.html"
    headers.write_text(
        "HTTP/2 403\nserver: cloudflare\ncf-ray: 7abc1234def56789-SJC\ncf-mitigated: challenge\n",
        encoding="utf-8",
    )
    body.write_text("<title>Just a moment...</title><div class='cf-turnstile'></div>Cloudflare", encoding="utf-8")
    return headers, body


def ensure_chain_artifact(root: Path, tmp: Path) -> Path:
    existing = root / "examples" / "captures" / "graphql-replay-case.json"
    if existing.exists():
        return existing
    path = tmp / "graphql-replay-case.json"
    path.write_text(
        json.dumps(
            {
                "type": "graphql",
                "url": "https://app.example.invalid/graphql",
                "baseline": {"operationName": "Viewer", "query": "query Viewer { viewer { id } }"},
            }
        ),
        encoding="utf-8",
    )
    return path


def build_cloud_token_fixture(tmp: Path) -> tuple[Path, list[str]]:
    access_key = "ASIA" + "1234567890ABCDEF"
    secret_value = "wJalr" + "X" * 28 + "tail"
    session_token = "IQoJ" + "Y" * 30 + "done"
    path = tmp / "cloud_tokens.json"
    path.write_text(
        json.dumps(
            {
                "AccessKeyId": access_key,
                "SecretAccessKey": secret_value,
                "SecurityToken": session_token,
                "RoleName": "demo-role",
                "Expiration": "2030-01-01T00:00:00Z",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path, [access_key, secret_value, session_token]


def eval_passive_repo(root: Path, skill: Path, tmp: Path) -> EvalCase:
    fixture = ensure_fixture_dir(root, tmp)
    script = skill / "scripts" / "passive_repo_audit.py"
    proc = run_cmd([sys.executable, str(script), str(fixture), "--complete-evidence", "--json"], root)
    if proc.returncode != 0:
        return record("passive_repo_audit", False, proc.stderr.strip() or f"exit {proc.returncode}")
    raw = proc.stdout
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return record("passive_repo_audit", False, f"invalid JSON: {exc}")
    text = json.dumps(data, ensure_ascii=False)
    condition = all(
        [
            data.get("scanned_files", 0) >= 1,
            "flask-route" in text,
            "command-exec" in text,
            "<redacted-sensitive-value>" in text,
            "demo12345" not in text,
        ]
    )
    return record("passive_repo_audit", condition, "routes/sinks detected and fixture secret redacted")


def eval_cloudflare(root: Path, skill: Path, tmp: Path) -> EvalCase:
    headers, body = ensure_cloudflare_files(root, tmp)
    script = skill / "scripts" / "cloudflare_triage.py"
    proc = run_cmd(
        [
            sys.executable,
            str(script),
            "--headers",
            str(headers),
            "--body",
            str(body),
            "--status",
            "403",
            "--url",
            "https://app.example.invalid/protected",
            "--json",
        ],
        root,
    )
    if proc.returncode != 0:
        return record("cloudflare_triage", False, proc.stderr.strip() or f"exit {proc.returncode}")
    try:
        findings = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return record("cloudflare_triage", False, f"invalid JSON: {exc}")
    first = findings[0] if findings else {}
    condition = (
        first.get("classification") == "cloudflare-challenge-or-bot-mitigation"
        and "7abc1234def56789-SJC" in first.get("ray_ids", [])
        and any("Turnstile" in step or "CAPTCHA" in step or "WAF" in step for step in first.get("safe_next_steps", []))
    )
    return record("cloudflare_triage", condition, "challenge classification, Ray ID, and safe next steps present")


def eval_cloud_tokens(root: Path, skills_parent: Path, tmp: Path) -> EvalCase:
    script = skills_parent / "wuyun-cloud-vuln" / "scripts" / "detect_cloud_tokens.py"
    if not script.exists():
        return record("detect_cloud_tokens", False, f"missing companion script: {script}")
    fixture, raw_values = build_cloud_token_fixture(tmp)
    proc = run_cmd([sys.executable, str(script), "--complete", "--json", str(fixture)], root)
    if proc.returncode != 0:
        return record("detect_cloud_tokens", False, proc.stderr.strip() or f"exit {proc.returncode}")
    output = proc.stdout
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        return record("detect_cloud_tokens", False, f"invalid JSON: {exc}")
    text = json.dumps(data, ensure_ascii=False)
    raw_leaked = any(value in text for value in raw_values)
    condition = (not raw_leaked) and "demo-role" in text and "ASIA…CDEF" in text and data.get("online_validation") is False
    return record("detect_cloud_tokens", condition, "credential-shaped values redacted while non-sensitive role context remains")


def eval_cli_playbooks(root: Path, skill: Path) -> EvalCase:
    script = skill / "scripts" / "wuyun_cli.py"
    proc = run_cmd([sys.executable, str(script), "playbooks"], root)
    if proc.returncode != 0:
        return record("wuyun_cli_playbooks", False, proc.stderr.strip() or f"exit {proc.returncode}")
    condition = "cloudflare-waf" in proc.stdout and "chain-mode" in proc.stdout
    return record("wuyun_cli_playbooks", condition, "Cloudflare and chain playbooks are discoverable")


def eval_chain_planner(root: Path, skill: Path, tmp: Path) -> EvalCase:
    artifact = ensure_chain_artifact(root, tmp)
    script = skill / "scripts" / "chain_planner.py"
    proc = run_cmd([sys.executable, str(script), str(artifact), "--json"], root)
    if proc.returncode != 0:
        return record("chain_planner", False, proc.stderr.strip() or f"exit {proc.returncode}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return record("chain_planner", False, f"invalid JSON: {exc}")
    stages = {node.get("stage") for node in data.get("chain_nodes", [])}
    condition = "protocol" in stages and "$wuyun-protocol-analysis" in json.dumps(data)
    return record("chain_planner", condition, "GraphQL artifact routes to protocol companion skill")


def print_summary(cases: list[EvalCase], root: Path) -> int:
    passed = sum(1 for case in cases if case.passed)
    failed = len(cases) - passed
    print("# Wuyun Offline Eval")
    print()
    print(f"- Root: `{root}`")
    print(f"- PASS: `{passed}`")
    print(f"- FAIL: `{failed}`")
    print()
    print("| Case | Result | Detail |")
    print("|---|---|---|")
    for case in cases:
        result = "PASS" if case.passed else "FAIL"
        detail = case.detail.replace("|", "\\|").replace("\n", " ")[:240]
        print(f"| `{case.name}` | {result} | {detail} |")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run Wuyun local-only regression evals.")
    parser.add_argument("path", nargs="?", help="repository root or installed wuyun skill directory")
    args = parser.parse_args(argv)

    root, skill, skills_parent = resolve_layout(args.path)
    if not (skill / "SKILL.md").exists():
        print(f"error: not a Wuyun checkout or installed skill: {root}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="wuyun-eval-") as raw_tmp:
        tmp = Path(raw_tmp)
        cases = [
            eval_passive_repo(root, skill, tmp),
            eval_cloudflare(root, skill, tmp),
            eval_cloud_tokens(root, skills_parent, tmp),
            eval_cli_playbooks(root, skill),
            eval_chain_planner(root, skill, tmp),
        ]
    return print_summary(cases, root)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
