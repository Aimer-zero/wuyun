#!/usr/bin/env python3
"""Run Wuyun publish-oriented local quality gates.

The gate is intentionally passive. It validates the skill package, compiles helper
scripts, and runs a bounded self-audit without contacting targets.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(label: str, cmd: list[str], cwd: Path) -> int:
    print(f"\n## {label}")
    print("```bash")
    print(" ".join(cmd))
    print("```")
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.stderr:
        print("\n[stderr]")
        print(proc.stderr.rstrip())
    print(f"\nResult: {'PASS' if proc.returncode == 0 else 'FAIL'} (exit {proc.returncode})")
    return proc.returncode


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run Wuyun local publish quality gates.")
    parser.add_argument("path", nargs="?", default=Path(__file__).resolve().parents[2], help="repository root")
    parser.add_argument("--skip-preflight", action="store_true", help="skip local capability preflight output")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    skill = root / "wuyun"
    scripts = skill / "scripts"
    if not (skill / "SKILL.md").exists():
        print(f"error: not a Wuyun repository root: {root}", file=sys.stderr)
        return 2

    print("# Wuyun Quality Gate")
    print(f"- Root: `{root}`")
    failures = 0

    checks = [
        ("Package validation", [sys.executable, str(scripts / "validate_skill.py"), str(root)]),
        ("Installer syntax", ["bash", "-n", str(root / "install.sh")]),
        ("Bounded self passive audit", [
            sys.executable, str(scripts / "passive_repo_audit.py"), str(root),
            "--max-files", "500", "--code-only",
            "--exclude", "wuyun/scripts",
            "--exclude", "wuyun-web-api-audit/scripts",
            "--exclude", "wuyun-cloud-vuln/scripts",
            "--exclude", "wuyun-js-reverse/scripts",
            "--exclude", "wuyun-browser-runtime/scripts",
            "--exclude", "wuyun-js-deobfuscation/scripts",
            "--exclude", "wuyun-protocol-analysis/scripts",
            "--exclude", "wuyun-auth-audit/scripts",
            "--exclude", "wuyun-ai-audit/scripts",
            "--exclude", "wuyun-recon/scripts",
            "--exclude", "wuyun-evasion/scripts",
            "--exclude", "wuyun/agents",
            "--exclude", "wuyun-web-api-audit/agents",
            "--exclude", "wuyun-cloud-vuln/agents",
            "--exclude", "wuyun-js-reverse/agents",
            "--exclude", "wuyun-browser-runtime/agents",
            "--exclude", "wuyun-js-deobfuscation/agents",
            "--exclude", "wuyun-protocol-analysis/agents",
            "--exclude", "wuyun-auth-audit/agents",
            "--exclude", "wuyun-ai-audit/agents",
            "--exclude", "wuyun-recon/agents",
            "--exclude", "wuyun-evasion/agents",
        ]),
    ]
    if not args.skip_preflight:
        checks.insert(1, ("Local tool preflight", [sys.executable, str(scripts / "check_tools.py"), "--cwd", str(root)]))

    for label, cmd in checks:
        failures += run(label, cmd, root) != 0

    print("\n# Summary")
    if failures:
        print(f"FAIL: {failures} gate(s) failed.")
        return 1
    print("PASS: all gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
